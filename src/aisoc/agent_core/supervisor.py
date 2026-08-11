"""Bounded subprocess supervision for candidate Agent release health gates."""

from __future__ import annotations

import os
import re
import signal
import stat
import subprocess
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Final

from aisoc.agent_core.installer import InstalledRelease

PROCESS_STARTED_MARKER: Final = b"AISOC_AGENT_HEALTH_V1 STARTED"
PROCESS_HEALTHY_MARKER: Final = b"AISOC_AGENT_HEALTH_V1 HEALTHY"

_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 64 * 1024
_MAX_PROTOCOL_LINE_BYTES = 1024
_SAFE_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_FORCE_SIGNAL: Final = signal.SIGKILL
_BLOCKED_ENVIRONMENT_NAMES = {
    "BASH_ENV",
    "ENV",
    "IFS",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONUNBUFFERED",
}
_ALLOWED_EXTRA_ENVIRONMENT_NAMES = {"TZ"}


class AgentProcessSupervisorError(RuntimeError):
    """A candidate process could not prove bounded startup, health, and shutdown."""

    def __init__(
        self,
        message: str,
        *,
        reason: ProcessProbeFailure,
        result: ProcessProbeResult | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.result = result


class ProcessProbeFailure(StrEnum):
    INVALID_LAUNCH = "invalid_launch"
    START_FAILED = "start_failed"
    STARTUP_TIMEOUT = "startup_timeout"
    HEALTH_TIMEOUT = "health_timeout"
    PROTOCOL_ERROR = "protocol_error"
    OUTPUT_LIMIT = "output_limit"
    EARLY_EXIT = "early_exit"
    STOP_TIMEOUT = "stop_timeout"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True, slots=True)
class AgentProcessSupervisorConfig:
    startup_timeout_seconds: float = 10.0
    health_timeout_seconds: float = 20.0
    stop_timeout_seconds: float = 5.0
    kill_timeout_seconds: float = 5.0
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "startup_timeout_seconds",
            "health_timeout_seconds",
            "stop_timeout_seconds",
            "kill_timeout_seconds",
        ):
            value = getattr(self, name)
            if not 0.05 <= value <= 300:
                raise ValueError(f"{name} must be between 0.05 and 300")
        if not 1024 <= self.max_output_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_output_bytes must be between 1024 and 67108864")


@dataclass(frozen=True, slots=True)
class ProcessLaunch:
    executable: Path
    arguments: tuple[str, ...] = ()
    working_directory: Path | None = None
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "executable", self.executable.expanduser().absolute())
        if self.working_directory is not None:
            object.__setattr__(
                self,
                "working_directory",
                self.working_directory.expanduser().absolute(),
            )
        if len(self.arguments) > _MAX_ARGUMENTS:
            raise ValueError("process launch contains too many arguments")
        encoded_size = 0
        for argument in self.arguments:
            if not isinstance(argument, str) or "\x00" in argument:
                raise ValueError("process launch contains an invalid argument")
            encoded_size += len(argument.encode("utf-8"))
        if encoded_size > _MAX_ARGUMENT_BYTES:
            raise ValueError("process launch arguments exceed the byte limit")
        seen_environment: set[str] = set()
        for name, value in self.environment:
            comparable_name = name.upper()
            if (
                _SAFE_ENVIRONMENT_NAME.fullmatch(name) is None
                or comparable_name in seen_environment
                or comparable_name not in _ALLOWED_EXTRA_ENVIRONMENT_NAMES
                or comparable_name in _BLOCKED_ENVIRONMENT_NAMES
                or comparable_name.startswith("DYLD_")
                or comparable_name.startswith("LD_")
                or "\x00" in value
                or len(value.encode("utf-8")) > 4096
            ):
                raise ValueError("process launch contains an invalid environment entry")
            seen_environment.add(comparable_name)


@dataclass(frozen=True, slots=True)
class ProcessProbeResult:
    pid: int
    exit_code: int | None
    started: bool
    healthy: bool
    terminated: bool
    killed: bool
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float


class AgentProcessSupervisor:
    """Run a health-probe process without a shell, leaked descriptors, or unbounded waits."""

    def __init__(self, config: AgentProcessSupervisorConfig | None = None) -> None:
        self.config = config or AgentProcessSupervisorConfig()

    def probe(self, launch: ProcessLaunch) -> ProcessProbeResult:
        self._validate_launch(launch)
        environment = _sanitized_environment(launch.environment)
        command = (os.fspath(launch.executable), *launch.arguments)
        working_directory = os.fspath(launch.working_directory or launch.executable.parent)

        started_at = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                cwd=working_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                shell=False,
                start_new_session=True,
                restore_signals=True,
                umask=0o077,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise AgentProcessSupervisorError(
                "candidate Agent process could not be started",
                reason=ProcessProbeFailure.START_FAILED,
            ) from error

        if process.stdout is None or process.stderr is None:
            with suppress(OSError, subprocess.SubprocessError):
                process.kill()
            raise AgentProcessSupervisorError(
                "candidate Agent output pipes are unavailable",
                reason=ProcessProbeFailure.START_FAILED,
            )

        capture = _BoundedCapture(self.config.max_output_bytes)
        readers = (
            _start_reader(process.stdout, capture, is_stdout=True),
            _start_reader(process.stderr, capture, is_stdout=False),
        )
        failure: ProcessProbeFailure | None = None
        failure_message = ""
        terminated = False
        killed = False

        stage = self._wait_for_stage(
            process,
            capture,
            marker="started",
            timeout=self.config.startup_timeout_seconds,
        )
        if stage is not None:
            failure, failure_message = stage
        else:
            stage = self._wait_for_stage(
                process,
                capture,
                marker="healthy",
                timeout=self.config.health_timeout_seconds,
            )
            if stage is not None:
                failure, failure_message = stage
            elif process.poll() is not None:
                failure = ProcessProbeFailure.EARLY_EXIT
                failure_message = "candidate Agent exited before supervised shutdown"

        terminated, killed, cleanup_failure = self._stop_process(process, capture)
        for reader in readers:
            reader.join(timeout=self.config.kill_timeout_seconds)
        capture.close_parent_streams(process)
        snapshot = capture.snapshot()
        result = ProcessProbeResult(
            pid=process.pid,
            exit_code=process.poll(),
            started=snapshot.started,
            healthy=snapshot.healthy,
            terminated=terminated,
            killed=killed,
            stdout=snapshot.stdout,
            stderr=snapshot.stderr,
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
        )
        if cleanup_failure is not None:
            failure = cleanup_failure
            failure_message = "candidate Agent process tree could not be reaped within its deadline"
        elif killed and failure is None:
            failure = ProcessProbeFailure.STOP_TIMEOUT
            failure_message = "candidate Agent ignored bounded graceful shutdown"
        elif snapshot.overflow and failure is None:
            failure = ProcessProbeFailure.OUTPUT_LIMIT
            failure_message = "candidate Agent exceeded its combined output limit"
        elif snapshot.protocol_error and failure is None:
            failure = ProcessProbeFailure.PROTOCOL_ERROR
            failure_message = "candidate Agent emitted an invalid health protocol sequence"

        if failure is not None:
            raise AgentProcessSupervisorError(
                failure_message,
                reason=failure,
                result=result,
            )
        return result

    @staticmethod
    def _validate_launch(launch: ProcessLaunch) -> None:
        try:
            metadata = launch.executable.lstat()
        except OSError as error:
            raise AgentProcessSupervisorError(
                "candidate Agent executable is unavailable",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AgentProcessSupervisorError(
                "candidate Agent executable must be a regular file",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            )
        if not metadata.st_mode & 0o111:
            raise AgentProcessSupervisorError(
                "candidate Agent executable is not executable",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            )
        working_directory = launch.working_directory or launch.executable.parent
        try:
            directory_metadata = working_directory.lstat()
        except OSError as error:
            raise AgentProcessSupervisorError(
                "candidate Agent working directory is unavailable",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            ) from error
        if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
            raise AgentProcessSupervisorError(
                "candidate Agent working directory must be a real directory",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            )

    def _wait_for_stage(
        self,
        process: subprocess.Popen[bytes],
        capture: _BoundedCapture,
        *,
        marker: str,
        timeout: float,
    ) -> tuple[ProcessProbeFailure, str] | None:
        deadline = time.monotonic() + timeout
        while True:
            snapshot = capture.snapshot()
            if snapshot.overflow:
                return (
                    ProcessProbeFailure.OUTPUT_LIMIT,
                    "candidate Agent exceeded its combined output limit",
                )
            if snapshot.protocol_error:
                return (
                    ProcessProbeFailure.PROTOCOL_ERROR,
                    "candidate Agent emitted an invalid health protocol sequence",
                )
            if marker == "started" and snapshot.started:
                return None
            if marker == "healthy" and snapshot.healthy:
                return None
            if process.poll() is not None:
                return (
                    ProcessProbeFailure.EARLY_EXIT,
                    f"candidate Agent exited before reporting {marker}",
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = (
                    ProcessProbeFailure.STARTUP_TIMEOUT
                    if marker == "started"
                    else ProcessProbeFailure.HEALTH_TIMEOUT
                )
                return reason, f"candidate Agent {marker} deadline expired"
            capture.wait_for_activity(min(remaining, 0.05))

    def _stop_process(
        self,
        process: subprocess.Popen[bytes],
        capture: _BoundedCapture,
    ) -> tuple[bool, bool, ProcessProbeFailure | None]:
        terminated = _signal_process_tree(process, signal.SIGTERM)
        if _wait_for_exit_and_streams(
            process,
            capture,
            timeout=self.config.stop_timeout_seconds,
        ):
            return terminated, False, None
        killed = _signal_process_tree(process, _FORCE_SIGNAL)
        if _wait_for_exit_and_streams(
            process,
            capture,
            timeout=self.config.kill_timeout_seconds,
        ):
            return terminated, killed, None
        return terminated, killed, ProcessProbeFailure.CLEANUP_FAILED


@dataclass(frozen=True, slots=True)
class InstalledReleaseProcessHealthCheck:
    """Resolve and execute a declared candidate binary before installer state commit."""

    installation_root: Path
    supervisor: AgentProcessSupervisor
    executable_path: str = "bin/aisoc-agent"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "installation_root",
            self.installation_root.expanduser().absolute(),
        )
        path = PurePosixPath(self.executable_path)
        if (
            not self.executable_path
            or path.is_absolute()
            or "\\" in self.executable_path
            or path.as_posix() != self.executable_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("candidate executable path is unsafe")

    def __call__(self, installed: InstalledRelease) -> bool:
        declared = next(
            (item for item in installed.files if item.path == self.executable_path),
            None,
        )
        if declared is None or not declared.executable:
            raise AgentProcessSupervisorError(
                "candidate Agent executable is not declared executable content",
                reason=ProcessProbeFailure.INVALID_LAUNCH,
            )
        content_root = (
            self.installation_root
            / "artifacts"
            / installed.artifact_id
            / "versions"
            / installed.deployment_dir
            / "content"
        )
        executable = content_root.joinpath(*PurePosixPath(self.executable_path).parts)
        result = self.supervisor.probe(
            ProcessLaunch(
                executable=executable,
                arguments=("health-probe",),
                working_directory=content_root,
            )
        )
        return result.started and result.healthy and not result.killed


@dataclass(frozen=True, slots=True)
class _CaptureSnapshot:
    stdout: bytes
    stderr: bytes
    started: bool
    healthy: bool
    protocol_error: bool
    overflow: bool
    closed_streams: int


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._stdout_pending = bytearray()
        self._started = False
        self._healthy = False
        self._protocol_error = False
        self._overflow = False
        self._closed_streams = 0
        self._condition = threading.Condition()

    def add(self, value: bytes, *, is_stdout: bool) -> None:
        with self._condition:
            remaining = self._limit - len(self._stdout) - len(self._stderr)
            accepted = value[: max(0, remaining)]
            if is_stdout:
                self._stdout.extend(accepted)
                self._parse_stdout(accepted)
            else:
                self._stderr.extend(accepted)
            if len(value) > len(accepted):
                self._overflow = True
            self._condition.notify_all()

    def mark_closed(self, *, is_stdout: bool) -> None:
        with self._condition:
            self._closed_streams += 1
            if is_stdout and self._stdout_pending:
                self._parse_line(bytes(self._stdout_pending))
                self._stdout_pending.clear()
            self._condition.notify_all()

    def snapshot(self) -> _CaptureSnapshot:
        with self._condition:
            return _CaptureSnapshot(
                stdout=bytes(self._stdout),
                stderr=bytes(self._stderr),
                started=self._started,
                healthy=self._healthy,
                protocol_error=self._protocol_error,
                overflow=self._overflow,
                closed_streams=self._closed_streams,
            )

    def wait_for_activity(self, timeout: float) -> None:
        with self._condition:
            self._condition.wait(timeout)

    def close_parent_streams(self, process: subprocess.Popen[bytes]) -> None:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                with suppress(OSError, subprocess.SubprocessError):
                    stream.close()

    def _parse_stdout(self, value: bytes) -> None:
        self._stdout_pending.extend(value)
        while b"\n" in self._stdout_pending:
            raw_line, _, remainder = self._stdout_pending.partition(b"\n")
            self._stdout_pending = bytearray(remainder)
            self._parse_line(bytes(raw_line.rstrip(b"\r")))
        if len(self._stdout_pending) > _MAX_PROTOCOL_LINE_BYTES:
            self._protocol_error = True

    def _parse_line(self, line: bytes) -> None:
        if line == PROCESS_STARTED_MARKER:
            if self._started or self._healthy:
                self._protocol_error = True
            self._started = True
        elif line == PROCESS_HEALTHY_MARKER:
            if not self._started or self._healthy:
                self._protocol_error = True
            self._healthy = True


def _start_reader(
    stream: IO[bytes],
    capture: _BoundedCapture,
    *,
    is_stdout: bool,
) -> threading.Thread:
    def read_stream() -> None:
        try:
            descriptor = stream.fileno()
            while value := os.read(descriptor, 4096):
                capture.add(value, is_stdout=is_stdout)
        finally:
            capture.mark_closed(is_stdout=is_stdout)

    thread = threading.Thread(target=read_stream, daemon=True)
    thread.start()
    return thread


def _sanitized_environment(extra: tuple[tuple[str, str], ...]) -> dict[str, str]:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    environment["PYTHONUNBUFFERED"] = "1"
    environment.update(dict(extra))
    return environment


def _signal_process_tree(process: subprocess.Popen[bytes], requested: signal.Signals) -> bool:
    try:
        os.killpg(process.pid, requested)
        return True
    except (OSError, ProcessLookupError):
        return False


def _wait_for_exit_and_streams(
    process: subprocess.Popen[bytes],
    capture: _BoundedCapture,
    *,
    timeout: float,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = capture.snapshot()
        if process.poll() is not None and snapshot.closed_streams == 2:
            return True
        capture.wait_for_activity(min(0.05, max(0.0, deadline - time.monotonic())))
    return process.poll() is not None and capture.snapshot().closed_streams == 2
