from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from aisoc.agent_core import (
    PROCESS_HEALTHY_MARKER,
    PROCESS_STARTED_MARKER,
    AgentProcessSupervisor,
    AgentProcessSupervisorConfig,
    AgentProcessSupervisorError,
    ProcessLaunch,
    ProcessProbeFailure,
)


def supervisor(
    *,
    startup: float = 1,
    health: float = 1,
    stop: float = 1,
    kill: float = 1,
    output: int = 16 * 1024,
) -> AgentProcessSupervisor:
    return AgentProcessSupervisor(
        AgentProcessSupervisorConfig(
            startup_timeout_seconds=startup,
            health_timeout_seconds=health,
            stop_timeout_seconds=stop,
            kill_timeout_seconds=kill,
            max_output_bytes=output,
        )
    )


def python_launch(source: str, *arguments: str) -> ProcessLaunch:
    return ProcessLaunch(
        executable=Path(sys.executable).resolve(),
        arguments=("-c", source, *arguments),
        working_directory=Path.cwd(),
    )


def marker_source(*, started: bool = True, healthy: bool = True, body: str = "") -> str:
    lines = [
        "import signal,time",
        "stopping=False",
        "def stop(*_args):\n global stopping; stopping=True",
        "signal.signal(signal.SIGTERM,stop)",
    ]
    if started:
        lines.append(f"print({PROCESS_STARTED_MARKER.decode()!r},flush=True)")
    if body:
        lines.append(body)
    if healthy:
        lines.append(f"print({PROCESS_HEALTHY_MARKER.decode()!r},flush=True)")
    lines.append("\nwhile not stopping: time.sleep(0.01)")
    return "\n".join(lines)


def test_probe_proves_ordered_startup_health_and_bounded_stop() -> None:
    result = supervisor().probe(python_launch(marker_source()))

    assert result.started is True
    assert result.healthy is True
    assert result.terminated is True
    assert result.killed is False
    assert result.stdout.splitlines() == [PROCESS_STARTED_MARKER, PROCESS_HEALTHY_MARKER]
    assert result.stderr == b""


def test_probe_has_distinct_startup_and_health_deadlines() -> None:
    with pytest.raises(AgentProcessSupervisorError) as startup_error:
        supervisor(startup=0.1).probe(python_launch("import time; time.sleep(30)"))
    assert startup_error.value.reason is ProcessProbeFailure.STARTUP_TIMEOUT
    assert startup_error.value.result is not None
    assert startup_error.value.result.started is False

    delayed_health = marker_source(healthy=False, body="time.sleep(30)")
    with pytest.raises(AgentProcessSupervisorError) as health_error:
        supervisor(health=0.1).probe(python_launch(delayed_health))
    assert health_error.value.reason is ProcessProbeFailure.HEALTH_TIMEOUT
    assert health_error.value.result is not None
    assert health_error.value.result.started is True
    assert health_error.value.result.healthy is False


def test_probe_rejects_crash_and_out_of_order_health_protocol() -> None:
    crashed = f"print({PROCESS_STARTED_MARKER.decode()!r},flush=True); raise SystemExit(17)"
    with pytest.raises(AgentProcessSupervisorError) as crash_error:
        supervisor().probe(python_launch(crashed))
    assert crash_error.value.reason is ProcessProbeFailure.EARLY_EXIT
    assert crash_error.value.result is not None
    assert crash_error.value.result.exit_code == 17

    out_of_order = marker_source(started=False)
    with pytest.raises(AgentProcessSupervisorError) as protocol_error:
        supervisor().probe(python_launch(out_of_order))
    assert protocol_error.value.reason is ProcessProbeFailure.PROTOCOL_ERROR


def test_probe_kills_process_that_ignores_graceful_stop() -> None:
    source = "\n".join(
        (
            "import signal,time",
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)",
            f"print({PROCESS_STARTED_MARKER.decode()!r},flush=True)",
            f"print({PROCESS_HEALTHY_MARKER.decode()!r},flush=True)",
            "time.sleep(30)",
        )
    )
    with pytest.raises(AgentProcessSupervisorError) as error:
        supervisor(stop=0.1, kill=1).probe(python_launch(source))

    assert error.value.reason is ProcessProbeFailure.STOP_TIMEOUT
    assert error.value.result is not None
    assert error.value.result.killed is True


def test_probe_bounds_combined_output_without_pipe_deadlock() -> None:
    source = "\n".join(
        (
            "import os,time",
            "os.write(1,b'x'*4096)",
            "os.write(2,b'y'*4096)",
            "time.sleep(30)",
        )
    )
    with pytest.raises(AgentProcessSupervisorError) as error:
        supervisor(output=1024).probe(python_launch(source))

    assert error.value.reason is ProcessProbeFailure.OUTPUT_LIMIT
    assert error.value.result is not None
    assert len(error.value.result.stdout) + len(error.value.result.stderr) == 1024


def test_launch_uses_literal_argv_and_does_not_inherit_parent_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    injected = tmp_path / "would-have-been-created"
    malicious = f";__import__('pathlib').Path({str(injected)!r}).write_text('bad')"
    monkeypatch.setenv("AISOC_TEST_PARENT_SECRET", "must-not-cross-exec")
    source = "\n".join(
        (
            "import os,signal,sys,time",
            "assert sys.argv[1].startswith(';__import__')",
            "assert 'AISOC_TEST_PARENT_SECRET' not in os.environ",
            "stopping=False",
            "def stop(*_args):\n global stopping; stopping=True",
            "signal.signal(signal.SIGTERM,stop)",
            f"print({PROCESS_STARTED_MARKER.decode()!r},flush=True)",
            f"print({PROCESS_HEALTHY_MARKER.decode()!r},flush=True)",
            "\nwhile not stopping: time.sleep(0.01)",
        )
    )

    result = supervisor().probe(python_launch(source, malicious))

    assert result.healthy is True
    assert not injected.exists()


def test_launch_rejects_loader_environment_and_linked_executable(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="environment"):
        ProcessLaunch(
            Path(sys.executable).resolve(),
            environment=(("LD_PRELOAD", "malicious.so"),),
        )

    linked = tmp_path / "python"
    linked.symlink_to(Path(sys.executable))
    with pytest.raises(AgentProcessSupervisorError) as error:
        supervisor().probe(ProcessLaunch(linked))
    assert error.value.reason is ProcessProbeFailure.INVALID_LAUNCH


def _resolve_agent_executable() -> tuple[Path, tuple[str, ...]]:
    """Resolve the real health-probe without relying on inherited PYTHONPATH."""
    sibling = Path(sys.executable).parent / "aisoc-agent"
    if sibling.is_file() and not sibling.is_symlink() and os.access(sibling, os.X_OK):
        return sibling, ("health-probe",)
    source_root = Path(__file__).resolve().parents[2] / "src"
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {str(source_root)!r});"
        "from aisoc.agent_core.__main__ import main;"
        "raise SystemExit(main(['health-probe']))"
    )
    return Path(sys.executable).resolve(), ("-c", bootstrap)


def test_real_agent_health_probe_runs_under_the_same_protocol() -> None:
    executable, arguments = _resolve_agent_executable()
    result = supervisor(startup=5, health=10, stop=2, kill=2).probe(
        ProcessLaunch(
            executable=executable,
            arguments=arguments,
            working_directory=Path.cwd(),
        )
    )

    assert result.started is True
    assert result.healthy is True
    assert result.killed is False
