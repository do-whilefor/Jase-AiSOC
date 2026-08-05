"""Standalone non-root Linux smoke for the Agent process and release health gate."""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blue_team.agent_core import (
    AgentProcessSupervisor,
    AgentProcessSupervisorConfig,
    AgentProcessSupervisorError,
    ArtifactKind,
    InstalledReleaseProcessHealthCheck,
    ProcessLaunch,
    ProcessProbeFailure,
    ReleaseActivationError,
    ReleaseInstaller,
    ReleaseInstallerConfig,
    ReleaseManifest,
    ReleaseState,
    ReleaseStateStore,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerifier,
    VerifiedRelease,
    sign_release,
)

STARTED = "BLUE_TEAM_AGENT_HEALTH_V1 STARTED"
HEALTHY = "BLUE_TEAM_AGENT_HEALTH_V1 HEALTHY"
NOW = datetime(2026, 8, 4, 8, tzinfo=UTC)


def main() -> int:
    assert os.name == "posix"
    assert _getuid() == 10001
    agent_executable = Path("/app/.venv/bin/blue-team-agent")
    python_executable = Path(sys.executable).resolve()
    bounded = AgentProcessSupervisor(
        AgentProcessSupervisorConfig(
            startup_timeout_seconds=5,
            health_timeout_seconds=10,
            stop_timeout_seconds=2,
            kill_timeout_seconds=2,
            max_output_bytes=64 * 1024,
        )
    )
    healthy = bounded.probe(ProcessLaunch(agent_executable, ("health-probe",), Path("/app")))
    assert healthy.started and healthy.healthy and healthy.terminated and not healthy.killed
    assert healthy.exit_code == 0

    _expect_failure(
        AgentProcessSupervisor(
            AgentProcessSupervisorConfig(
                startup_timeout_seconds=0.1,
                health_timeout_seconds=1,
                stop_timeout_seconds=1,
                kill_timeout_seconds=1,
                max_output_bytes=4096,
            )
        ),
        ProcessLaunch(python_executable, ("-c", "import time; time.sleep(30)")),
        ProcessProbeFailure.STARTUP_TIMEOUT,
    )
    _expect_failure(
        AgentProcessSupervisor(
            AgentProcessSupervisorConfig(
                startup_timeout_seconds=1,
                health_timeout_seconds=0.1,
                stop_timeout_seconds=1,
                kill_timeout_seconds=1,
                max_output_bytes=4096,
            )
        ),
        ProcessLaunch(
            python_executable,
            ("-c", f"import time; print({STARTED!r},flush=True); time.sleep(30)"),
        ),
        ProcessProbeFailure.HEALTH_TIMEOUT,
    )
    _expect_failure(
        bounded,
        ProcessLaunch(
            python_executable,
            (
                "-c",
                "import os,time; os.write(1,(b'x'*512+b'\\n')*256); time.sleep(30)",
            ),
        ),
        ProcessProbeFailure.OUTPUT_LIMIT,
    )
    ignoring = AgentProcessSupervisor(
        AgentProcessSupervisorConfig(
            startup_timeout_seconds=1,
            health_timeout_seconds=1,
            stop_timeout_seconds=0.1,
            kill_timeout_seconds=1,
            max_output_bytes=4096,
        )
    )
    ignored = _expect_failure(
        ignoring,
        ProcessLaunch(
            python_executable,
            (
                "-c",
                "import signal,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                f"print({STARTED!r},flush=True); print({HEALTHY!r},flush=True); "
                "time.sleep(30)",
            ),
        ),
        ProcessProbeFailure.STOP_TIMEOUT,
    )
    assert ignored.result is not None and ignored.result.killed

    os.environ["BLUE_TEAM_SMOKE_SECRET"] = "must-not-be-inherited"
    literal_argument = "; touch /tmp/blue-team-supervisor-injected"
    literal_source = "\n".join(
        (
            "import os,signal,sys,time",
            "assert 'BLUE_TEAM_SMOKE_SECRET' not in os.environ",
            "assert sys.argv[1].startswith('; touch')",
            "stopping=False",
            "def stop(*_args):\n global stopping; stopping=True",
            "signal.signal(signal.SIGTERM,stop)",
            f"print({STARTED!r},flush=True)",
            f"print({HEALTHY!r},flush=True)",
            "while not stopping: time.sleep(0.01)",
        )
    )
    literal = bounded.probe(
        ProcessLaunch(
            python_executable,
            ("-c", literal_source, literal_argument),
        )
    )
    assert literal.healthy
    assert not Path("/tmp/blue-team-supervisor-injected").exists()

    with tempfile.TemporaryDirectory(prefix="blue-team-process-smoke-") as temporary:
        root = Path(temporary)
        _configured_process_smoke(agent_executable, root)
        _installer_process_gate_smoke(agent_executable, root)

    print(
        json.dumps(
            {
                "uid": _getuid(),
                "real_agent_probe": "healthy",
                "single_instance": "locked",
                "startup_timeout": "bounded",
                "health_timeout": "bounded",
                "output": "bounded",
                "term_kill": "bounded",
                "environment": "sanitized",
                "argv": "literal",
                "configured_process": "stopped_cleanly",
                "installer_gate": "commit_and_rollback_verified",
            },
            sort_keys=True,
        )
    )
    return 0


def _configured_process_smoke(agent_executable: Path, root: Path) -> None:
    state = root / "agent-state"
    config_path = root / "agent.json"
    config_path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "tenant_id": "ten_smoketest01",
                "agent_id": "agent_smoketest01",
                "host_id": "host_smoketest01",
                "boot_id": "linux-supervisor-smoke",
                "state_directory": str(state),
                "heartbeat_interval_seconds": 5,
                "heartbeat_retry_seconds": 1,
                "poll_interval_seconds": 0.05,
                "max_payload_bytes": 1024 * 1024,
                "critical_reserve_bytes": 0,
                "max_event_bytes": 64 * 1024,
                "min_free_bytes": 0,
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    process = subprocess.Popen(
        (os.fspath(agent_executable), "run", "--config", os.fspath(config_path)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    try:
        deadline = time.monotonic() + 10
        while not (state / "heartbeats.jsonl").exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("configured Agent exited before its first heartbeat")
            time.sleep(0.05)
        assert (state / "heartbeats.jsonl").exists()
        competing = subprocess.run(
            (os.fspath(agent_executable), "run", "--config", os.fspath(config_path)),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            close_fds=True,
            timeout=5,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        assert competing.returncode == 1
        assert b"another Agent process" in competing.stderr
        _kill_process_group(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            _kill_process_group(process.pid, signal.Signals(9))
            process.wait(timeout=2)
    assert process.returncode == 0, (stdout, stderr)
    assert stdout == b"" and stderr == b""
    lifecycle = [
        json.loads(line)
        for line in (state / "lifecycle.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    states = [
        record["payload"]["state"] for record in lifecycle if record["kind"] == "runtime_event"
    ]
    assert "running" in states and states[-1] == "stopped"
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    for name in (".agent.lock", "queue.sqlite3", "heartbeats.jsonl", "lifecycle.jsonl"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600


def _installer_process_gate_smoke(agent_executable: Path, root: Path) -> None:
    install_root = root / "install"
    state_store = ReleaseStateStore(root / "release-state")
    installer = ReleaseInstaller(ReleaseInstallerConfig(install_root), state_store=state_store)
    private_key = Ed25519PrivateKey.generate()
    verifier = ReleaseVerifier(
        (
            ReleaseTrustKey(
                key_id="release.smoke",
                public_key=private_key.public_key(),
                allowed_kinds=frozenset({ArtifactKind.AGENT}),
            ),
        ),
        installation_id="inst_smoke01",
        operating_system="linux",
        architecture="x86_64",
        distro="debian",
    )
    process_supervisor = AgentProcessSupervisor(
        AgentProcessSupervisorConfig(
            startup_timeout_seconds=5,
            health_timeout_seconds=10,
            stop_timeout_seconds=2,
            kill_timeout_seconds=2,
            max_output_bytes=64 * 1024,
        )
    )
    gate = InstalledReleaseProcessHealthCheck(install_root, process_supervisor)
    wrapper = f'#!/bin/sh\nexec {agent_executable} "$@"\n'.encode()
    first_payload = _tar_payload(wrapper)
    first_verified = _verified(
        first_payload,
        private_key,
        verifier,
        ReleaseState(),
        version="1.0.0",
        sequence=1,
    )
    first = installer.install(
        first_verified,
        first_payload,
        verifier=verifier,
        health_check=gate,
        now=NOW,
    )
    executable = (
        install_root
        / "artifacts"
        / "agent.runtime"
        / "versions"
        / first.installed.deployment_dir
        / "content"
        / "bin"
        / "blue-team-agent"
    )
    assert stat.S_IMODE(executable.stat().st_mode) == 0o500
    assert first.state.revision == 1

    failed_payload = _tar_payload(f"#!/bin/sh\nprintf '{STARTED}\\n'\nsleep 30\n".encode())
    second = _verified(
        failed_payload,
        private_key,
        verifier,
        state_store.load(),
        version="1.0.1",
        sequence=2,
    )
    queue_sentinel = root / "queue-sentinel"
    queue_sentinel.write_bytes(b"preserved")
    try:
        installer.install(
            second,
            failed_payload,
            verifier=verifier,
            health_check=gate,
            now=NOW,
        )
    except ReleaseActivationError:
        pass
    else:
        raise AssertionError("unhealthy candidate was activated")
    assert installer.active_release("agent.runtime") == first.active
    assert state_store.load() == first.state
    assert queue_sentinel.read_bytes() == b"preserved"


def _tar_payload(executable: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        directory = tarfile.TarInfo("bin/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = 0
        archive.addfile(directory)
        member = tarfile.TarInfo("bin/blue-team-agent")
        member.size = len(executable)
        member.mode = 0o755
        member.mtime = 0
        archive.addfile(member, io.BytesIO(executable))
    return output.getvalue()


def _verified(
    payload: bytes,
    private_key: Ed25519PrivateKey,
    verifier: ReleaseVerifier,
    state: ReleaseState,
    *,
    version: str,
    sequence: int,
) -> VerifiedRelease:
    manifest = ReleaseManifest(
        artifact_id="agent.runtime",
        kind=ArtifactKind.AGENT,
        version=version,
        sequence=sequence,
        target=ReleaseTarget(architecture="x86_64", distro="debian"),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size=len(payload),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        minimum_allowed_version="1.0.0",
        rollout_id="rollout.smoke",
    )
    signed = sign_release(
        manifest,
        key_id="release.smoke",
        private_key=private_key,
    )
    return verifier.verify(signed, payload, state, now=NOW)


def _expect_failure(
    supervisor: AgentProcessSupervisor,
    launch: ProcessLaunch,
    reason: ProcessProbeFailure,
) -> AgentProcessSupervisorError:
    try:
        supervisor.probe(launch)
    except AgentProcessSupervisorError as error:
        assert error.reason is reason, error
        return error
    raise AssertionError(f"probe unexpectedly succeeded instead of {reason}")


def _getuid() -> int:
    return int(os.getuid())


def _kill_process_group(pid: int, requested: signal.Signals) -> None:
    os.killpg(pid, requested)


if __name__ == "__main__":
    raise SystemExit(main())
