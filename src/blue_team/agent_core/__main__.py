"""Command-line entry point for the Linux Agent process and release health probe."""

from __future__ import annotations

import argparse
import signal
import sys
import tempfile
import threading
from collections.abc import Sequence
from pathlib import Path

from blue_team.agent_core.process import (
    AgentProcessError,
    load_agent_process_config,
    run_agent_process,
)
from blue_team.agent_core.queue import LocalDiskQueue, QueueConfig
from blue_team.agent_core.runtime import AgentRuntime, RuntimeConfig
from blue_team.agent_core.supervisor import (
    PROCESS_HEALTHY_MARKER,
    PROCESS_STARTED_MARKER,
)
from blue_team.platform import LinuxPlatformAdapter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blue-team-agent")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run the configured long-lived Agent")
    run.add_argument("--config", type=Path, required=True)
    commands.add_parser(
        "health-probe",
        help="run the bounded candidate-release startup and shutdown protocol",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)
    try:
        if arguments.command == "health-probe":
            return _run_health_probe(stop_event)
        config = load_agent_process_config(arguments.config)
        return run_agent_process(config, stop_event=stop_event)
    except AgentProcessError as error:
        sys.stderr.write(f"blue-team-agent failed: {error}\n")
        return 1
    except Exception:
        sys.stderr.write("blue-team-agent failed: runtime initialization error\n")
        return 1


def _run_health_probe(stop_event: threading.Event) -> int:
    with tempfile.TemporaryDirectory(prefix="blue-team-agent-health-") as temporary:
        root = Path(temporary)
        queue = LocalDiskQueue(
            QueueConfig(
                database_path=root / "queue.sqlite3",
                tenant_id="ten_healthprobe1",
                agent_id="agent_healthprobe1",
                host_id="host_healthprobe1",
                max_payload_bytes=1024 * 1024,
                critical_reserve_bytes=0,
                max_event_bytes=64 * 1024,
                min_free_bytes=0,
            )
        )
        runtime = AgentRuntime(
            RuntimeConfig(
                tenant_id="ten_healthprobe1",
                agent_id="agent_healthprobe1",
                host_id="host_healthprobe1",
                boot_id="release-health-probe",
                heartbeat_interval_seconds=30,
                heartbeat_retry_seconds=5,
            ),
            queue=queue,
            capability_probe=LinuxPlatformAdapter().capabilities,
            heartbeat_sink=lambda _heartbeat: None,
        )
        _emit_protocol_marker(PROCESS_STARTED_MARKER)
        runtime.start()
        attempt = runtime.run_once()
        if attempt is None or not attempt.delivered:
            raise AgentProcessError("candidate runtime did not complete its first heartbeat")
        _emit_protocol_marker(PROCESS_HEALTHY_MARKER)
        while not stop_event.wait(0.1):
            pass
        runtime.stop()
    return 0


def _emit_protocol_marker(value: bytes) -> None:
    sys.stdout.buffer.write(value + b"\n")
    sys.stdout.buffer.flush()


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    for name in ("SIGTERM", "SIGINT"):
        requested = getattr(signal, name, None)
        if requested is not None:
            signal.signal(requested, request_stop)


if __name__ == "__main__":
    raise SystemExit(main())
