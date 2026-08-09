from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from blue_team import __version__
from blue_team.agent_core import (
    AgentProcessConfig,
    AgentProcessError,
    PrivateJsonlJournal,
    load_agent_process_config,
    run_agent_process,
)
from blue_team.agent_core.queue import LocalDiskQueue, QueueConfig
from blue_team.platform import LinuxPlatformAdapter
from tests.unit.test_agent_contracts import AGENT_ID, BOOT_ID, HOST_ID, TENANT_ID


def config_value(state_directory: Path) -> dict[str, object]:
    return {
        "format_version": 1,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "host_id": HOST_ID,
        "boot_id": BOOT_ID,
        "state_directory": str(state_directory.absolute()),
        "heartbeat_interval_seconds": 5,
        "heartbeat_retry_seconds": 1,
        "poll_interval_seconds": 0.05,
        "max_payload_bytes": 1024 * 1024,
        "critical_reserve_bytes": 0,
        "max_event_bytes": 64 * 1024,
        "min_free_bytes": 0,
    }


def write_config(path: Path, state_directory: Path) -> None:
    path.write_text(json.dumps(config_value(state_directory)), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_configured_agent_process_persists_heartbeat_and_lifecycle_on_stop(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agent.json"
    state_directory = tmp_path / "state"
    write_config(config_path, state_directory)
    config = load_agent_process_config(config_path)
    stop_event = threading.Event()
    outcome: list[int] = []
    failures: list[BaseException] = []

    def run() -> None:
        try:
            outcome.append(
                run_agent_process(
                    config,
                    stop_event=stop_event,
                    capability_probe=LinuxPlatformAdapter().capabilities,
                )
            )
        except BaseException as error:
            failures.append(error)

    process = threading.Thread(target=run)
    process.start()
    deadline = time.monotonic() + 10
    while not config.heartbeat_journal_path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    with pytest.raises(AgentProcessError, match="another Agent process"):
        run_agent_process(
            config,
            stop_event=threading.Event(),
            capability_probe=LinuxPlatformAdapter().capabilities,
        )
    stop_event.set()
    process.join(timeout=10)

    assert not process.is_alive()
    assert failures == []
    assert outcome == [0]
    heartbeats = jsonl(config.heartbeat_journal_path)
    assert len(heartbeats) == 1
    heartbeat = heartbeats[0]
    assert heartbeat["kind"] == "heartbeat"
    assert heartbeat["payload"]["tenant_id"] == TENANT_ID  # type: ignore[index]
    assert heartbeat["payload"]["agent_version"] == __version__  # type: ignore[index]
    lifecycle = jsonl(config.lifecycle_journal_path)
    kinds = [record["kind"] for record in lifecycle]
    assert kinds[0] == "process_starting"
    assert "heartbeat_attempt" in kinds
    runtime_events = [
        record["payload"] for record in lifecycle if record["kind"] == "runtime_event"
    ]
    assert any(event["state"] == "running" for event in runtime_events)  # type: ignore[index]
    assert runtime_events[-1]["state"] == "stopped"  # type: ignore[index]
    assert config.queue_path.exists()
    if os.name != "nt":
        assert stat.S_IMODE(config.state_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE((config.state_directory / ".agent.lock").stat().st_mode) == 0o600
        assert stat.S_IMODE(config.queue_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(config.heartbeat_journal_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(config.lifecycle_journal_path.stat().st_mode) == 0o600


def test_agent_process_config_is_bounded_private_and_absolute(tmp_path: Path) -> None:
    config_path = tmp_path / "agent.json"
    write_config(config_path, tmp_path / "state")
    assert load_agent_process_config(config_path).tenant_id == TENANT_ID

    config_path.write_bytes(b"{" + b" " * (64 * 1024))
    if os.name != "nt":
        config_path.chmod(0o600)
    with pytest.raises(AgentProcessError, match="byte limit"):
        load_agent_process_config(config_path)

    invalid = config_value(tmp_path / "state")
    invalid["state_directory"] = "relative/state"
    with pytest.raises(ValidationError, match="absolute"):
        AgentProcessConfig.model_validate(invalid)

    incomplete_audit = config_value(tmp_path / "state")
    incomplete_audit["auditd_enabled"] = True
    with pytest.raises(ValidationError, match="auditd_log_path"):
        AgentProcessConfig.model_validate(incomplete_audit)


def test_agent_process_registers_audit_collector_and_queues_event(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.log"
    audit_log.write_bytes(
        b"type=SYSCALL msg=audit(1786176000.123:50): "
        b'arch=c000003e syscall=59 success=yes ppid=49 pid=50 uid=0 exe="/bin/sh"\n'
        b'type=EXECVE msg=audit(1786176000.123:50): argc=1 a0="sh"\n'
        b"type=EOE msg=audit(1786176000.123:50):\n"
    )
    values = config_value(tmp_path / "state")
    values.update(
        {
            "auditd_enabled": True,
            "auditd_log_path": str(audit_log.absolute()),
            "auditd_start_at_end": False,
            "max_event_bytes": 4 * 1024 * 1024,
        }
    )
    config = AgentProcessConfig.model_validate(values)
    stop_event = threading.Event()
    failures: list[BaseException] = []
    probe: LocalDiskQueue | None = None

    def run() -> None:
        try:
            run_agent_process(
                config,
                stop_event=stop_event,
                capability_probe=LinuxPlatformAdapter().capabilities,
            )
        except BaseException as error:
            failures.append(error)

    process = threading.Thread(target=run)
    process.start()
    deadline = time.monotonic() + 10
    queued = 0
    while time.monotonic() < deadline:
        if config.queue_path.exists():
            probe = LocalDiskQueue(
                QueueConfig(
                    database_path=config.queue_path,
                    tenant_id=TENANT_ID,
                    agent_id=AGENT_ID,
                    host_id=HOST_ID,
                    max_payload_bytes=config.max_payload_bytes,
                    critical_reserve_bytes=config.critical_reserve_bytes,
                    max_event_bytes=config.max_event_bytes,
                    min_free_bytes=config.min_free_bytes,
                )
            )
            queued = probe.telemetry().queued_count
            if queued:
                break
        time.sleep(0.02)
    stop_event.set()
    process.join(timeout=10)

    assert not process.is_alive()
    assert failures == []
    assert queued == 1
    assert probe is not None
    batch = probe.reserve_batch()
    assert batch is not None
    assert batch.events[0].event.event_type == "process.exec"
    assert batch.events[0].event.source.kind.value == "auditd"
    assert config.auditd_state_path.exists()


def test_agent_process_rejects_linked_or_shared_configuration(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX symlink and mode checks require Linux")
    target = tmp_path / "target.json"
    write_config(target, tmp_path / "state")
    linked = tmp_path / "linked.json"
    linked.symlink_to(target)
    with pytest.raises(AgentProcessError, match="regular file"):
        load_agent_process_config(linked)

    target.chmod(0o640)
    with pytest.raises(AgentProcessError, match="group or other"):
        load_agent_process_config(target)


def test_private_journal_rejects_link_substitution(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX symlink semantics require Linux")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    destination = tmp_path / "attacker-controlled"
    destination.write_text("unchanged", encoding="utf-8")
    linked = state / "lifecycle.jsonl"
    linked.symlink_to(destination)
    journal = PrivateJsonlJournal(linked)

    with pytest.raises(AgentProcessError, match="persisted"):
        journal.append("test", {})
    assert destination.read_text(encoding="utf-8") == "unchanged"

    linked.unlink()
    os.link(destination, linked)
    journal = PrivateJsonlJournal(linked)
    with pytest.raises(AgentProcessError, match="private regular file"):
        journal.append("test", {})
    assert destination.read_text(encoding="utf-8") == "unchanged"
