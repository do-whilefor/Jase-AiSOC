from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from blue_team.agent_core import (
    AgentProcessConfig,
    AgentProcessError,
    PrivateJsonlJournal,
    load_agent_process_config,
    run_agent_process,
)
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
