"""P5 deterministic host runtime behavior rules."""

from __future__ import annotations

import ipaddress
import posixpath
from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from pathlib import PurePosixPath

from aisoc._rustcore import sha256_hex
from aisoc.detection_engine.base import Detection, Rule, RuleContext
from aisoc.detection_engine.rule_registry import register
from aisoc.domain.detection import AttackState, DetectionCategory
from aisoc.domain.resources import IncidentSeverity
from aisoc.domain.security_event import SecurityEvent

_WEB_PARENT_NAMES = {
    "apache2",
    "caddy",
    "gunicorn",
    "httpd",
    "nginx",
    "php-fpm",
    "uwsgi",
}
_SHELL_OR_INTERPRETER_NAMES = {
    "bash",
    "dash",
    "ksh",
    "perl",
    "python",
    "python3",
    "ruby",
    "sh",
    "zsh",
}
_DOWNLOADERS = {"aria2c", "curl", "fetch", "wget"}
_SUSPICIOUS_PERSISTENCE_WRITERS = {
    *_SHELL_OR_INTERPRETER_NAMES,
    *_DOWNLOADERS,
    "cp",
    "install",
    "sed",
    "tee",
}
_WRITE_EVENT_TYPES = {"file.creat", "file.open", "file.openat", "file.rename", "file.write"}


def _basename(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return PurePosixPath(value).name.lower()


def _ordered_unique(events: Sequence[SecurityEvent]) -> list[SecurityEvent]:
    unique = {event.event_id: event for event in events}
    return sorted(unique.values(), key=lambda event: (event.event_time, event.event_id))


def _process_key(event: SecurityEvent) -> tuple[str, int] | None:
    if event.boot_id is None or event.actor is None or event.actor.pid is None:
        return None
    return event.boot_id, event.actor.pid


def _normalized_path(event: SecurityEvent) -> str | None:
    if event.file is None or not event.file.path:
        return None
    return posixpath.normpath(event.file.path)


def _file_entity(boot_id: str, path: str) -> str:
    value = f"file:{boot_id}:{path}"
    if len(value) <= 256:
        return value
    digest = sha256_hex(path.encode())
    return f"file:{boot_id}:{digest}"[:256]


def _process_generation_entity(boot_id: str, pid: int, event_id: str) -> str:
    digest = sha256_hex(event_id.encode())[:16]
    return f"process:{boot_id}:{pid}:gen:{digest}"[:256]


def _display_path(path: str) -> str:
    return path if len(path) <= 320 else f"{path[:300]}...{path[-16:]}"


def _successful(event: SecurityEvent) -> bool:
    return event.outcome != "failure"


def _write_event(event: SecurityEvent) -> bool:
    if event.event_type not in _WRITE_EVENT_TYPES or not _successful(event):
        return False
    if event.event_type in {"file.creat", "file.rename", "file.write"}:
        return True
    flags = event.extensions.get("file.flags")
    if not isinstance(flags, str):
        return False
    upper = flags.upper()
    return any(token in upper for token in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"))


def _web_shell_exec(event: SecurityEvent) -> bool:
    if event.event_type != "process.exec" or event.process is None:
        return False
    child = _basename(event.process.path)
    parent = _basename(event.extensions.get("process.parent_path")) or _basename(
        event.extensions.get("process.parent_name")
    )
    return parent in _WEB_PARENT_NAMES and child in _SHELL_OR_INTERPRETER_NAMES


@register(DetectionCategory.HOST_WEB_PROCESS_SHELL.value)
class WebProcessShellRule(Rule):
    """Detect a web-serving parent directly spawning a shell/interpreter."""

    rule_id = DetectionCategory.HOST_WEB_PROCESS_SHELL.value
    version = "0.1.0"
    applicable_event_types = ("process.exec",)

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        detections: list[Detection] = []
        for event in events:
            if event.process is None or event.boot_id is None or not _successful(event):
                continue
            child = _basename(event.process.path)
            parent_path = event.extensions.get("process.parent_path")
            parent_name = _basename(parent_path) or _basename(
                event.extensions.get("process.parent_name")
            )
            if parent_name not in _WEB_PARENT_NAMES or child not in _SHELL_OR_INTERPRETER_NAMES:
                continue
            pid = event.actor.pid if event.actor is not None else None
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    category=self.rule_id,
                    severity=IncidentSeverity.HIGH.value,
                    confidence=0.9,
                    attack_state=AttackState.SUSPECTED_SUCCESS.value,
                    tenant_id=context.tenant_id,
                    host_id=context.host_id,
                    entity_key=(
                        f"process:{event.boot_id}:{pid}"
                        if pid is not None
                        else f"event:{event.event_id}"
                    ),
                    event_time_window_start=event.event_time,
                    event_time_window_end=event.event_time,
                    summary=f"web process {parent_name} spawned {child}",
                    evidence_event_ids=[event.event_id],
                    aggregate_metrics={
                        "parent_process": parent_name,
                        "parent_path": parent_path,
                        "child_process": child,
                        "child_path": event.process.path,
                        "command_line": (event.process.command_line or "")[:512],
                        "attack_technique_id": "T1059",
                    },
                    next_steps=(
                        "correlate the parent PID and timestamp with the triggering web request, "
                        "child file writes, and outbound connections; require direct persistence, "
                        "C2, or malicious-file evidence before confirmed_compromise"
                    ),
                )
            )
        return detections


@register(DetectionCategory.HOST_DOWNLOAD_EXECUTE.value)
class DownloadExecuteRule(Rule):
    """Correlate downloader exec -> write -> chmod -> execution by boot and path."""

    rule_id = DetectionCategory.HOST_DOWNLOAD_EXECUTE.value
    version = "0.1.0"
    applicable_event_types = (
        "process.exec",
        "file.creat",
        "file.open",
        "file.openat",
        "file.rename",
        "file.write",
        "file.chmod",
    )

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        window = timedelta(seconds=context.settings.detection_host_chain_window_seconds)
        active_downloaders: dict[tuple[str, int], SecurityEvent] = {}
        written: dict[tuple[str, str], tuple[SecurityEvent, SecurityEvent]] = {}
        executable: dict[tuple[str, str], tuple[SecurityEvent, SecurityEvent, SecurityEvent]] = {}
        emitted: set[tuple[str, str]] = set()
        detections: list[Detection] = []

        for event in _ordered_unique(events):
            key = _process_key(event)
            if event.event_type == "process.exec" and key is not None:
                # Any exec is a new process generation for this boot/PID.  Reset
                # stale state first so PID reuse cannot inherit downloader status.
                active_downloaders.pop(key, None)
                process_name = _basename(event.process.path) if event.process is not None else None
                if process_name in _DOWNLOADERS and _successful(event):
                    active_downloaders[key] = event

                target = _normalized_process_path(event)
                if target is None:
                    continue
                path_key = (event.boot_id or "", target)
                staged = executable.get(path_key)
                if staged is None or path_key in emitted or not _successful(event):
                    continue
                download, write, chmod = staged
                if event.event_time - download.event_time > window:
                    continue
                emitted.add(path_key)
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        category=self.rule_id,
                        severity=IncidentSeverity.HIGH.value,
                        confidence=0.92,
                        attack_state=AttackState.SUSPECTED_SUCCESS.value,
                        tenant_id=context.tenant_id,
                        host_id=context.host_id,
                        entity_key=_file_entity(event.boot_id or "", target),
                        event_time_window_start=download.event_time,
                        event_time_window_end=event.event_time,
                        summary=(
                            "downloaded file was written, made executable, and run: "
                            f"{_display_path(target)}"
                        ),
                        evidence_event_ids=[
                            download.event_id,
                            write.event_id,
                            chmod.event_id,
                            event.event_id,
                        ],
                        aggregate_metrics={
                            "boot_id": event.boot_id,
                            "download_process": download.process.path if download.process else None,
                            "download_pid": download.actor.pid if download.actor else None,
                            "file_path": target,
                            "attack_technique_ids": ["T1105", "T1222.002", "T1204.002"],
                        },
                        next_steps=(
                            "validate the downloaded bytes/hash, destination, execution result, "
                            "and any child persistence or outbound activity before declaring "
                            "compromise"
                        ),
                    )
                )
                continue

            if key is None:
                continue
            path = _normalized_path(event)
            if path is None:
                continue
            path_key = (event.boot_id or "", path)
            if _write_event(event):
                active_download = active_downloaders.get(key)
                if (
                    active_download is not None
                    and event.event_time - active_download.event_time <= window
                ):
                    written[path_key] = (active_download, event)
            elif event.event_type == "file.chmod" and _successful(event):
                written_stage = written.get(path_key)
                if (
                    written_stage is not None
                    and event.event_time - written_stage[0].event_time <= window
                ):
                    executable[path_key] = (written_stage[0], written_stage[1], event)
        return detections


@register(DetectionCategory.HOST_PERSISTENCE_CHANGE.value)
class PersistenceChangeRule(Rule):
    """Detect successful suspicious writes to cron, systemd, or authorized_keys."""

    rule_id = DetectionCategory.HOST_PERSISTENCE_CHANGE.value
    version = "0.1.0"
    applicable_event_types = tuple(sorted(_WRITE_EVENT_TYPES | {"file.chmod"}))

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        detections: list[Detection] = []
        for event in _ordered_unique(events):
            if event.boot_id is None or event.actor is None or event.actor.pid is None:
                continue
            successful_chmod = event.event_type == "file.chmod" and _successful(event)
            if not (_write_event(event) or successful_chmod):
                continue
            path = _normalized_path(event)
            writer = _basename(event.process.path) if event.process is not None else None
            mechanism = _persistence_mechanism(path)
            if mechanism is None or writer not in _SUSPICIOUS_PERSISTENCE_WRITERS:
                continue
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    category=self.rule_id,
                    severity=IncidentSeverity.HIGH.value,
                    confidence=0.86,
                    attack_state=AttackState.SUSPECTED_SUCCESS.value,
                    tenant_id=context.tenant_id,
                    host_id=context.host_id,
                    entity_key=_file_entity(event.boot_id, path or ""),
                    event_time_window_start=event.event_time,
                    event_time_window_end=event.event_time,
                    summary=(
                        f"{writer} modified {mechanism} persistence target "
                        f"{_display_path(path or '')}"
                    ),
                    evidence_event_ids=[event.event_id],
                    aggregate_metrics={
                        "boot_id": event.boot_id,
                        "pid": event.actor.pid,
                        "writer": writer,
                        "file_path": path,
                        "mechanism": mechanism,
                        "attack_technique_id": {
                            "cron": "T1053.003",
                            "systemd": "T1543.002",
                            "authorized_keys": "T1098.004",
                        }[mechanism],
                    },
                    next_steps=(
                        "retrieve the file before/after content and deployment context; a trusted "
                        "configuration change must remain suspected rather than confirmed "
                        "compromise"
                    ),
                )
            )
        return detections


@register(DetectionCategory.HOST_WEB_SHELL_OUTBOUND.value)
class WebShellOutboundRule(Rule):
    """Correlate a web-spawned shell with its successful external connection."""

    rule_id = DetectionCategory.HOST_WEB_SHELL_OUTBOUND.value
    version = "0.1.0"
    applicable_event_types = ("process.exec", "network.connect")

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        window = timedelta(seconds=context.settings.detection_host_chain_window_seconds)
        shells: dict[tuple[str, int], SecurityEvent] = {}
        detections: list[Detection] = []
        for event in _ordered_unique(events):
            key = _process_key(event)
            if key is None:
                continue
            if event.event_type == "process.exec":
                shells.pop(key, None)
                if _web_shell_exec(event) and _successful(event):
                    shells[key] = event
                continue
            shell = shells.get(key)
            if shell is None or event.event_time - shell.event_time > window:
                continue
            destination = _global_destination(event)
            if destination is None or not _successful(event):
                continue
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    category=self.rule_id,
                    severity=IncidentSeverity.HIGH.value,
                    confidence=0.95,
                    attack_state=AttackState.SUSPECTED_SUCCESS.value,
                    tenant_id=context.tenant_id,
                    host_id=context.host_id,
                    entity_key=f"process:{key[0]}:{key[1]}",
                    event_time_window_start=shell.event_time,
                    event_time_window_end=event.event_time,
                    summary=f"web-spawned shell connected to {destination}",
                    evidence_event_ids=[shell.event_id, event.event_id],
                    aggregate_metrics={
                        "boot_id": key[0],
                        "pid": key[1],
                        "destination": destination,
                        "destination_port": event.network.dst_port if event.network else None,
                        "attack_technique_ids": ["T1059", "T1071"],
                    },
                    next_steps=(
                        "correlate the triggering HTTP request and inspect transferred bytes, "
                        "child processes, and persistence before confirmed_compromise"
                    ),
                )
            )
            shells.pop(key, None)
        return detections


@register(DetectionCategory.HOST_LATERAL_SCAN.value)
class LateralScanRule(Rule):
    """Detect one process generation connecting to many private hosts."""

    rule_id = DetectionCategory.HOST_LATERAL_SCAN.value
    version = "0.1.0"
    applicable_event_types = ("process.exec", "network.connect")

    def evaluate(self, events: Sequence[SecurityEvent], context: RuleContext) -> list[Detection]:
        threshold = context.settings.detection_lateral_scan_unique_hosts
        window = timedelta(seconds=context.window_seconds)
        generations: dict[tuple[str, int], SecurityEvent] = {}
        connects: dict[tuple[str, int, str], list[SecurityEvent]] = defaultdict(list)
        detections: list[Detection] = []
        emitted: set[tuple[str, int, str]] = set()

        for event in _ordered_unique(events):
            key = _process_key(event)
            if key is None:
                continue
            if event.event_type == "process.exec":
                generations.pop(key, None)
                if _successful(event):
                    generations[key] = event
                continue
            generation = generations.get(key)
            destination = _private_destination(event)
            if generation is None or destination is None or not _successful(event):
                continue
            generation_key = (*key, generation.event_id)
            members = connects[generation_key]
            members.append(event)
            cutoff = event.event_time - window
            while members and members[0].event_time < cutoff:
                members.pop(0)
            destinations = {
                str(member.network.dst_ip)
                for member in members
                if member.network is not None and member.network.dst_ip is not None
            }
            if len(destinations) < threshold or generation_key in emitted:
                continue
            emitted.add(generation_key)
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    category=self.rule_id,
                    severity=IncidentSeverity.HIGH.value,
                    confidence=0.88,
                    attack_state=AttackState.ATTACK_ATTEMPT.value,
                    tenant_id=context.tenant_id,
                    host_id=context.host_id,
                    entity_key=_process_generation_entity(key[0], key[1], generation.event_id),
                    event_time_window_start=members[0].event_time,
                    event_time_window_end=event.event_time,
                    summary=(
                        "process "
                        f"{_basename(generation.process.path) if generation.process else key[1]} "
                        f"connected to {len(destinations)} private hosts"
                    ),
                    evidence_event_ids=[generation.event_id]
                    + [member.event_id for member in members[:50]],
                    aggregate_metrics={
                        "boot_id": key[0],
                        "pid": key[1],
                        "process": generation.process.path if generation.process else None,
                        "unique_private_hosts": len(destinations),
                        "sample_destinations": sorted(destinations)[:20],
                        "window_seconds": context.window_seconds,
                        "attack_technique_id": "T1046",
                    },
                    next_steps=(
                        "confirm whether the process is an approved inventory/monitoring tool and "
                        "correlate authentication or remote execution outcomes"
                    ),
                )
            )
        return detections


def _normalized_process_path(event: SecurityEvent) -> str | None:
    if event.process is None or not event.process.path or not event.process.path.startswith("/"):
        return None
    return posixpath.normpath(event.process.path)


def _persistence_mechanism(path: str | None) -> str | None:
    if path is None:
        return None
    if path == "/etc/crontab" or path.startswith(("/etc/cron.", "/var/spool/cron/")):
        return "cron"
    if path.startswith("/etc/systemd/system/") and (
        path.endswith(".service") or ".service.d/" in path
    ):
        return "systemd"
    if path.endswith("/.ssh/authorized_keys"):
        return "authorized_keys"
    return None


def _global_destination(event: SecurityEvent) -> str | None:
    if event.network is None or event.network.dst_ip is None:
        return None
    address = ipaddress.ip_address(str(event.network.dst_ip))
    return str(address) if address.is_global else None


def _private_destination(event: SecurityEvent) -> str | None:
    if event.network is None or event.network.dst_ip is None:
        return None
    address = ipaddress.ip_address(str(event.network.dst_ip))
    return str(address) if address.is_private and not address.is_loopback else None


__all__ = [
    "DownloadExecuteRule",
    "LateralScanRule",
    "PersistenceChangeRule",
    "WebProcessShellRule",
    "WebShellOutboundRule",
]
