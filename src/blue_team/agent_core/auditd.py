"""Agent-side contract for one completely aggregated Linux audit event.

Linux audit emits one logical operation as several records (for example
``SYSCALL``, ``EXECVE``, ``CWD`` and one or more ``PATH`` records) carrying the
same audit serial.  The collector must group those records before enqueueing
them; otherwise downstream rules can mistake a partial syscall for a complete
process or file operation.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from blue_team.agent_core.contracts import AgentContract, BootId

_AUDIT_HEADER = re.compile(
    r"^(?:node=\S+\s+)?type=(?P<record_type>[A-Z][A-Z0-9_]*)\s+"
    r"msg=audit\([0-9]+(?:\.[0-9]+)?:(?P<serial>[0-9]+)\):(?:\s|$)"
)
_MAX_GROUP_BYTES = 2 * 1024 * 1024


class AuditdRecord(AgentContract):
    """One native audit text record retained verbatim as evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    record_type: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
    message: Annotated[str, Field(min_length=1)]

    @field_validator("message")
    @classmethod
    def require_bounded_utf8_record(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 65_536:
            raise ValueError("audit record exceeds its byte limit")
        return value


class AuditdSerialGroup(AgentContract):
    """Versioned hand-off from the Agent audit collector to normalization."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    boot_id: BootId
    serial: Annotated[int, Field(ge=0)]
    complete: bool
    last_record_at: datetime | None = None
    records: Annotated[tuple[AuditdRecord, ...], Field(min_length=1, max_length=256)]

    @field_validator("last_record_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("last_record_at must include a timezone offset")
        return value

    @model_validator(mode="after")
    def require_terminal_eoe_when_complete(self) -> Self:
        record_types = [record.record_type for record in self.records]
        if self.complete and (not record_types or record_types[-1] != "EOE"):
            raise ValueError("a complete audit serial group must end with EOE")
        if "EOE" in record_types[:-1]:
            raise ValueError("EOE may only be the final record in an audit serial group")
        total_bytes = sum(len(record.message.encode("utf-8")) for record in self.records)
        if total_bytes > _MAX_GROUP_BYTES:
            raise ValueError("audit serial group exceeds its byte limit")
        return self


@dataclass(slots=True)
class _OpenGroup:
    records: list[AuditdRecord]
    last_record_at: datetime


class AuditdSerialAggregator:
    """Bounded, interleaving-safe grouping of native audit lines by serial.

    ``ingest`` may return an incomplete group when the open-serial or per-group
    bound is reached.  The caller must enqueue those groups too: normalization
    sends them to the DLQ instead of silently losing the evidence.
    """

    def __init__(
        self,
        *,
        boot_id: str,
        max_open_serials: int = 1024,
        max_records: int = 256,
        max_pending_bytes: int = 8 * 1024 * 1024,
        clock: Callable[[], datetime] | None = None,
    ):
        if not boot_id:
            raise ValueError("boot_id is required")
        if max_open_serials < 1:
            raise ValueError("max_open_serials must be at least 1")
        if max_records < 2 or max_records > 256:
            raise ValueError("max_records must be between 2 and 256")
        if not 65_536 <= max_pending_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_pending_bytes must be between 64 KiB and 64 MiB")
        self._boot_id = boot_id
        self._max_open_serials = max_open_serials
        self._max_records = max_records
        self._max_pending_bytes = max_pending_bytes
        self._clock = clock or (lambda: datetime.now(UTC))
        self._groups: OrderedDict[int, _OpenGroup] = OrderedDict()

    @property
    def pending_count(self) -> int:
        return len(self._groups)

    def ingest(
        self, message: str, *, observed_at: datetime | None = None
    ) -> tuple[AuditdSerialGroup, ...]:
        """Add one line and return any completed or bounded-eviction groups."""
        match = _AUDIT_HEADER.match(message)
        if match is None:
            raise ValueError("invalid audit record header")
        serial = int(match.group("serial"))
        record = AuditdRecord(record_type=match.group("record_type"), message=message)
        emitted: list[AuditdSerialGroup] = []
        seen_at = self._aware(observed_at or self._clock())

        group = self._groups.get(serial)
        if group is None:
            if len(self._groups) >= self._max_open_serials:
                evicted_serial, evicted = self._groups.popitem(last=False)
                emitted.append(self._group(evicted_serial, evicted, complete=False))
            group = _OpenGroup(records=[], last_record_at=seen_at)
            self._groups[serial] = group
        else:
            self._groups.move_to_end(serial)

        if len(group.records) >= self._max_records:
            emitted.append(self._group(serial, group, complete=False))
            group = _OpenGroup(records=[], last_record_at=seen_at)
            self._groups[serial] = group
        group.records.append(record)
        group.last_record_at = seen_at

        if record.record_type == "EOE":
            self._groups.pop(serial, None)
            emitted.append(self._group(serial, group, complete=True))
        else:
            while self._pending_bytes() > self._max_pending_bytes:
                evicted_serial, evicted = self._groups.popitem(last=False)
                emitted.append(self._group(evicted_serial, evicted, complete=False))
        return tuple(emitted)

    def flush_expired(
        self, *, max_age_seconds: float, now: datetime | None = None
    ) -> tuple[AuditdSerialGroup, ...]:
        """Flush serials that have not received a record within the bounded timeout."""
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        current = self._aware(now or self._clock())
        cutoff = current - timedelta(seconds=max_age_seconds)
        expired: list[AuditdSerialGroup] = []
        for serial, group in tuple(self._groups.items()):
            if group.last_record_at > cutoff:
                continue
            self._groups.pop(serial)
            expired.append(self._group(serial, group, complete=False))
        return tuple(expired)

    def pending_groups(self) -> tuple[AuditdSerialGroup, ...]:
        """Snapshot pending groups without consuming them for crash-safe cursor state."""
        return tuple(
            self._group(serial, group, complete=False) for serial, group in self._groups.items()
        )

    def restore(self, groups: Iterable[AuditdSerialGroup]) -> None:
        """Restore a previously persisted pending snapshot before collection starts."""
        if self._groups:
            raise ValueError("cannot restore into a non-empty audit aggregator")
        restored = tuple(groups)
        if len(restored) > self._max_open_serials:
            raise ValueError("pending audit snapshot exceeds max_open_serials")
        for group in restored:
            if group.boot_id != self._boot_id or group.complete or group.last_record_at is None:
                raise ValueError("invalid pending audit group snapshot")
            if len(group.records) > self._max_records:
                raise ValueError("pending audit group exceeds max_records")
            if group.serial in self._groups:
                raise ValueError("pending audit snapshot contains duplicate serials")
            self._groups[group.serial] = _OpenGroup(
                records=list(group.records),
                last_record_at=group.last_record_at,
            )
        if self._pending_bytes() > self._max_pending_bytes:
            self._groups.clear()
            raise ValueError("pending audit snapshot exceeds max_pending_bytes")

    def flush_incomplete(self) -> tuple[AuditdSerialGroup, ...]:
        """Flush every open serial, for collector shutdown or timeout handling."""
        groups = tuple(
            self._group(serial, group, complete=False) for serial, group in self._groups.items()
        )
        self._groups.clear()
        return groups

    def _group(self, serial: int, group: _OpenGroup, *, complete: bool) -> AuditdSerialGroup:
        return AuditdSerialGroup(
            boot_id=self._boot_id,
            serial=serial,
            complete=complete,
            last_record_at=group.last_record_at,
            records=tuple(group.records),
        )

    def _pending_bytes(self) -> int:
        return sum(
            len(record.message.encode("utf-8"))
            for group in self._groups.values()
            for record in group.records
        )

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("audit aggregator clock must be timezone-aware")
        return value.astimezone(UTC)


__all__ = ["AuditdRecord", "AuditdSerialAggregator", "AuditdSerialGroup"]
