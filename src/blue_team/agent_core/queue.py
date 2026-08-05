"""Transactional SQLite Agent queue with priority-aware, auditable backpressure."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import sqlite3
import zlib
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from blue_team.agent_core.contracts import (
    AgentEnvelope,
    BatchAck,
    EventBatch,
    EventPriority,
    PriorityCounts,
    QueueTelemetry,
    build_event_batch,
    canonical_envelope_bytes,
)
from blue_team.domain.identifiers import (
    AGENT_ID_PATTERN,
    HOST_ID_PATTERN,
    TENANT_ID_PATTERN,
)

_SCHEMA_VERSION = 1
_IDENTIFIERS = {
    "tenant_id": re.compile(TENANT_ID_PATTERN),
    "agent_id": re.compile(AGENT_ID_PATTERN),
    "host_id": re.compile(HOST_ID_PATTERN),
}
_BATCH_ID = re.compile(r"^batch_[a-f0-9]{32}$")
_ACTIVE = "active"
_CORRUPT = "corrupt"


class QueueError(RuntimeError):
    """Base class for recoverable Agent queue failures."""


class QueueConfigurationError(QueueError):
    pass


class QueueIdentityMismatch(QueueError):
    pass


class QueueProtectionRequired(QueueError):
    """Protected P0/P1 data could not be accepted without active loss."""


class QueueSequenceConflict(QueueError):
    pass


class QueueIntegrityError(QueueError):
    pass


class QueueEventTooLarge(QueueError):
    pass


class QueueStorageError(QueueError):
    pass


class QueueDisposition(StrEnum):
    STORED = "stored"
    DUPLICATE = "duplicate"
    DROPPED = "dropped"


@dataclass(frozen=True, slots=True)
class QueueConfig:
    database_path: Path
    tenant_id: str
    agent_id: str
    host_id: str
    max_payload_bytes: int = 256 * 1024 * 1024
    critical_reserve_bytes: int = 64 * 1024 * 1024
    max_event_bytes: int = 4 * 1024 * 1024
    min_free_bytes: int = 256 * 1024 * 1024
    compression_level: int = 6
    lease_seconds: int = 30
    reduction_rule_version: str = "queue-capacity-v0.1.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "database_path", self.database_path.expanduser().resolve())
        for name in ("tenant_id", "agent_id", "host_id"):
            if _IDENTIFIERS[name].fullmatch(getattr(self, name)) is None:
                raise QueueConfigurationError(f"invalid {name}")
        if self.max_payload_bytes <= 0 or self.max_event_bytes <= 0:
            raise QueueConfigurationError("queue and event byte limits must be positive")
        if self.critical_reserve_bytes < 0 or self.min_free_bytes < 0:
            raise QueueConfigurationError("reserve limits cannot be negative")
        if not 0 <= self.compression_level <= 9:
            raise QueueConfigurationError("compression_level must be between 0 and 9")
        if not 1 <= self.lease_seconds <= 86_400:
            raise QueueConfigurationError("lease_seconds must be between 1 and 86400")
        if not self.reduction_rule_version or len(self.reduction_rule_version) > 128:
            raise QueueConfigurationError("reduction_rule_version is invalid")

    @property
    def hard_payload_bytes(self) -> int:
        return self.max_payload_bytes + self.critical_reserve_bytes


@dataclass(frozen=True, slots=True)
class QueueWriteResult:
    disposition: QueueDisposition
    sequence: int
    stored_size: int
    evicted_count: int = 0


@dataclass(frozen=True, slots=True)
class QueueAuditRecord:
    occurred_at: datetime
    action: str
    reason: str
    priority: EventPriority | None
    input_count: int
    output_count: int
    byte_count: int
    rule_version: str
    window_start: datetime | None
    window_end: datetime | None
    source: str | None
    details: dict[str, object]


@dataclass(frozen=True, slots=True)
class _EncodedEnvelope:
    canonical: bytes
    compressed: bytes
    digest: str

    @property
    def stored_size(self) -> int:
        return len(self.compressed)


class LocalDiskQueue:
    """A single-Agent append queue whose unacknowledged batches survive restarts."""

    def __init__(
        self,
        config: QueueConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        free_space: Callable[[Path], int] | None = None,
    ) -> None:
        self.config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._free_space = free_space or (lambda path: shutil.disk_usage(path).free)

    def initialize(self) -> None:
        parent = self.config.database_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            parent.chmod(0o700)
        try:
            connection = sqlite3.connect(self.config.database_path, timeout=5)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version == 0:
                    self._create_schema(connection)
                elif version != _SCHEMA_VERSION:
                    raise QueueConfigurationError(
                        f"unsupported queue schema version {version}; expected {_SCHEMA_VERSION}"
                    )
                self._bind_identity(connection)
                connection.commit()
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise QueueStorageError("queue database initialization failed") from error
        with suppress(OSError):
            self.config.database_path.chmod(0o600)

    def estimate_stored_size(self, envelope: AgentEnvelope) -> int:
        self._require_identity(envelope)
        return self._encode(envelope).stored_size

    def enqueue(self, envelope: AgentEnvelope) -> QueueWriteResult:
        self._require_identity(envelope)
        encoded = self._encode(envelope)
        try:
            with self._transaction(write=True) as connection:
                outcome = self._enqueue(connection, envelope, encoded)
        except sqlite3.Error as error:
            message = "queue storage failed before the event could be durably audited"
            if envelope.priority in {EventPriority.P0, EventPriority.P1}:
                raise QueueProtectionRequired(message) from error
            raise QueueStorageError(message) from error
        if isinstance(outcome, QueueError):
            raise outcome
        return outcome

    def reserve_batch(
        self,
        *,
        max_items: int = 250,
        max_uncompressed_bytes: int = 4 * 1024 * 1024,
    ) -> EventBatch | None:
        if max_items <= 0 or max_items > 1000:
            raise ValueError("max_items must be between 1 and 1000")
        if max_uncompressed_bytes <= 0:
            raise ValueError("max_uncompressed_bytes must be positive")
        with self._transaction(write=True) as connection:
            outcome = self._reserve_batch(
                connection,
                max_items=max_items,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
        if isinstance(outcome, QueueError):
            raise outcome
        return outcome

    def release_batch(self, batch_id: str, *, reason: str) -> int:
        if _BATCH_ID.fullmatch(batch_id) is None:
            raise ValueError("invalid batch_id")
        if not reason or len(reason) > 512:
            raise ValueError("release reason must contain between 1 and 512 characters")
        now = self._now()
        with self._transaction(write=True) as connection:
            rows = connection.execute(
                "SELECT sequence FROM queue_items WHERE batch_id = ? AND state = ?",
                (batch_id, _ACTIVE),
            ).fetchall()
            if rows:
                connection.execute(
                    "UPDATE queue_items SET lease_until = ? WHERE batch_id = ? AND state = ?",
                    (_timestamp(now), batch_id, _ACTIVE),
                )
                self._audit(
                    connection,
                    action="retry_scheduled",
                    reason=reason,
                    input_count=len(rows),
                    output_count=len(rows),
                    details={"batch_id": batch_id},
                )
            return len(rows)

    def acknowledge(self, acknowledgement: BatchAck) -> int:
        now = self._now()
        with self._transaction(write=True) as connection:
            rows = connection.execute(
                """
                SELECT sequence FROM queue_items
                WHERE batch_id = ? AND state = ? ORDER BY sequence
                """,
                (acknowledgement.batch_id, _ACTIVE),
            ).fetchall()
            if not rows:
                return 0
            final_sequence = int(rows[-1]["sequence"])
            if acknowledgement.errors or acknowledgement.accepted_sequence != final_sequence:
                connection.execute(
                    "UPDATE queue_items SET lease_until = ? WHERE batch_id = ? AND state = ?",
                    (_timestamp(now), acknowledgement.batch_id, _ACTIVE),
                )
                self._audit(
                    connection,
                    action="partial_ack",
                    reason="receiver did not accept the complete immutable batch",
                    input_count=len(rows),
                    output_count=len(rows),
                    details={
                        "accepted_sequence": acknowledgement.accepted_sequence,
                        "batch_id": acknowledgement.batch_id,
                        "error_count": len(acknowledgement.errors),
                        "final_sequence": final_sequence,
                    },
                )
                return 0
            connection.execute(
                "DELETE FROM queue_items WHERE batch_id = ? AND state = ?",
                (acknowledgement.batch_id, _ACTIVE),
            )
            self._audit(
                connection,
                action="ack",
                reason="receiver accepted the complete batch",
                input_count=len(rows),
                output_count=0,
                details={"batch_id": acknowledgement.batch_id},
            )
            return len(rows)

    def telemetry(self) -> QueueTelemetry:
        with self._transaction(write=False) as connection:
            counts = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN state = 'active' AND batch_id IS NULL THEN 1 ELSE 0 END)
                        AS queued_count,
                    SUM(CASE WHEN state = 'active' AND batch_id IS NOT NULL THEN 1 ELSE 0 END)
                        AS inflight_count,
                    SUM(CASE WHEN state = 'corrupt' THEN 1 ELSE 0 END) AS corrupt_count,
                    COALESCE(SUM(stored_size), 0) AS stored_bytes
                FROM queue_items
                """
            ).fetchone()
            dropped_rows = connection.execute(
                """
                SELECT priority, COALESCE(SUM(input_count - output_count), 0) AS count
                FROM queue_audit
                WHERE action IN ('drop', 'evict') AND priority IS NOT NULL
                GROUP BY priority
                """
            ).fetchall()
            dropped = {row["priority"]: int(row["count"]) for row in dropped_rows}
            protection = self._get_metadata(connection, "protection_mode") == "1"
        return QueueTelemetry(
            queued_count=int(counts["queued_count"] or 0),
            inflight_count=int(counts["inflight_count"] or 0),
            corrupt_count=int(counts["corrupt_count"] or 0),
            stored_bytes=int(counts["stored_bytes"]),
            dropped=PriorityCounts(
                p0=dropped.get(EventPriority.P0.value, 0),
                p1=dropped.get(EventPriority.P1.value, 0),
                p2=dropped.get(EventPriority.P2.value, 0),
                p3=dropped.get(EventPriority.P3.value, 0),
            ),
            protection_mode=protection,
        )

    def audit_records(self, *, limit: int = 100) -> tuple[QueueAuditRecord, ...]:
        if not 1 <= limit <= 10_000:
            raise ValueError("audit limit must be between 1 and 10000")
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT * FROM queue_audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._audit_record(row) for row in rows)

    def _enqueue(
        self,
        connection: sqlite3.Connection,
        envelope: AgentEnvelope,
        encoded: _EncodedEnvelope,
    ) -> QueueWriteResult | QueueError:
        existing = connection.execute(
            """
            SELECT payload_sha256 FROM queue_items
            WHERE agent_id = ? AND boot_id = ? AND sequence = ?
            """,
            (envelope.agent_id, envelope.boot_id, envelope.sequence),
        ).fetchone()
        if existing is not None:
            if secrets_compare(existing["payload_sha256"], encoded.digest):
                self._audit_for_envelope(
                    connection,
                    envelope,
                    action="duplicate",
                    reason="identical source sequence was already buffered",
                    input_count=1,
                    output_count=1,
                    byte_count=encoded.stored_size,
                )
                return QueueWriteResult(
                    disposition=QueueDisposition.DUPLICATE,
                    sequence=envelope.sequence,
                    stored_size=encoded.stored_size,
                )
            self._audit_for_envelope(
                connection,
                envelope,
                action="sequence_conflict",
                reason="source sequence already exists with different canonical content",
                input_count=1,
                output_count=1,
                byte_count=encoded.stored_size,
            )
            return QueueSequenceConflict(
                f"sequence {envelope.sequence} for boot {envelope.boot_id} conflicts"
            )

        free_bytes = self._free_space(self.config.database_path.parent)
        if free_bytes - encoded.stored_size < self.config.min_free_bytes:
            return self._capacity_failure(
                connection,
                envelope,
                encoded,
                reason="minimum filesystem free-space headroom would be crossed",
            )

        total = int(
            connection.execute("SELECT COALESCE(SUM(stored_size), 0) FROM queue_items").fetchone()[
                0
            ]
        )
        protected = envelope.priority in {EventPriority.P0, EventPriority.P1}
        limit = self.config.hard_payload_bytes if protected else self.config.max_payload_bytes
        required = max(0, total + encoded.stored_size - limit)
        candidates: list[sqlite3.Row] = []
        if required:
            candidates = self._eviction_candidates(connection, envelope.priority, required)
            reclaimable = sum(int(row["stored_size"]) for row in candidates)
            if reclaimable < required:
                return self._capacity_failure(
                    connection,
                    envelope,
                    encoded,
                    reason="queue capacity cannot be reclaimed without higher-priority loss",
                )
            self._evict(connection, candidates)

        connection.execute(
            """
            INSERT INTO queue_items (
                tenant_id, agent_id, host_id, boot_id, sequence, priority,
                event_time, source, payload, payload_sha256, uncompressed_size,
                stored_size, state, batch_id, lease_until, attempts, queued_at,
                last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, NULL)
            """,
            (
                envelope.tenant_id,
                envelope.agent_id,
                envelope.host_id,
                envelope.boot_id,
                envelope.sequence,
                envelope.priority.value,
                _timestamp(envelope.event.event_time),
                envelope.event.source.collector,
                encoded.compressed,
                encoded.digest,
                len(encoded.canonical),
                encoded.stored_size,
                _ACTIVE,
                _timestamp(self._now()),
            ),
        )
        self._maybe_clear_protection(
            connection,
            stored_bytes=total + encoded.stored_size,
        )
        return QueueWriteResult(
            disposition=QueueDisposition.STORED,
            sequence=envelope.sequence,
            stored_size=encoded.stored_size,
            evicted_count=len(candidates),
        )

    def _capacity_failure(
        self,
        connection: sqlite3.Connection,
        envelope: AgentEnvelope,
        encoded: _EncodedEnvelope,
        *,
        reason: str,
    ) -> QueueWriteResult | QueueError:
        if envelope.priority in {EventPriority.P0, EventPriority.P1}:
            self._set_metadata(connection, "protection_mode", "1")
            self._audit_for_envelope(
                connection,
                envelope,
                action="protection",
                reason=reason,
                input_count=1,
                output_count=1,
                byte_count=encoded.stored_size,
            )
            return QueueProtectionRequired(reason)
        self._audit_for_envelope(
            connection,
            envelope,
            action="drop",
            reason=reason,
            input_count=1,
            output_count=0,
            byte_count=encoded.stored_size,
        )
        return QueueWriteResult(
            disposition=QueueDisposition.DROPPED,
            sequence=envelope.sequence,
            stored_size=encoded.stored_size,
        )

    def _eviction_candidates(
        self,
        connection: sqlite3.Connection,
        incoming: EventPriority,
        required: int,
    ) -> list[sqlite3.Row]:
        allowed: tuple[str, ...]
        if incoming is EventPriority.P0:
            allowed = (EventPriority.P1.value, EventPriority.P2.value, EventPriority.P3.value)
        elif incoming in {EventPriority.P1, EventPriority.P2}:
            allowed = (EventPriority.P2.value, EventPriority.P3.value)
        else:
            allowed = (EventPriority.P3.value,)
        placeholders = ",".join("?" for _ in allowed)
        rows = connection.execute(
            f"""
            SELECT id, priority, event_time, source, stored_size
            FROM queue_items
            WHERE state = ? AND batch_id IS NULL AND priority IN ({placeholders})
            ORDER BY priority DESC, queued_at ASC, sequence ASC
            """,
            (_ACTIVE, *allowed),
        ).fetchall()
        selected: list[sqlite3.Row] = []
        reclaimed = 0
        for row in rows:
            selected.append(row)
            reclaimed += int(row["stored_size"])
            if reclaimed >= required:
                break
        return selected

    def _evict(self, connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
        groups: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            groups[(str(row["priority"]), str(row["source"]))].append(row)
        identifiers = [int(row["id"]) for row in rows]
        placeholders = ",".join("?" for _ in identifiers)
        connection.execute(
            f"DELETE FROM queue_items WHERE id IN ({placeholders})",
            identifiers,
        )
        for (priority, source), group in groups.items():
            times = [_parse_timestamp(str(row["event_time"])) for row in group]
            self._audit(
                connection,
                action="evict",
                reason="priority-aware queue capacity reduction",
                priority=EventPriority(priority),
                input_count=len(group),
                output_count=0,
                byte_count=sum(int(row["stored_size"]) for row in group),
                window_start=min(times),
                window_end=max(times),
                source=source,
                details={"policy": "drop-oldest-lower-or-equal-priority"},
            )

    def _reserve_batch(
        self,
        connection: sqlite3.Connection,
        *,
        max_items: int,
        max_uncompressed_bytes: int,
    ) -> EventBatch | None | QueueError:
        now = self._now()
        existing = connection.execute(
            """
            SELECT batch_id, MAX(lease_until) AS lease_until, MIN(queued_at) AS queued_at
            FROM queue_items
            WHERE state = ? AND batch_id IS NOT NULL
            GROUP BY batch_id ORDER BY queued_at LIMIT 1
            """,
            (_ACTIVE,),
        ).fetchone()
        if existing is not None:
            lease_until = _parse_timestamp(str(existing["lease_until"]))
            if lease_until > now:
                return None
            batch_id = str(existing["batch_id"])
            loaded = self._load_batch(connection, batch_id=batch_id)
            if isinstance(loaded, QueueError):
                return loaded
            self._lease(connection, batch_id, now)
            return loaded

        first = connection.execute(
            """
            SELECT tenant_id, agent_id, host_id, boot_id
            FROM queue_items
            WHERE state = ? AND batch_id IS NULL
            ORDER BY priority ASC, queued_at ASC, sequence ASC LIMIT 1
            """,
            (_ACTIVE,),
        ).fetchone()
        if first is None:
            return None
        rows = connection.execute(
            """
            SELECT * FROM queue_items
            WHERE state = ? AND batch_id IS NULL
              AND tenant_id = ? AND agent_id = ? AND host_id = ? AND boot_id = ?
            ORDER BY priority ASC, sequence ASC
            """,
            (
                _ACTIVE,
                first["tenant_id"],
                first["agent_id"],
                first["host_id"],
                first["boot_id"],
            ),
        ).fetchall()
        envelopes: list[AgentEnvelope] = []
        identifiers: list[int] = []
        total_bytes = 0
        for row in rows:
            decoded = self._decode(row)
            if isinstance(decoded, QueueIntegrityError):
                self._mark_corrupt(connection, row, str(decoded))
                continue
            size = int(row["uncompressed_size"])
            if envelopes and (
                len(envelopes) >= max_items or total_bytes + size > max_uncompressed_bytes
            ):
                break
            envelopes.append(decoded)
            identifiers.append(int(row["id"]))
            total_bytes += size
        if not envelopes:
            return None
        batch = build_event_batch(tuple(envelopes))
        placeholders = ",".join("?" for _ in identifiers)
        lease_until = now + timedelta(seconds=self.config.lease_seconds)
        connection.execute(
            f"""
            UPDATE queue_items
            SET batch_id = ?, lease_until = ?, attempts = attempts + 1
            WHERE id IN ({placeholders})
            """,
            (batch.batch_id, _timestamp(lease_until), *identifiers),
        )
        return batch

    def _load_batch(
        self,
        connection: sqlite3.Connection,
        *,
        batch_id: str,
    ) -> EventBatch | QueueError:
        rows = connection.execute(
            "SELECT * FROM queue_items WHERE batch_id = ? AND state = ? ORDER BY sequence",
            (batch_id, _ACTIVE),
        ).fetchall()
        envelopes: list[AgentEnvelope] = []
        corrupt_rows: list[sqlite3.Row] = []
        for row in rows:
            decoded = self._decode(row)
            if isinstance(decoded, QueueIntegrityError):
                corrupt_rows.append(row)
                self._mark_corrupt(connection, row, str(decoded))
            else:
                envelopes.append(decoded)
        if corrupt_rows:
            connection.execute(
                """
                UPDATE queue_items SET batch_id = NULL, lease_until = NULL
                WHERE batch_id = ? AND state = ?
                """,
                (batch_id, _ACTIVE),
            )
            self._set_metadata(connection, "protection_mode", "1")
            self._audit(
                connection,
                action="batch_integrity_failure",
                reason="an immutable retry batch contains corrupted local data",
                input_count=len(rows),
                output_count=len(envelopes),
                details={"batch_id": batch_id, "corrupt_count": len(corrupt_rows)},
            )
            return QueueIntegrityError(f"batch {batch_id} failed local integrity validation")
        if not envelopes:
            return QueueIntegrityError(f"batch {batch_id} has no recoverable events")
        return build_event_batch(tuple(envelopes), batch_id=batch_id)

    def _lease(self, connection: sqlite3.Connection, batch_id: str, now: datetime) -> None:
        connection.execute(
            """
            UPDATE queue_items
            SET lease_until = ?, attempts = attempts + 1
            WHERE batch_id = ? AND state = ?
            """,
            (
                _timestamp(now + timedelta(seconds=self.config.lease_seconds)),
                batch_id,
                _ACTIVE,
            ),
        )

    def _decode(self, row: sqlite3.Row) -> AgentEnvelope | QueueIntegrityError:
        payload = bytes(row["payload"])
        if len(payload) != int(row["stored_size"]):
            return QueueIntegrityError("compressed payload length differs from its index")
        try:
            decompressor = zlib.decompressobj()
            canonical = decompressor.decompress(
                payload,
                self.config.max_event_bytes + 1,
            )
        except zlib.error as error:
            return QueueIntegrityError(f"compressed payload is invalid: {error}")
        if (
            not decompressor.eof
            or decompressor.unconsumed_tail
            or decompressor.unused_data
            or len(canonical) > self.config.max_event_bytes
            or len(canonical) != int(row["uncompressed_size"])
        ):
            return QueueIntegrityError("decompressed payload length is invalid")
        digest = hashlib.sha256(canonical).hexdigest()
        if not secrets_compare(digest, str(row["payload_sha256"])):
            return QueueIntegrityError("payload SHA-256 mismatch")
        try:
            envelope = AgentEnvelope.model_validate_json(canonical)
        except ValidationError as error:
            return QueueIntegrityError(f"stored envelope validation failed: {error.title}")
        row_identity = (
            row["tenant_id"],
            row["agent_id"],
            row["host_id"],
            row["boot_id"],
            int(row["sequence"]),
            row["priority"],
        )
        envelope_identity = (
            envelope.tenant_id,
            envelope.agent_id,
            envelope.host_id,
            envelope.boot_id,
            envelope.sequence,
            envelope.priority.value,
        )
        if row_identity != envelope_identity:
            return QueueIntegrityError("indexed queue identity differs from the signed payload")
        return envelope

    def _mark_corrupt(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        reason: str,
    ) -> None:
        connection.execute(
            """
            UPDATE queue_items
            SET state = ?, batch_id = NULL, lease_until = NULL, last_error = ?
            WHERE id = ?
            """,
            (_CORRUPT, reason[:1024], row["id"]),
        )
        priority = EventPriority(str(row["priority"]))
        if priority in {EventPriority.P0, EventPriority.P1}:
            self._set_metadata(connection, "protection_mode", "1")
        self._audit(
            connection,
            action="integrity_failure",
            reason=reason[:512],
            priority=priority,
            input_count=1,
            output_count=0,
            byte_count=int(row["stored_size"]),
            window_start=_parse_timestamp(str(row["event_time"])),
            window_end=_parse_timestamp(str(row["event_time"])),
            source=str(row["source"]),
            details={"sequence": int(row["sequence"])},
        )

    def _audit_for_envelope(
        self,
        connection: sqlite3.Connection,
        envelope: AgentEnvelope,
        *,
        action: str,
        reason: str,
        input_count: int,
        output_count: int,
        byte_count: int,
    ) -> None:
        self._audit(
            connection,
            action=action,
            reason=reason,
            priority=envelope.priority,
            input_count=input_count,
            output_count=output_count,
            byte_count=byte_count,
            window_start=envelope.event.event_time,
            window_end=envelope.event.event_time,
            source=envelope.event.source.collector,
            details={"boot_id": envelope.boot_id, "sequence": envelope.sequence},
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        reason: str,
        input_count: int,
        output_count: int,
        priority: EventPriority | None = None,
        byte_count: int = 0,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        source: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO queue_audit (
                occurred_at, action, reason, priority, input_count, output_count,
                byte_count, rule_version, window_start, window_end, source, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _timestamp(self._now()),
                action,
                reason,
                priority.value if priority is not None else None,
                input_count,
                output_count,
                byte_count,
                self.config.reduction_rule_version,
                _timestamp(window_start) if window_start is not None else None,
                _timestamp(window_end) if window_end is not None else None,
                source,
                json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
            ),
        )

    def _encode(self, envelope: AgentEnvelope) -> _EncodedEnvelope:
        canonical = canonical_envelope_bytes(envelope)
        if len(canonical) > self.config.max_event_bytes:
            raise QueueEventTooLarge(
                f"event requires {len(canonical)} bytes; limit is {self.config.max_event_bytes}"
            )
        return _EncodedEnvelope(
            canonical=canonical,
            compressed=zlib.compress(canonical, level=self.config.compression_level),
            digest=hashlib.sha256(canonical).hexdigest(),
        )

    def _require_identity(self, envelope: AgentEnvelope) -> None:
        expected = (self.config.tenant_id, self.config.agent_id, self.config.host_id)
        actual = (envelope.tenant_id, envelope.agent_id, envelope.host_id)
        if actual != expected:
            raise QueueIdentityMismatch(
                "envelope identity differs from the configured Agent identity"
            )

    def _bind_identity(self, connection: sqlite3.Connection) -> None:
        expected = {
            "tenant_id": self.config.tenant_id,
            "agent_id": self.config.agent_id,
            "host_id": self.config.host_id,
        }
        for key, value in expected.items():
            existing = self._get_metadata(connection, key)
            if existing is None:
                self._set_metadata(connection, key, value)
            elif existing != value:
                raise QueueIdentityMismatch(f"queue {key} is bound to {existing!r}, not {value!r}")
        if self._get_metadata(connection, "protection_mode") is None:
            self._set_metadata(connection, "protection_mode", "0")

    def _maybe_clear_protection(
        self,
        connection: sqlite3.Connection,
        *,
        stored_bytes: int,
    ) -> None:
        if stored_bytes > self.config.max_payload_bytes:
            return
        protected_corruption = connection.execute(
            """
            SELECT 1 FROM queue_items
            WHERE state = ? AND priority IN (?, ?)
            LIMIT 1
            """,
            (_CORRUPT, EventPriority.P0.value, EventPriority.P1.value),
        ).fetchone()
        if protected_corruption is None:
            self._set_metadata(connection, "protection_mode", "0")

    @staticmethod
    def _get_metadata(connection: sqlite3.Connection, key: str) -> str | None:
        row = connection.execute(
            "SELECT value FROM queue_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return str(row["value"]) if row is not None else None

    @staticmethod
    def _set_metadata(connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            """
            INSERT INTO queue_metadata (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise QueueConfigurationError("queue clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        if not self.config.database_path.is_file():
            raise QueueConfigurationError("queue is not initialized")
        connection = sqlite3.connect(
            self.config.database_path,
            timeout=5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE queue_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE queue_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence >= 0),
                priority TEXT NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3')),
                event_time TEXT NOT NULL,
                source TEXT NOT NULL,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                uncompressed_size INTEGER NOT NULL CHECK (uncompressed_size > 0),
                stored_size INTEGER NOT NULL CHECK (stored_size > 0),
                state TEXT NOT NULL CHECK (state IN ('active', 'corrupt')),
                batch_id TEXT,
                lease_until TEXT,
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                queued_at TEXT NOT NULL,
                last_error TEXT,
                UNIQUE (agent_id, boot_id, sequence)
            );

            CREATE INDEX ix_queue_items_reserve
                ON queue_items (state, batch_id, priority, queued_at, sequence);
            CREATE INDEX ix_queue_items_batch ON queue_items (batch_id);

            CREATE TABLE queue_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                priority TEXT CHECK (priority IS NULL OR priority IN ('P0', 'P1', 'P2', 'P3')),
                input_count INTEGER NOT NULL CHECK (input_count >= 0),
                output_count INTEGER NOT NULL CHECK (output_count >= 0),
                byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
                rule_version TEXT NOT NULL,
                window_start TEXT,
                window_end TEXT,
                source TEXT,
                details TEXT NOT NULL
            );

            PRAGMA user_version = 1;
            """
        )

    @staticmethod
    def _audit_record(row: sqlite3.Row) -> QueueAuditRecord:
        details: Any = json.loads(str(row["details"]))
        if not isinstance(details, dict):
            details = {"invalid_details": True}
        return QueueAuditRecord(
            occurred_at=_parse_timestamp(str(row["occurred_at"])),
            action=str(row["action"]),
            reason=str(row["reason"]),
            priority=(EventPriority(str(row["priority"])) if row["priority"] is not None else None),
            input_count=int(row["input_count"]),
            output_count=int(row["output_count"]),
            byte_count=int(row["byte_count"]),
            rule_version=str(row["rule_version"]),
            window_start=(
                _parse_timestamp(str(row["window_start"]))
                if row["window_start"] is not None
                else None
            ),
            window_end=(
                _parse_timestamp(str(row["window_end"])) if row["window_end"] is not None else None
            ),
            source=str(row["source"]) if row["source"] is not None else None,
            details={str(key): value for key, value in details.items()},
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QueueIntegrityError("queue timestamp is missing a timezone")
    return parsed.astimezone(UTC)


def secrets_compare(left: object, right: object) -> bool:
    return secrets.compare_digest(str(left), str(right))
