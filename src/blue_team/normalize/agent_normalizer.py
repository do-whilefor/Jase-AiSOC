"""Agent SourceKind normalizer: pass-through of the verified SecurityEvent."""

from __future__ import annotations

from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    clock_offset_ms,
    dedupe_key,
    partition_key,
)
from blue_team.normalize.normalizer_registry import register


@register(SourceKind.AGENT)
class AgentNormalizer:
    """The Agent already emits canonical SecurityEvents; this is a pass-through."""

    kind = SourceKind.AGENT
    version = "0.1.0"

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        if raw.envelope is None:
            return NormalizeResult(
                event=None,
                dlq=DlqEntry(
                    raw_ref=raw.raw_ref,
                    reason="normalizer_exception",
                    detail="agent source requires a verified AgentEnvelope",
                    normalizer_version=self.version,
                    partition_key=part,
                    dedupe_key=None,
                ),
                partition_key=part,
                dedupe_key="",
                is_late=False,
                source_time_quality="untrusted",
            )
        event = raw.envelope.event
        offset = clock_offset_ms(raw.received_at, event.event_time)
        updated = event.model_copy(update={"clock_offset_ms": offset})
        return NormalizeResult(
            event=updated,
            dlq=None,
            partition_key=part,
            dedupe_key=dedupe_key(raw, raw.raw_payload),
            is_late=False,
            source_time_quality="trusted",
        )
