"""Stub normalizers for SourceKinds not yet implemented in P3.

Each stub registers itself and produces a DLQ entry with ``reason=no_normalizer``
so the pipeline never silently drops raw evidence for an unsupported source.
"""

from __future__ import annotations

from blue_team.domain.security_event import SourceKind
from blue_team.normalize.base import (
    DlqEntry,
    NormalizeResult,
    RawInput,
    partition_key,
)


class _StubNormalizer:
    """Produce a no_normalizer DLQ entry for an unimplemented SourceKind."""

    version = "0.0.0"

    def __init__(self, kind: SourceKind) -> None:
        self.kind = kind

    def normalize(self, raw: RawInput) -> NormalizeResult:
        part = partition_key(raw.tenant_id, raw.host_id, raw.boot_id)
        return NormalizeResult(
            event=None,
            dlq=DlqEntry(
                raw_ref=raw.raw_ref,
                reason="no_normalizer",
                detail=f"SourceKind.{self.kind.value} has no P3 normalizer",
                normalizer_version=self.version,
                partition_key=part,
                dedupe_key=None,
            ),
            partition_key=part,
            dedupe_key="",
            is_late=False,
            source_time_quality="untrusted",
        )


def _register_stub(kind: SourceKind) -> None:
    stub = _StubNormalizer(kind)
    from blue_team.normalize import normalizer_registry

    # A concrete adapter may have been imported first; never replace it with a
    # placeholder because of module import order.
    normalizer_registry._REGISTRY.setdefault(kind, stub)


for _kind in (
    SourceKind.FILE_SCAN,
    SourceKind.IMPORT,
):
    _register_stub(_kind)
