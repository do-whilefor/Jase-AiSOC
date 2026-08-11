"""SourceKind -> Normalizer registry."""

from __future__ import annotations

from collections.abc import Callable

from aisoc.domain.security_event import SourceKind
from aisoc.normalize.base import DlqEntry, Normalizer, NormalizeResult, RawInput, partition_key

_REGISTRY: dict[SourceKind, Normalizer] = {}


def register(kind: SourceKind) -> Callable[[type[Normalizer]], type[Normalizer]]:
    """Register a Normalizer implementation for a SourceKind (class decorator)."""

    def decorator(cls: type[Normalizer]) -> type[Normalizer]:
        if not hasattr(cls, "kind") or cls.kind != kind:
            raise ValueError(f"normalizer {cls.__name__} kind does not match {kind}")
        _REGISTRY[kind] = cls()
        return cls

    return decorator


def get_normalizer(kind: SourceKind) -> Normalizer | None:
    """Return the registered normalizer, or None (caller produces a DLQ entry)."""
    return _REGISTRY.get(kind)


def _dlq(
    raw: RawInput,
    *,
    reason: str,
    detail: str | None = None,
    normalizer_version: str | None = None,
) -> NormalizeResult:
    return NormalizeResult(
        event=None,
        dlq=DlqEntry(
            raw_ref=raw.raw_ref,
            reason=reason,
            detail=detail,
            normalizer_version=normalizer_version,
            partition_key=partition_key(raw.tenant_id, raw.host_id, raw.boot_id),
            dedupe_key=None,
        ),
        partition_key=partition_key(raw.tenant_id, raw.host_id, raw.boot_id),
        dedupe_key="",
        is_late=False,
        source_time_quality="untrusted",
    )
