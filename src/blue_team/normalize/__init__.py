"""P3 normalize pipeline: raw events -> canonical SecurityEvent + DLQ + watermark."""

from __future__ import annotations

# Importing the adapter modules registers them with the registry at import time.
from blue_team.normalize import (  # noqa: F401
    agent_normalizer,
    auditd_normalizer,
    falco_normalizer,
    journald_normalizer,
    service_log_normalizer,
    stub_normalizers,
    suricata_normalizer,
)
from blue_team.normalize.base import (
    DlqEntry,
    Normalizer,
    NormalizeResult,
    RawInput,
    clock_offset_ms,
    dedupe_key,
    partition_key,
)
from blue_team.normalize.normalizer_registry import get_normalizer, register
from blue_team.normalize.watermark import WatermarkAdvance, WatermarkSnapshot, advance

__all__ = [
    "DlqEntry",
    "NormalizeResult",
    "Normalizer",
    "RawInput",
    "WatermarkAdvance",
    "WatermarkSnapshot",
    "advance",
    "clock_offset_ms",
    "dedupe_key",
    "get_normalizer",
    "partition_key",
    "register",
]
