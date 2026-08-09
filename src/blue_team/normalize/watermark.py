"""Per-partition watermark advance for out-of-order and late-event detection (§7.5).

The tracker is pure logic; persistence of ``event_watermarks`` rows is handled by
the event repository so the normalizer can be unit-tested without a database.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class WatermarkSnapshot:
    """Current watermark state for one partition, loaded from the DB."""

    partition_key: str
    max_seen_event_time: datetime | None
    allowed_lateness_seconds: int


@dataclass(frozen=True, slots=True)
class WatermarkAdvance:
    """Result of advancing a partition with one event's time."""

    max_seen_event_time: datetime
    watermark: datetime
    is_late: bool
    advanced: bool


def advance(
    snapshot: WatermarkSnapshot,
    event_time: datetime,
    *,
    allowed_lateness_seconds: int | None = None,
) -> WatermarkAdvance:
    """Advance the partition watermark and flag late arrivals.

    ``is_late`` is true only when the event falls *before* the watermark
    (``max_seen_event_time - allowed_lateness``). Out-of-order events that remain
    inside the allowed lateness window are accepted without a late marker.
    """
    lateness = (
        allowed_lateness_seconds
        if allowed_lateness_seconds is not None
        else snapshot.allowed_lateness_seconds
    )
    if snapshot.max_seen_event_time is None or event_time > snapshot.max_seen_event_time:
        new_max = event_time
        advanced = snapshot.max_seen_event_time is not None
    else:
        new_max = snapshot.max_seen_event_time
        advanced = False
    watermark = new_max - timedelta(seconds=lateness)
    is_late = snapshot.max_seen_event_time is not None and event_time < watermark
    return WatermarkAdvance(
        max_seen_event_time=new_max,
        watermark=watermark,
        is_late=is_late,
        advanced=advanced,
    )
