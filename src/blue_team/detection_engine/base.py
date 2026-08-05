"""Detection engine contracts: the Rule protocol, Detection result, and a
deterministic sliding-window burst helper shared by rules.

Design (plan §4.3, §8.3, §8.4): rules are synchronous pure functions that
consume a batch of :class:`~blue_team.domain.security_event.SecurityEvent`
and return zero or more :class:`Detection` findings. They never touch the
database, so they are unit-testable and replay-deterministic (§8.4). Persistence
is handled separately by the detection repository.

Windowing is greedy and non-overlapping: scanning a sorted event stream with a
``window_seconds`` sliding window, the helper emits the first window whose
contents satisfy a predicate and then suppresses overlapping windows until
events fall past the emitted window's end. This bounds output to one detection
per burst and is reproducible across replays.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blue_team.config import Settings
    from blue_team.domain.security_event import SecurityEvent


@dataclass(frozen=True, slots=True)
class Detection:
    """An in-memory detection finding produced by a rule, pre-persistence."""

    rule_id: str
    rule_version: str
    category: str
    severity: str
    confidence: float
    attack_state: str
    tenant_id: str
    host_id: str
    entity_key: str
    event_time_window_start: datetime
    event_time_window_end: datetime
    summary: str | None = None
    evidence_event_ids: list[str] = field(default_factory=list)
    aggregate_metrics: dict[str, object] = field(default_factory=dict)
    next_steps: str | None = None


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Per-evaluation context: identity plus the thresholds a rule reads."""

    tenant_id: str
    host_id: str
    window_seconds: int
    settings: Settings


class Rule:
    """Detector protocol satisfied structurally by rule implementations.

    ``applicable_event_types`` filters which events the engine hands to the
    rule; ``evaluate`` returns the detections emitted for one batch. Rules are
    registered by ``rule_id`` (the detection category) via the registry.
    """

    rule_id: str
    version: str
    applicable_event_types: tuple[str, ...]

    def evaluate(
        self, events: Sequence[SecurityEvent], context: RuleContext
    ) -> list[Detection]:  # pragma: no cover - structural protocol
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class Window:
    """A time window [start, end] and the events falling within it."""

    start: datetime
    end: datetime
    events: list  # type: ignore[type-arg]  # list[SecurityEvent], avoided for dataclass cycle


def detect_bursts(
    events: Sequence[SecurityEvent],
    window_seconds: int,
    predicate: Callable[[list], bool],  # type: ignore[type-arg]  # list[SecurityEvent]
) -> Iterator[Window]:
    """Yield greedy non-overlapping detection windows over a sorted event stream.

    ``events`` must be ascending by ``event_time``. For each event as a window's
    right edge, the window spans ``[end - window_seconds, end]``. The first window
    (by end time) whose contents satisfy ``predicate`` is yielded; subsequent
    windows are suppressed until an event's ``event_time`` exceeds the yielded
    window's end. This guarantees determinism and one detection per burst.
    """
    if not events:
        return
    window = timedelta(seconds=window_seconds)
    emitted_until: datetime | None = None
    left = 0
    for right in range(len(events)):
        right_time = events[right].event_time
        if right_time.tzinfo is None:
            right_time = right_time.replace(tzinfo=UTC)
        # advance left edge so the window only holds events within window_seconds
        while left < right and events[left].event_time < right_time - window:
            left += 1
        window_start = right_time - window
        if emitted_until is not None and window_start < emitted_until:
            continue
        members = list(events[left : right + 1])
        if predicate(members):
            yield Window(start=window_start, end=right_time, events=members)
            emitted_until = right_time
