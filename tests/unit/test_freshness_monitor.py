"""Unit tests for the pure freshness classifier (no database)."""

from __future__ import annotations

import pytest

from blue_team.domain.console import FreshnessStatus
from blue_team.observability.freshness import classify_freshness

# Mirrors Settings defaults: production SLO 5s, verify SLO 10s.
_VERIFY = 10
_PRODUCTION = 5


@pytest.mark.parametrize(
    ("lag", "expected"),
    [
        (0.0, FreshnessStatus.FRESH),
        (5.0, FreshnessStatus.FRESH),
        (5.1, FreshnessStatus.STALE),
        (10.0, FreshnessStatus.STALE),
        (10.1, FreshnessStatus.DEGRADED),
        (3600.0, FreshnessStatus.DEGRADED),
        (-3.0, FreshnessStatus.FRESH),  # clock skew clamped to fresh
    ],
)
def test_classify_freshness_thresholds(lag: float, expected: FreshnessStatus) -> None:
    assert (
        classify_freshness(
            lag,
            verify_slo_seconds=_VERIFY,
            production_slo_seconds=_PRODUCTION,
        )
        == expected
    )


def test_classify_freshness_respects_custom_thresholds() -> None:
    # Tighter production SLO moves the fresh/stale boundary.
    assert classify_freshness(2.0, verify_slo_seconds=10, production_slo_seconds=1) is (
        FreshnessStatus.STALE
    )
    assert classify_freshness(0.5, verify_slo_seconds=10, production_slo_seconds=1) is (
        FreshnessStatus.FRESH
    )
