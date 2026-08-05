from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from blue_team.platform import (
    CapabilityLevel,
    CapabilityReport,
    CollectorCapability,
    CollectorState,
    InitSystem,
    PlatformInfo,
)


def platform_info() -> PlatformInfo:
    return PlatformInfo(
        distro_id="ubuntu",
        distro_like=("debian",),
        version_id="24.04",
        kernel_release="6.8.0-40-generic",
        architecture="x86_64",
        init_system=InitSystem.SYSTEMD,
        btf_available=True,
    )


def test_capability_report_preserves_collector_degradation_evidence() -> None:
    report = CapabilityReport(
        observed_at=datetime.now(UTC),
        level=CapabilityLevel.L1,
        platform=platform_info(),
        collectors=(
            CollectorCapability(
                name="auditd",
                state=CollectorState.DEGRADED,
                drop_count=7,
                last_error="backlog pressure",
            ),
        ),
    )

    assert report.collectors[0].drop_count == 7
    assert report.platform.distro_like == ("debian",)


def test_failed_collector_requires_an_observable_reason() -> None:
    with pytest.raises(ValidationError, match="last_error"):
        CollectorCapability(name="ebpf", state=CollectorState.FAILED)


def test_capability_report_rejects_duplicate_collectors_and_naive_time() -> None:
    collector = CollectorCapability(name="journald", state=CollectorState.ENABLED)

    with pytest.raises(ValidationError, match="timezone"):
        CapabilityReport(
            observed_at=datetime(2026, 8, 3),
            level=CapabilityLevel.L0,
            platform=platform_info(),
            collectors=(collector,),
        )
    with pytest.raises(ValidationError, match="unique"):
        CapabilityReport(
            observed_at=datetime.now(UTC),
            level=CapabilityLevel.L0,
            platform=platform_info(),
            collectors=(collector, collector),
        )
