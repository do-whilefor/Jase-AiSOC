"""P3 FreshnessMonitor + /api/v1/freshness gate against real PostgreSQL."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from blue_team.api_server import create_app
from blue_team.config import Settings
from blue_team.domain.console import FreshnessStatus
from blue_team.domain.resources import TenantCreate
from blue_team.observability.freshness import FreshnessMonitor
from blue_team.storage import Database
from blue_team.storage.models import (
    AgentEventRecord,
    EventFreshnessRecord,
    HostRecord,
    NormalizedEventRecord,
    TenantRecord,
)
from blue_team.storage.repositories import create_tenant
from tests.integration._helpers import truncate_all

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_freshness_integration"
OTHER_TENANT = "ten_freshness_other"
HOST_FRESH = "host_freshness_fresh"
HOST_STALE = "host_freshness_stale"
HOST_OTHER = "host_freshness_other"


def _settings() -> Settings:
    assert DATABASE_URL is not None
    return Settings(
        environment="test",
        database_url=DATABASE_URL,
        bootstrap_admin_token=None,
        log_format="json",
        workers_enabled=False,
    )


async def _seed(database: Database, *, observed_at: datetime) -> None:
    """Seed two tenants/hosts with normalized events at known event_times."""
    fresh_event_time = observed_at - timedelta(seconds=2)  # within production SLO (5s)
    stale_event_time = observed_at - timedelta(seconds=60)  # beyond verify SLO (10s) -> degraded

    async with database.session() as session, session.begin():
        session.add(TenantRecord(id=TENANT, name="freshness-integration"))
        session.add(TenantRecord(id=OTHER_TENANT, name="freshness-other"))
        for host in (HOST_FRESH, HOST_STALE):
            session.add(
                HostRecord(
                    id=host,
                    tenant_id=TENANT,
                    hostname=host,
                    agent_id=None,
                    distro="test",
                    kernel="test",
                    capabilities={},
                    criticality="medium",
                )
            )
        session.add(
            HostRecord(
                id=HOST_OTHER,
                tenant_id=OTHER_TENANT,
                hostname=HOST_OTHER,
                agent_id=None,
                distro="test",
                kernel="test",
                capabilities={},
                criticality="medium",
            )
        )

    async with database.session() as session, session.begin():
        for idx, (host, event_time) in enumerate(
            ((HOST_FRESH, fresh_event_time), (HOST_STALE, stale_event_time))
        ):
            raw_id = f"agevt_{host}"
            session.add(
                AgentEventRecord(
                    id=raw_id,
                    tenant_id=TENANT,
                    agent_id="agent_freshness",
                    host_id=host,
                    boot_id="boot-freshness",
                    sequence=idx,
                    event_id=f"evt_{host}",
                    event_time=event_time,
                    source="web",
                    raw_ref="evidence://test",
                    integrity_sha256="0" * 64,
                    received_at=observed_at,
                    normalize_status="done",
                )
            )
            session.add(
                NormalizedEventRecord(
                    id=f"nevt_{host}",
                    tenant_id=TENANT,
                    raw_event_id=raw_id,
                    event_id=f"evt_{host}",
                    source_event_id=None,
                    partition_key=f"{TENANT}|{host}|web",
                    dedupe_key=f"dedupe-{host}",
                    event_type="web.request",
                    event_time=event_time,
                    ingest_time=observed_at,
                    clock_offset_ms=None,
                    source_time_quality="trusted",
                    payload={},
                    labels={},
                    extensions={},
                    raw_ref="evidence://test",
                    normalizer_version="0.1.0",
                    status="active",
                    revision=1,
                    revision_reason=None,
                    watermark_event_time=event_time,
                )
            )
        raw_other = "agevt_other"
        session.add(
            AgentEventRecord(
                id=raw_other,
                tenant_id=OTHER_TENANT,
                agent_id="agent_freshness_other",
                host_id=HOST_OTHER,
                boot_id="boot-freshness-other",
                sequence=0,
                event_id="evt_other",
                event_time=observed_at - timedelta(seconds=1),
                source="web",
                raw_ref="evidence://test",
                integrity_sha256="0" * 64,
                received_at=observed_at,
                normalize_status="done",
            )
        )
        session.add(
            NormalizedEventRecord(
                id="nevt_other",
                tenant_id=OTHER_TENANT,
                raw_event_id=raw_other,
                event_id="evt_other",
                source_event_id=None,
                partition_key=f"{OTHER_TENANT}|{HOST_OTHER}|web",
                dedupe_key="dedupe-other",
                event_type="web.request",
                event_time=observed_at - timedelta(seconds=1),
                ingest_time=observed_at,
                clock_offset_ms=None,
                source_time_quality="trusted",
                payload={},
                labels={},
                extensions={},
                raw_ref="evidence://test",
                normalizer_version="0.1.0",
                status="active",
                revision=1,
                revision_reason=None,
                watermark_event_time=observed_at - timedelta(seconds=1),
            )
        )


@pytest.mark.asyncio
async def test_freshness_monitor_classifies_and_upserts_per_host() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    settings = _settings()
    await truncate_all(database)
    observed_at = datetime.now(UTC)
    await _seed(database, observed_at=observed_at)
    try:
        monitor = FreshnessMonitor(database, settings=settings)
        upserted = await monitor.run_once(now=observed_at)
        assert upserted == 3  # two hosts in TENANT, one in OTHER_TENANT

        async with database.session() as session:
            rows = {
                r.host_id: r
                for r in (
                    await session.scalars(
                        select(EventFreshnessRecord).where(EventFreshnessRecord.tenant_id == TENANT)
                    )
                ).all()
            }
        assert set(rows) == {HOST_FRESH, HOST_STALE}
        # fresh event was 2s old, production SLO is 5s -> fresh
        assert rows[HOST_FRESH].status == FreshnessStatus.FRESH.value
        assert rows[HOST_FRESH].lag_seconds == pytest.approx(2.0, abs=0.001)
        # stale event was 60s old, beyond verify SLO (10s) -> degraded
        assert rows[HOST_STALE].status == FreshnessStatus.DEGRADED.value
        assert rows[HOST_STALE].lag_seconds == pytest.approx(60.0, abs=0.001)

        # Idempotent re-run: same host set, no duplicates (host_id is the key).
        upserted_again = await monitor.run_once(now=observed_at)
        assert upserted_again == 3
        async with database.session() as session:
            tenant_count = await session.scalar(
                select(func.count())
                .select_from(EventFreshnessRecord)
                .where(EventFreshnessRecord.tenant_id == TENANT)
            )
        assert tenant_count == 2
    finally:
        await truncate_all(database)
        await database.dispose()


@pytest.mark.asyncio
async def test_freshness_route_is_tenant_scoped() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    settings = _settings()
    await truncate_all(database)
    observed_at = datetime.now(UTC)

    # Create two real tenants (with bearer tokens) and seed freshness for one of them.
    async with database.session() as session, session.begin():
        read_a, token_a = await create_tenant(
            session,
            data=TenantCreate(name="freshness-route-a"),
            actor="integration",
        )
        tenant_a = read_a.id
    async with database.session() as session, session.begin():
        read_b, token_b = await create_tenant(
            session,
            data=TenantCreate(name="freshness-route-b"),
            actor="integration",
        )
        tenant_b = read_b.id

    fresh_event_time = observed_at - timedelta(seconds=1)
    async with database.session() as session, session.begin():
        host_id = "host_route_a"
        session.add(
            HostRecord(
                id=host_id,
                tenant_id=tenant_a,
                hostname=host_id,
                agent_id=None,
                distro="test",
                kernel="test",
                capabilities={},
                criticality="medium",
            )
        )
        raw_id = "agevt_route_a"
        session.add(
            AgentEventRecord(
                id=raw_id,
                tenant_id=tenant_a,
                agent_id="agent_route_a",
                host_id=host_id,
                boot_id="boot-route",
                sequence=0,
                event_id="evt_route_a",
                event_time=fresh_event_time,
                source="web",
                raw_ref="evidence://test",
                integrity_sha256="0" * 64,
                received_at=observed_at,
                normalize_status="done",
            )
        )
        session.add(
            NormalizedEventRecord(
                id="nevt_route_a",
                tenant_id=tenant_a,
                raw_event_id=raw_id,
                event_id="evt_route_a",
                source_event_id=None,
                partition_key=f"{tenant_a}|{host_id}|web",
                dedupe_key="dedupe-route-a",
                event_type="web.request",
                event_time=fresh_event_time,
                ingest_time=observed_at,
                clock_offset_ms=None,
                source_time_quality="trusted",
                payload={},
                labels={},
                extensions={},
                raw_ref="evidence://test",
                normalizer_version="0.1.0",
                status="active",
                revision=1,
                revision_reason=None,
                watermark_event_time=fresh_event_time,
            )
        )

    try:
        monitor = FreshnessMonitor(database, settings=settings)
        await monitor.run_once(now=observed_at)

        app = create_app(settings=settings, database=database)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp_a = await client.get(
                "/api/v1/freshness",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            metrics_a = await client.get(
                "/api/v1/freshness/metrics",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            resp_b = await client.get(
                "/api/v1/freshness",
                headers={"Authorization": f"Bearer {token_b}"},
            )

        # Tenant A sees its single fresh host.
        assert resp_a.status_code == 200
        body_a = resp_a.json()
        assert body_a["total"] == 1
        assert body_a["items"][0]["host_id"] == "host_route_a"
        assert body_a["items"][0]["status"] == FreshnessStatus.FRESH.value

        assert metrics_a.status_code == 200
        metrics = metrics_a.json()
        assert metrics["tracked_hosts"] == 1
        assert metrics["fresh"] == 1
        assert metrics["degraded"] == 0
        assert metrics["lag_sample_count"] == 1
        assert metrics["maximum_lag_seconds"] is not None

        # Tenant B sees nothing of tenant A's data -> tenant isolation.
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 0
        assert tenant_b != tenant_a
    finally:
        await truncate_all(database)
        await database.dispose()
