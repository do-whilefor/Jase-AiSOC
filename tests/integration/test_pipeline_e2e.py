"""P0-P4 end-to-end pipeline: ingest receipts -> normalize -> detect -> query API.

Real PostgreSQL. Exercises the full wired pipeline against the in-process app:
insert raw agent_events + object-store envelopes, run the normalize worker, run
the detection worker, then query /api/v1/events and /api/v1/detections via
httpx. Verifies the pipeline is no longer broken (plan §4.3 data flow).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from blue_team.agent_core.contracts import AgentEnvelope, EventPriority
from blue_team.api_server import create_app
from blue_team.config import Settings
from blue_team.detection_engine.worker import DetectionWorker
from blue_team.normalize.worker import NormalizeWorker
from blue_team.storage import Database, LocalObjectStore

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_e2e_pipeline00"
HOST = "host_e2e_pipeline00"


def _envelope(
    seq: int,
    src_ip: str,
    url: str,
    status: int,
    offset: int,
    *,
    base_time: datetime,
) -> AgentEnvelope:
    from blue_team.domain.security_event import SecurityEvent

    event_time = base_time + timedelta(seconds=offset)
    event = SecurityEvent.model_validate(
        {
            "event_id": f"evt_e2epipe{seq:04d}",
            "schema_version": "0.1.0",
            "event_type": "network.http",
            "event_time": event_time.isoformat(),
            "ingest_time": event_time.isoformat(),
            "boot_id": "boot-e2e",
            "sequence": seq,
            "source": {
                "kind": "agent",
                "collector": "suricata-eve",
                "collector_version": "0.1.0",
                "agent_id": "agent_e2e_pipeline",
            },
            "tenant": {"id": TENANT},
            "host": {"id": HOST, "os": "linux"},
            "network": {
                "src_ip": src_ip,
                "src_port": 50000 + seq,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "transport": "tcp",
            },
            "labels": {},
            "extensions": {"http.method": "GET", "http.url": url, "http.status": status},
            "raw_ref": f"evidence://{TENANT}/raw/{seq}",
        }
    )
    return AgentEnvelope(
        tenant_id=TENANT,
        agent_id="agent_e2e_pipeline",
        host_id=HOST,
        boot_id="boot-e2e",
        sequence=seq,
        priority=EventPriority.P2,
        event=event,
    )


@pytest.mark.asyncio
async def test_pipeline_normalize_detect_query_end_to_end(tmp_path: Path) -> None:
    assert DATABASE_URL is not None
    settings = Settings(
        environment="test",
        database_url=DATABASE_URL,
        object_store_root=tmp_path / "evidence",
        bootstrap_admin_token=None,
        log_format="json",
        workers_enabled=False,  # we drive workers explicitly for determinism
    )
    database = Database(DATABASE_URL)
    object_store = LocalObjectStore(tmp_path / "evidence")
    await object_store.initialize()

    async with database.engine.begin() as connection:
        await connection.execute(text("DELETE FROM detections"))
        await connection.execute(text("DELETE FROM normalized_events"))
        await connection.execute(text("DELETE FROM agent_events"))
        await connection.execute(
            text(
                "INSERT INTO tenants (id, name) VALUES (:tid, 'e2e-pipeline') "
                "ON CONFLICT (id) DO NOTHING"
            ),
            {"tid": TENANT},
        )

    # 1. Insert 301 raw agent_events receipts with object-store envelopes.
    from blue_team.agent_core.contracts import canonical_envelope_bytes

    received_at = datetime.now(UTC)
    event_base_time = received_at - timedelta(seconds=45)
    async with database.session() as session, session.begin():
        from blue_team.storage.models import AgentEventRecord

        for seq in range(301):
            env = _envelope(
                seq,
                "203.0.113.9",
                f"/p{seq:03d}",
                404,
                round(seq * 0.1),
                base_time=event_base_time,
            )
            canonical = canonical_envelope_bytes(env)
            metadata = await object_store.put(TENANT, canonical, media_type="application/json")
            session.add(
                AgentEventRecord(
                    id=f"agevt_e2e{seq:04d}",
                    tenant_id=TENANT,
                    agent_id="agent_e2e_pipeline",
                    host_id=HOST,
                    boot_id="boot-e2e",
                    sequence=seq,
                    event_id=env.event.event_id,
                    event_time=env.event.event_time,
                    source="suricata-eve",
                    raw_ref=metadata.ref,
                    integrity_sha256=metadata.sha256,
                    received_at=received_at,
                    normalize_status="pending",
                )
            )

    # 2. Run the normalize worker -> normalized_events populated.
    normalize_worker = NormalizeWorker(database, object_store, batch_size=500, poll_seconds=1.0)
    normalized_count = await normalize_worker.run_once()
    assert normalized_count == 301

    async with database.session() as session:
        from sqlalchemy import func, select

        from blue_team.storage.models import NormalizedEventRecord

        ne_count = await session.scalar(
            select(func.count()).select_from(
                select(NormalizedEventRecord)
                .where(NormalizedEventRecord.tenant_id == TENANT)
                .subquery()
            )
        )
        done_count = await session.scalar(
            select(func.count()).select_from(
                text("agent_events WHERE normalize_status='done' AND tenant_id=:tid").bindparams(
                    tid=TENANT
                )
            )
        )
    assert ne_count == 301
    assert done_count == 301

    # 3. Run the detection worker -> a web.recon.scanning detection is persisted.
    # Use a large lookback so the fixed-timestamp test events fall in range.
    detection_worker = DetectionWorker(
        database, settings=settings, poll_seconds=2.0, lookback_seconds=86400
    )
    emitted = await detection_worker.run_once()
    assert emitted == 1

    # 4. Query the API: events + detections are visible to the tenant.
    app = create_app(settings, database=database, object_store=object_store)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client,
    ):
        # Bootstrap a tenant credential to query as.
        # The tenant already exists; issue a credential directly via the DB.
        from uuid import uuid4

        from blue_team.api_server.tenant_tokens import issue_tenant_token
        from blue_team.storage.models import TenantCredentialRecord

        issued = issue_tenant_token(f"cred_{uuid4().hex}")
        async with database.session() as session, session.begin():
            session.add(
                TenantCredentialRecord(
                    id=issued.credential_id,
                    tenant_id=TENANT,
                    token_digest=issued.token_digest,
                )
            )
        bearer = {"Authorization": f"Bearer {issued.value}"}

        events_resp = await client.get("/api/v1/events?limit=10", headers=bearer)
        detections_resp = await client.get("/api/v1/detections", headers=bearer)

    assert events_resp.status_code == 200
    events_body = events_resp.json()
    assert events_body["total"] == 301
    assert len(events_body["items"]) == 10
    assert events_body["items"][0]["event_type"] == "network.http"

    assert detections_resp.status_code == 200
    det_body = detections_resp.json()
    assert det_body["total"] == 1
    assert det_body["items"][0]["category"] == "web.recon.scanning"

    # 5. Idempotent replay: re-running both workers produces no new rows.
    await normalize_worker.run_once()
    await detection_worker.run_once()
    async with database.session() as session:
        from sqlalchemy import func, select

        from blue_team.storage.models import DetectionRecord, NormalizedEventRecord

        ne2 = await session.scalar(
            select(func.count()).select_from(
                select(NormalizedEventRecord)
                .where(NormalizedEventRecord.tenant_id == TENANT)
                .subquery()
            )
        )
        det2 = await session.scalar(
            select(func.count()).select_from(
                select(DetectionRecord).where(DetectionRecord.tenant_id == TENANT).subquery()
            )
        )
    assert ne2 == 301
    assert det2 == 1
