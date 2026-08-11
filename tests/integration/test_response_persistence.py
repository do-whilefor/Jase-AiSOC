"""P11 real-PostgreSQL approval, lease, execution, rollback, and tenant gate.

This remains skipped in the non-Docker Windows pass and is intended for the
later Kali/PostgreSQL validation environment with migration 0013 applied.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from blue_team.domain.response import (
    ApprovalDecision,
    FirewallAdapter,
    IpResponseTarget,
    ResponseActionKind,
    ResponseActionStatus,
    ResponseApprovalCreate,
    ResponsePlanCreate,
    ResponseQueueRequest,
    ResponseRollbackRequest,
)
from blue_team.errors import NotFoundError, StateConflictError
from blue_team.response_engine import execute_response_action, rollback_response_action
from blue_team.storage import Database
from blue_team.storage.models import (
    AgentEventRecord,
    HostRecord,
    IncidentEvidenceRecord,
    IncidentRecord,
    IncidentRevisionRecord,
    NormalizedEventRecord,
    ResponseActionEventRecord,
    ResponseApprovalRecord,
    ResponseExecutionRecord,
    ResponseRollbackRecord,
    TenantRecord,
)
from blue_team.storage.response_repository import (
    claim_next_response_action,
    complete_response_execution,
    complete_response_rollback,
    create_response_plan,
    decide_response_approval,
    get_response_action,
    queue_response_action,
    request_response_rollback,
)
from tests.integration._helpers import truncate_all
from tests.unit.test_response_adapters import FakeAdapter

DATABASE_URL = os.getenv("BLUE_TEAM_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="PostgreSQL integration URL is not set"),
]

TENANT = "ten_response_integration"
HOST = "host_response_integration"
AGENT = "agent_response_integration"
INCIDENT = "inc_response_integration"
EVENT = "evt_response_integration01"
NOW = datetime(2026, 8, 9, 19, 0, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def _clean(database: Database) -> None:
    await truncate_all(database)


async def _seed(database: Database) -> None:
    raw_id = "aevt_" + _digest(EVENT)[:24]
    async with database.session() as session, session.begin():
        session.add(TenantRecord(id=TENANT, name="integration-p11"))
        session.add(
            HostRecord(
                id=HOST,
                tenant_id=TENANT,
                hostname="response-integration",
                agent_id=AGENT,
                distro="test",
                kernel="test",
                capabilities={"response": True},
                criticality="critical",
            )
        )
        await session.flush()
        session.add(
            IncidentRecord(
                id=INCIDENT,
                tenant_id=TENANT,
                correlation_key="icr_" + _digest(INCIDENT)[:40],
                primary_host_id=HOST,
                status="open",
                severity="critical",
                confidence=0.99,
                risk_score=95,
                attack_state="confirmed_compromise",
                summary="P11 response integration",
                first_seen=NOW,
                last_seen=NOW,
                assurance="deterministic_only",
                revision=1,
                detection_count=1,
                evidence_count=1,
                aggregate_metrics={},
                full_query_ref="qry_" + _digest(INCIDENT)[:32],
            )
        )
        session.add(
            IncidentRevisionRecord(
                tenant_id=TENANT,
                incident_id=INCIDENT,
                revision=1,
                reason="initial_correlation",
                snapshot_hash=_digest("response-snapshot"),
                severity="critical",
                confidence=0.99,
                risk_score=95,
                attack_state="confirmed_compromise",
                summary="P11 response integration",
                first_seen=NOW,
                last_seen=NOW,
                assurance="deterministic_only",
                detection_count=1,
                evidence_count=1,
                aggregate_metrics={},
                full_query_ref="qry_" + _digest(INCIDENT)[:32],
            )
        )
        session.add(
            AgentEventRecord(
                id=raw_id,
                tenant_id=TENANT,
                agent_id=AGENT,
                host_id=HOST,
                boot_id="boot-response-integration",
                sequence=1,
                event_id=EVENT,
                event_time=NOW,
                source="auditd",
                raw_ref=f"evidence://{TENANT}/{EVENT}",
                integrity_sha256=_digest(EVENT),
                normalize_status="done",
            )
        )
        session.add(
            NormalizedEventRecord(
                id="nevt_" + _digest(EVENT)[:24],
                tenant_id=TENANT,
                raw_event_id=raw_id,
                event_id=EVENT,
                source_event_id=None,
                partition_key=f"{TENANT}|{HOST}|auditd",
                dedupe_key="dedupe-" + _digest(EVENT),
                event_type="process.exec",
                event_time=NOW,
                ingest_time=NOW,
                clock_offset_ms=0,
                source_time_quality="trusted",
                payload={"event_id": EVENT},
                labels={},
                extensions={},
                raw_ref=f"evidence://{TENANT}/{EVENT}",
                normalizer_version="0.1.0",
                status="active",
                revision=1,
                revision_reason=None,
                watermark_event_time=NOW,
            )
        )
        session.add(
            IncidentEvidenceRecord(
                tenant_id=TENANT,
                incident_id=INCIDENT,
                revision=1,
                event_id=EVENT,
                evidence_id="evi_" + _digest(EVENT)[:24],
                event_type="process.exec",
                event_time=NOW,
                host_id=HOST,
                raw_ref=f"evidence://{TENANT}/{EVENT}",
                integrity_sha256=_digest(EVENT),
                source_time_quality="trusted",
                is_late=False,
            )
        )


@pytest.mark.asyncio
async def test_p11_persists_two_person_approval_execution_and_verified_rollback() -> None:
    assert DATABASE_URL is not None
    database = Database(DATABASE_URL)
    await _clean(database)
    await _seed(database)
    request = ResponsePlanCreate(
        incident_revision=1,
        action=ResponseActionKind.TEMPORARY_BLOCK_IP,
        target=IpResponseTarget(
            host_id=HOST,
            expected_agent_id=AGENT,
            ip_address="203.0.113.90",
        ),
        evidence_ids=(EVENT,),
        reason="integration containment with TTL",
        ttl_seconds=1800,
    )
    try:
        async with database.session() as session, session.begin():
            created = await create_response_plan(
                session,
                tenant_id=TENANT,
                incident_id=INCIDENT,
                data=request,
                actor="tenant-credential:cred_requester",
                firewall_adapter=FirewallAdapter.NFTABLES,
                file_quarantine_root="/var/lib/blue-team/response-quarantine",
                allowed_file_roots=("/opt", "/srv", "/tmp", "/var/tmp"),
                max_active_actions_per_incident=8,
                max_active_targets_per_incident=4,
                now=NOW,
            )
        assert created.plan.policy.required_approvals == 2
        async with database.session() as session, session.begin():
            first = await decide_response_approval(
                session,
                tenant_id=TENANT,
                action_id=created.plan.action_id,
                data=ResponseApprovalCreate(
                    decision=ApprovalDecision.APPROVE,
                    comment="security approval",
                ),
                actor="tenant-credential:cred_approver01",
                now=NOW + timedelta(seconds=1),
            )
            with pytest.raises(StateConflictError):
                await decide_response_approval(
                    session,
                    tenant_id=TENANT,
                    action_id=created.plan.action_id,
                    data=ResponseApprovalCreate(
                        decision=ApprovalDecision.APPROVE,
                        comment="duplicate actor",
                    ),
                    actor="tenant-credential:cred_approver01",
                    now=NOW + timedelta(seconds=2),
                )
        assert first.plan.status is ResponseActionStatus.PENDING_APPROVAL
        async with database.session() as session, session.begin():
            approved = await decide_response_approval(
                session,
                tenant_id=TENANT,
                action_id=created.plan.action_id,
                data=ResponseApprovalCreate(
                    decision=ApprovalDecision.APPROVE,
                    comment="business approval",
                ),
                actor="tenant-credential:cred_approver02",
                now=NOW + timedelta(seconds=3),
            )
            await queue_response_action(
                session,
                tenant_id=TENANT,
                action_id=created.plan.action_id,
                data=ResponseQueueRequest(idempotency_key="integration-execute-01"),
                actor="tenant-credential:cred_responder",
                now=NOW + timedelta(seconds=4),
            )
        assert approved.plan.status is ResponseActionStatus.APPROVED

        async with database.session() as session, session.begin():
            lease = await claim_next_response_action(
                session,
                worker_id="response-worker-integration",
                lease_seconds=300,
                now=NOW + timedelta(seconds=5),
            )
        assert lease is not None
        adapter = FakeAdapter(lease.plan)
        executed = await execute_response_action(
            lease.plan,
            adapter,
            now=NOW + timedelta(seconds=5),
        )
        async with database.session() as session, session.begin():
            await complete_response_execution(
                session,
                lease=lease,
                result=executed,
                worker_id="response-worker-integration",
                completed_at=NOW + timedelta(seconds=6),
            )
            await request_response_rollback(
                session,
                tenant_id=TENANT,
                action_id=created.plan.action_id,
                data=ResponseRollbackRequest(
                    reason="restore after containment validation",
                    idempotency_key="integration-rollback-01",
                ),
                actor="tenant-credential:cred_responder",
                now=NOW + timedelta(seconds=7),
            )
        async with database.session() as session, session.begin():
            rollback_lease = await claim_next_response_action(
                session,
                worker_id="response-worker-integration",
                lease_seconds=300,
                now=NOW + timedelta(seconds=8),
            )
        assert rollback_lease is not None
        assert rollback_lease.execution is not None
        rolled_back = await rollback_response_action(
            rollback_lease.plan,
            rollback_lease.execution,
            adapter,
        )
        async with database.session() as session, session.begin():
            await complete_response_rollback(
                session,
                lease=rollback_lease,
                result=rolled_back,
                worker_id="response-worker-integration",
                completed_at=NOW + timedelta(seconds=9),
            )
            detail = await get_response_action(
                session,
                tenant_id=TENANT,
                action_id=created.plan.action_id,
            )
            approvals = await session.scalar(
                select(func.count())
                .select_from(ResponseApprovalRecord)
                .where(ResponseApprovalRecord.tenant_id == TENANT)
            )
            executions = await session.scalar(
                select(func.count())
                .select_from(ResponseExecutionRecord)
                .where(ResponseExecutionRecord.tenant_id == TENANT)
            )
            rollbacks = await session.scalar(
                select(func.count())
                .select_from(ResponseRollbackRecord)
                .where(ResponseRollbackRecord.tenant_id == TENANT)
            )
            events = await session.scalar(
                select(func.count())
                .select_from(ResponseActionEventRecord)
                .where(ResponseActionEventRecord.tenant_id == TENANT)
            )
            with pytest.raises(NotFoundError):
                await get_response_action(
                    session,
                    tenant_id="ten_other_response",
                    action_id=created.plan.action_id,
                )

        assert detail.plan.status is ResponseActionStatus.ROLLED_BACK
        assert approvals == 2
        assert executions == 1
        assert rollbacks == 1
        assert events is not None and events >= 9
    finally:
        await _clean(database)
        await database.dispose()
