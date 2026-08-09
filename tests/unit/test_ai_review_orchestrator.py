"""P7 deterministic gate-to-Analyzer orchestration tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from blue_team.ai_review.orchestrator import AiReviewOrchestrator
from blue_team.ai_review.providers import ModelProviderError, ResilientModelClient
from blue_team.ai_review.tool_gateway import ReadOnlyToolDataSource, ToolGateway, ToolQueryScope
from blue_team.domain import (
    AiReviewPolicy,
    AnalyzerClaim,
    AnalyzerReport,
    AttackState,
    ClaimReviewStatus,
    IncidentDataReduction,
    IncidentEvidenceBundle,
    IncidentEvidenceRef,
    IncidentQuerySpec,
    IncidentReviewContext,
    IncidentReviewInput,
    IncidentSeverity,
    ModelCapabilities,
    ModelHealth,
    ModelHealthStatus,
    ModelRequest,
    ModelResponse,
    ModelRunStatus,
    ModelToolCall,
    ModelUsage,
    ReviewExecutionStatus,
)

TENANT = "ten_01JP7ORCHESTR"
HOST = "host_01JP7ORCHEST"
INCIDENT = "inc_01JP7ORCHESTR"
EVENT = "evt_p7orchestr0001"
TOOL_EVENT = "evt_p7orchestr0002"
QUERY = "qry_" + "3" * 32
NOW = datetime(2026, 8, 9, 14, 0, tzinfo=UTC)


class StubProvider:
    def __init__(self, outcomes: list[ModelResponse | Exception]) -> None:
        self.outcomes = outcomes
        self.requests: list[ModelRequest] = []

    @property
    def provider_name(self) -> str:
        return "stub"

    @property
    def model_name(self) -> str:
        return "stub-analyzer"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            tools=True,
            json_schema=True,
            stream=False,
            context_tokens=100_000,
        )

    async def health(self) -> ModelHealth:
        return ModelHealth(
            status=ModelHealthStatus.AVAILABLE,
            provider=self.provider_name,
            model=self.model_name,
            checked_at=NOW,
        )

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class StubToolSource(ReadOnlyToolDataSource):
    def __init__(self) -> None:
        self.calls: list[ToolQueryScope] = []

    async def search_events(
        self,
        scope: ToolQueryScope,
        *,
        event_types: tuple[str, ...],
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        del event_types, limit
        self.calls.append(scope)
        return (
            {
                "event_id": TOOL_EVENT,
                "event_type": "process.exec",
                "event_time": NOW.isoformat(),
            },
        )

    async def get_process_tree(
        self,
        scope: ToolQueryScope,
        *,
        pid: int | None,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        del scope, pid, limit
        return ()

    async def get_incident_timeline(
        self,
        scope: ToolQueryScope,
        *,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, object], ...]:
        del scope, limit, offset
        return ()

    async def get_entity_graph(
        self,
        scope: ToolQueryScope,
        *,
        entity_types: tuple[str, ...],
        include_edges: bool,
        limit: int,
    ) -> tuple[dict[str, object], ...]:
        del scope, entity_types, include_edges, limit
        return ()


def _policy(**updates: object) -> AiReviewPolicy:
    values: dict[str, object] = {
        "policy_version": "p7-orchestrator-test",
        "provider_max_retries": 0,
    }
    values.update(updates)
    return AiReviewPolicy.model_validate(values)


def _incident(
    *,
    severity: IncidentSeverity = IncidentSeverity.HIGH,
    risk_score: int = 80,
) -> IncidentReviewInput:
    return IncidentReviewInput(
        tenant_id=TENANT,
        incident_id=INCIDENT,
        revision=1,
        primary_host_id=HOST,
        severity=severity,
        confidence=0.85,
        risk_score=risk_score,
        attack_state=AttackState.SUSPECTED_SUCCESS,
        summary="process chain crossed a deterministic detection threshold",
        evidence_count=1,
        aggregate_metrics={"event_count": 1},
    )


def _evidence() -> IncidentEvidenceBundle:
    reference = IncidentEvidenceRef(
        evidence_id="evi_" + "0" * 24,
        event_id=EVENT,
        event_type="process.exec",
        event_time=NOW,
        host_id=HOST,
        raw_ref=f"evidence://{TENANT}/raw/0",
        integrity_sha256="0" * 64,
        source_time_quality="trusted",
    )
    query = IncidentQuerySpec(
        tenant_id=TENANT,
        host_id=HOST,
        event_time_from=NOW,
        event_time_to=NOW,
        event_types=("process.exec",),
    )
    reduction = IncidentDataReduction(
        reduction_id="red_" + "0" * 24,
        input_count=1,
        retained_count=1,
        dropped_count=0,
        sample_event_ids=(EVENT,),
        full_query_ref=QUERY,
        query=query,
    )
    return IncidentEvidenceBundle(
        incident_id=INCIDENT,
        tenant_id=TENANT,
        revision=1,
        evidence_count=1,
        evidence_index=(reference,),
        data_reductions=(reduction,),
    )


def _final_response(
    *,
    evidence_id: str = EVENT,
    cost_usd: float = 0.01,
) -> ModelResponse:
    claim = AnalyzerClaim(
        claim_id="aic_" + "0" * 24,
        category="host.process_chain",
        statement="The process execution is present in the authorized evidence.",
        epistemic_status="observed",
        evidence_ids=(evidence_id,),
        support_score=1.0,
        review_status=ClaimReviewStatus.SUPPORTED,
    )
    report = AnalyzerReport(
        incident_id=INCIDENT,
        summary="The bounded evidence supports one atomic process claim.",
        claims=(claim,),
    )
    return ModelResponse(
        structured_output=report.model_dump(mode="json"),
        usage=ModelUsage(input_tokens=500, output_tokens=100, cost_usd=cost_usd),
        response_sha256="1" * 64,
    )


def _tool_response() -> ModelResponse:
    return ModelResponse(
        tool_calls=(
            ModelToolCall(
                call_id="call-search-1",
                name="search_events",
                arguments={"query_ref": QUERY, "limit": 1},
            ),
        ),
        usage=ModelUsage(input_tokens=400, output_tokens=50, cost_usd=0.01),
        response_sha256="2" * 64,
    )


def _orchestrator(
    provider: StubProvider,
    policy: AiReviewPolicy,
    source: StubToolSource | None = None,
) -> tuple[AiReviewOrchestrator, StubToolSource]:
    actual_source = source or StubToolSource()
    gateway = ToolGateway(actual_source, policy)
    client = ResilientModelClient(provider, policy)
    return AiReviewOrchestrator(policy, client, gateway), actual_source


@pytest.mark.asyncio
async def test_normal_incident_is_skipped_without_any_model_or_tool_call() -> None:
    provider = StubProvider([])
    orchestrator, source = _orchestrator(provider, _policy())

    outcome = await orchestrator.review(
        _incident(severity=IncidentSeverity.LOW, risk_score=10),
        IncidentReviewContext(normal_or_expected_activity=True),
        _evidence(),
    )

    assert outcome.status is ReviewExecutionStatus.SKIPPED
    assert outcome.deterministic_result_preserved is True
    assert provider.requests == []
    assert source.calls == []


@pytest.mark.asyncio
async def test_provider_failure_degrades_without_changing_deterministic_result() -> None:
    provider = StubProvider([ModelProviderError("HTTP 503", retryable=False)])
    orchestrator, _ = _orchestrator(provider, _policy())

    outcome = await orchestrator.review(_incident(), IncidentReviewContext(), _evidence())

    assert outcome.status is ReviewExecutionStatus.MODEL_UNAVAILABLE
    assert outcome.deterministic_result_preserved is True
    assert outcome.report is None
    assert outcome.model_runs[0].status is ModelRunStatus.FAILED
    assert outcome.model_runs[0].degradation_reason == "ModelProviderError"
    assert outcome.model_runs[0].response_sha256 is None


@pytest.mark.asyncio
async def test_tool_loop_closes_report_to_package_or_tool_evidence() -> None:
    provider = StubProvider([_tool_response(), _final_response(evidence_id=TOOL_EVENT)])
    orchestrator, source = _orchestrator(provider, _policy())

    outcome = await orchestrator.review(_incident(), IncidentReviewContext(), _evidence())

    assert outcome.status is ReviewExecutionStatus.COMPLETED
    assert outcome.report is not None
    assert outcome.report.claims[0].evidence_ids == (TOOL_EVENT,)
    assert len(outcome.model_runs) == 2
    assert outcome.model_runs[0].tool_call_count == 1
    assert source.calls == [
        ToolQueryScope(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            revision=1,
            query_ref=QUERY,
        )
    ]


@pytest.mark.asyncio
async def test_report_cannot_cite_unknown_or_cross_incident_evidence() -> None:
    provider = StubProvider([_final_response(evidence_id="evt_foreign000001")])
    orchestrator, _ = _orchestrator(provider, _policy())

    outcome = await orchestrator.review(_incident(), IncidentReviewContext(), _evidence())

    assert outcome.status is ReviewExecutionStatus.INVALID_OUTPUT
    assert outcome.report is None
    assert outcome.degradation_reason == "model report failed the evidence-closure contract"


@pytest.mark.asyncio
async def test_token_cost_tool_and_rate_budgets_fail_closed() -> None:
    cost_provider = StubProvider([_final_response(cost_usd=2.0)])
    cost_orchestrator, _ = _orchestrator(
        cost_provider,
        _policy(max_cost_usd_per_incident=1.0),
    )
    cost = await cost_orchestrator.review(_incident(), IncidentReviewContext(), _evidence())
    assert cost.status is ReviewExecutionStatus.BUDGET_EXCEEDED

    tool_provider = StubProvider([_tool_response()])
    tool_orchestrator, _ = _orchestrator(tool_provider, _policy(max_tool_calls=0))
    tools = await tool_orchestrator.review(_incident(), IncidentReviewContext(), _evidence())
    assert tools.status is ReviewExecutionStatus.BUDGET_EXCEEDED

    context_provider = StubProvider([])
    context_orchestrator, _ = _orchestrator(
        context_provider,
        _policy(max_context_tokens=100, max_output_tokens=50),
    )
    context = await context_orchestrator.review(_incident(), IncidentReviewContext(), _evidence())
    assert context.status is ReviewExecutionStatus.BUDGET_EXCEEDED
    assert context_provider.requests == []

    rate_provider = StubProvider([_final_response()])
    rate_orchestrator, _ = _orchestrator(
        rate_provider,
        _policy(max_reviews_per_minute=1),
    )
    first = await rate_orchestrator.review(_incident(), IncidentReviewContext(), _evidence())
    second = await rate_orchestrator.review(_incident(), IncidentReviewContext(), _evidence())
    assert first.status is ReviewExecutionStatus.COMPLETED
    assert second.status is ReviewExecutionStatus.BUDGET_EXCEEDED
    assert len(rate_provider.requests) == 1


@pytest.mark.asyncio
async def test_invalid_tool_query_is_rejected_without_expanding_scope() -> None:
    response = _tool_response().model_copy(
        update={
            "tool_calls": (
                ModelToolCall(
                    call_id="call-cross-query",
                    name="search_events",
                    arguments={"query_ref": "qry_" + "9" * 32, "limit": 1},
                ),
            )
        }
    )
    provider = StubProvider([response])
    orchestrator, source = _orchestrator(provider, _policy())

    outcome = await orchestrator.review(_incident(), IncidentReviewContext(), _evidence())

    assert outcome.status is ReviewExecutionStatus.INVALID_OUTPUT
    assert source.calls == []
