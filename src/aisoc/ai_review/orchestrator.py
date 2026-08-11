"""P8 Analyzer, blind Verifier, and optional Adjudicator orchestration."""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import ValidationError

from aisoc._rustcore import sha256_hex
from aisoc.ai_review.evidence import (
    EvidencePackageError,
    build_evidence_package,
    review_task_id,
)
from aisoc.ai_review.evidence_verifier import (
    blind_claims,
    detect_claim_conflicts,
    verify_claim_evidence,
)
from aisoc.ai_review.gate import AiReviewGate
from aisoc.ai_review.prompting import (
    PROMPT_VERSION,
    build_adjudicator_request,
    build_model_request,
    build_verifier_request,
)
from aisoc.ai_review.providers import (
    CircuitOpenError,
    ProviderCallFailed,
    ResilientModelClient,
)
from aisoc.ai_review.tool_gateway import ToolGateway, ToolGatewayError
from aisoc.domain.ai_review import (
    AdjudicationReport,
    AiReviewPolicy,
    AnalyzerReport,
    AssuranceLevel,
    BlindClaim,
    ClaimConflict,
    ClaimProgramVerification,
    ClaimReviewStatus,
    EvidencePackage,
    IncidentReviewContext,
    IncidentReviewInput,
    ModelHistoryScore,
    ModelRequest,
    ModelResponse,
    ModelRole,
    ModelRunStatus,
    ModelRunSummary,
    ModelToolCall,
    ModelUsage,
    ProgramVerificationStatus,
    ReviewDecision,
    ReviewDecisionKind,
    ReviewExecutionStatus,
    ReviewOutcome,
    ToolCallAudit,
    ToolCallAuditStatus,
    ToolResult,
    VerifierReport,
)
from aisoc.domain.incident import IncidentEvidenceBundle


class ReviewRateLimiter:
    """Atomic in-process per-tenant rolling-minute budget."""

    def __init__(
        self,
        max_reviews_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._maximum = max_reviews_per_minute
        self._clock = clock
        self._accepted: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def acquire(self, tenant_id: str) -> bool:
        async with self._lock:
            now = self._clock()
            boundary = now - 60.0
            accepted = self._accepted[tenant_id]
            while accepted and accepted[0] <= boundary:
                accepted.popleft()
            if len(accepted) >= self._maximum:
                return False
            accepted.append(now)
            return True


@dataclass(slots=True)
class _ExecutionBudget:
    model_runs: list[ModelRunSummary]
    tool_calls: list[ToolCallAudit]
    tool_results: list[ToolResult]
    seen_call_ids: set[str]
    total_cost: float
    degradation_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_outcome(cls, outcome: ReviewOutcome) -> _ExecutionBudget:
        tool_results = [item.result for item in outcome.tool_calls if item.result is not None]
        return cls(
            model_runs=list(outcome.model_runs),
            tool_calls=list(outcome.tool_calls),
            tool_results=tool_results,
            seen_call_ids={item.call_id for item in outcome.tool_calls},
            total_cost=sum(item.usage.cost_usd for item in outcome.model_runs),
        )


class AiReviewOrchestrator:
    """Run AI only after the deterministic Incident gate selects one revision."""

    def __init__(
        self,
        policy: AiReviewPolicy,
        model_client: ResilientModelClient,
        tool_gateway: ToolGateway,
        *,
        allowed_tools: tuple[str, ...] | None = None,
        rate_limiter: ReviewRateLimiter | None = None,
        verifier_clients: tuple[ResilientModelClient, ...] = (),
        adjudicator_client: ResilientModelClient | None = None,
        model_history: tuple[ModelHistoryScore, ...] = (),
    ) -> None:
        self._policy = policy
        self._client = model_client
        self._gateway = tool_gateway
        requested_tools = tool_gateway.supported_tools() if allowed_tools is None else allowed_tools
        if not model_client.provider.capabilities().tools:
            requested_tools = ()
        unsupported = set(requested_tools) - set(tool_gateway.supported_tools())
        if unsupported:
            raise ValueError("allowed_tools contains an unsupported Tool Gateway capability")
        self._allowed_tools = tuple(sorted(set(requested_tools)))
        self._verifier_clients = verifier_clients
        self._model_history = model_history
        self._adjudicator_client = adjudicator_client
        self._gate = AiReviewGate(
            policy,
            prompt_version=PROMPT_VERSION,
            allowed_tools=self._allowed_tools,
        )
        self._rate_limiter = rate_limiter or ReviewRateLimiter(policy.max_reviews_per_minute)

    async def review(
        self,
        incident: IncidentReviewInput,
        context: IncidentReviewContext,
        evidence: IncidentEvidenceBundle,
    ) -> ReviewOutcome:
        decision, task_id = self.plan(incident, context)
        if decision.kind is ReviewDecisionKind.SKIP:
            return ReviewOutcome(
                review_task_id=task_id,
                decision=decision,
                status=ReviewExecutionStatus.SKIPPED,
            )
        if decision.kind is ReviewDecisionKind.REQUIRE_HUMAN:
            return ReviewOutcome(
                review_task_id=task_id,
                decision=decision,
                status=ReviewExecutionStatus.REQUIRE_HUMAN,
            )

        try:
            package = build_evidence_package(
                incident,
                evidence,
                decision,
                self._policy,
                available_tools=self._allowed_tools,
            )
        except EvidencePackageError:
            return ReviewOutcome(
                review_task_id=task_id,
                decision=decision,
                status=ReviewExecutionStatus.REQUIRE_HUMAN,
                degradation_reason="deterministic evidence package could not be closed",
            )
        if not await self._rate_limiter.acquire(incident.tenant_id):
            return self._degraded(
                decision,
                package,
                ReviewExecutionStatus.BUDGET_EXCEEDED,
                "tenant review rate budget exhausted",
            )
        analyzer_outcome = await self._run_analyzer(decision, package)
        if analyzer_outcome.report is None:
            return analyzer_outcome
        return await self._run_verification(analyzer_outcome)

    def plan(
        self,
        incident: IncidentReviewInput,
        context: IncidentReviewContext,
    ) -> tuple[ReviewDecision, str]:
        decision = self._gate.evaluate(incident, context)
        return decision, review_task_id(incident, self._policy)

    async def _run_analyzer(
        self,
        decision: ReviewDecision,
        package: EvidencePackage,
    ) -> ReviewOutcome:
        profile = decision.profile
        assert profile is not None
        definitions = self._gateway.definitions(profile.allowed_tools)
        tool_results: tuple[ToolResult, ...] = ()
        model_runs: tuple[ModelRunSummary, ...] = ()
        tool_audits: tuple[ToolCallAudit, ...] = ()
        seen_call_ids: set[str] = set()
        total_cost = 0.0
        capabilities = self._client.provider.capabilities()
        context_limit = min(self._policy.max_context_tokens, capabilities.context_tokens)

        for run_index in range(self._policy.max_model_runs_per_incident):
            request = build_model_request(
                package,
                tool_results=tool_results,
                tools=definitions,
                max_output_tokens=self._policy.max_output_tokens,
                run_index=run_index,
            )
            request_hash = _request_hash(request)
            if _estimate_tokens(request) + request.max_output_tokens > context_limit:
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.BUDGET_EXCEEDED,
                    "model context token budget exhausted before provider call",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )
            try:
                call_result = await self._client.complete(request)
            except CircuitOpenError as error:
                model_runs += (
                    self._failed_run(
                        package,
                        request,
                        request_hash,
                        error,
                        ModelRunStatus.CIRCUIT_OPEN,
                    ),
                )
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.MODEL_UNAVAILABLE,
                    "model provider circuit is open",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )
            except ProviderCallFailed as error:
                model_runs += (
                    self._failed_run(
                        package,
                        request,
                        request_hash,
                        error,
                        ModelRunStatus.FAILED,
                    ),
                )
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.MODEL_UNAVAILABLE,
                    "model provider call failed",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )

            response = call_result.response
            model_runs += (
                ModelRunSummary(
                    run_id=_run_id(package, request, self._client.provider.provider_name),
                    provider=self._client.provider.provider_name,
                    model=self._client.provider.model_name,
                    role=request.role,
                    status=ModelRunStatus.COMPLETED,
                    evidence_count=len(package.evidence_ids),
                    usage=response.usage,
                    latency_ms=call_result.latency_ms,
                    retry_count=call_result.retry_count,
                    tool_call_count=len(response.tool_calls),
                    request_sha256=request_hash,
                    response_sha256=response.response_sha256,
                ),
            )
            total_cost += response.usage.cost_usd
            if (
                response.usage.input_tokens + response.usage.output_tokens > context_limit
                or total_cost > self._policy.max_cost_usd_per_incident
            ):
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.BUDGET_EXCEEDED,
                    "provider usage exceeded the configured token or cost budget",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )
            if response.tool_calls and response.structured_output is not None:
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.INVALID_OUTPUT,
                    "model returned tools and a final report in one ambiguous response",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )
            if response.tool_calls:
                if len(tool_results) + len(response.tool_calls) > self._policy.max_tool_calls:
                    run_id = model_runs[-1].run_id
                    tool_audits += tuple(
                        _rejected_tool_audit(call, run_id, "tool_call_budget_exhausted")
                        for call in response.tool_calls
                    )
                    return self._degraded(
                        decision,
                        package,
                        ReviewExecutionStatus.BUDGET_EXCEEDED,
                        "tool call budget exhausted",
                        model_runs=model_runs,
                        tool_calls=tool_audits,
                    )
                new_results: list[ToolResult] = []
                run_id = model_runs[-1].run_id
                try:
                    for call in response.tool_calls:
                        if call.call_id in seen_call_ids:
                            raise ToolGatewayError("duplicate tool call ID")
                        seen_call_ids.add(call.call_id)
                        result = await self._gateway.execute(package, call)
                        new_results.append(result)
                        tool_audits += (
                            ToolCallAudit(
                                call_id=call.call_id,
                                run_id=run_id,
                                tool_name=call.name,
                                status=ToolCallAuditStatus.COMPLETED,
                                arguments=call.arguments,
                                arguments_sha256=sha256_hex(
                                    _canonical_json(call.arguments)
                                ),
                                result=result,
                            ),
                        )
                except ToolGatewayError as error:
                    tool_audits += (_rejected_tool_audit(call, run_id, type(error).__name__),)
                    return self._degraded(
                        decision,
                        package,
                        ReviewExecutionStatus.INVALID_OUTPUT,
                        "model requested an invalid or unauthorized tool call",
                        model_runs=model_runs,
                        tool_calls=tool_audits,
                    )
                tool_results += tuple(new_results)
                continue

            report = self._validate_report(package, tool_results, response.structured_output)
            if report is None:
                return self._degraded(
                    decision,
                    package,
                    ReviewExecutionStatus.INVALID_OUTPUT,
                    "model report failed the evidence-closure contract",
                    model_runs=model_runs,
                    tool_calls=tool_audits,
                )
            return ReviewOutcome(
                review_task_id=package.review_task_id,
                decision=decision,
                status=ReviewExecutionStatus.COMPLETED,
                evidence_package=package,
                report=report,
                model_runs=model_runs,
                tool_calls=tool_audits,
            )

        return self._degraded(
            decision,
            package,
            ReviewExecutionStatus.BUDGET_EXCEEDED,
            "model run budget exhausted before a final report",
            model_runs=model_runs,
            tool_calls=tool_audits,
        )

    async def _run_verification(self, outcome: ReviewOutcome) -> ReviewOutcome:
        package = outcome.evidence_package
        report = outcome.report
        assert package is not None
        assert report is not None

        program_verifications = verify_claim_evidence(
            package,
            report,
            outcome.tool_calls,
        )
        verification_required = (
            outcome.decision.kind is ReviewDecisionKind.ANALYZE_AND_VERIFY
            or self._requires_dynamic_verification(report, program_verifications)
        )
        budget = _ExecutionBudget.from_outcome(outcome)
        blinded = blind_claims(report)
        base_tool_results = tuple(budget.tool_results)
        verifier_reports: list[VerifierReport] = []
        verifier_identities: list[tuple[str, str]] = []

        if verification_required:
            scenarios = tuple(sorted({item.category for item in report.claims}))
            verifier_clients = tuple(
                sorted(
                    self._verifier_clients,
                    key=lambda client: _history_routing_score(
                        client,
                        self._model_history,
                        ModelRole.VERIFIER,
                        scenarios,
                    ),
                    reverse=True,
                )
            )[: self._policy.max_verifier_slots]
            for position, client in enumerate(verifier_clients):
                if len(budget.model_runs) >= self._policy.max_model_runs_per_incident:
                    budget.degradation_reasons.append(
                        "model run budget exhausted before all verifier slots"
                    )
                    break
                verifier = await self._run_verifier_slot(
                    client,
                    package,
                    blinded,
                    program_verifications,
                    base_tool_results,
                    position=position,
                    budget=budget,
                )
                if verifier is not None:
                    verifier_reports.append(verifier)
                    verifier_identities.append(
                        (client.provider.provider_name, client.provider.model_name)
                    )

        conflicts = detect_claim_conflicts(
            report,
            program_verifications,
            tuple(verifier_reports),
        )
        adjudication: AdjudicationReport | None = None
        if (
            conflicts
            and self._policy.adjudicator_enabled
            and self._adjudicator_client is not None
            and len(budget.model_runs) < self._policy.max_model_runs_per_incident
        ):
            adjudication = await self._run_adjudicator(
                self._adjudicator_client,
                package,
                blinded,
                program_verifications,
                tuple(verifier_reports),
                conflicts,
                budget,
            )

        unresolved_conflicts = self._unresolved_conflicts(conflicts, adjudication)
        human_review_required = bool(unresolved_conflicts)
        if verification_required and not verifier_reports:
            human_review_required = True
            budget.degradation_reasons.append("required blind Verifier unavailable")
        if conflicts and adjudication is None:
            budget.degradation_reasons.append("Claim conflicts require human review")

        assurance = self._assurance_level(
            outcome,
            verification_required=verification_required,
            verifier_reports=tuple(verifier_reports),
            verifier_identities=tuple(verifier_identities),
            human_review_required=human_review_required,
        )
        reasons = list(
            filter(
                None,
                (outcome.degradation_reason, *budget.degradation_reasons),
            )
        )
        degradation_reason = "; ".join(dict.fromkeys(reasons))[:512] or None
        return ReviewOutcome.model_validate(
            {
                **outcome.model_dump(mode="python"),
                "assurance_level": assurance,
                "verification_required": verification_required,
                "human_review_required": human_review_required,
                "program_verifications": program_verifications,
                "verifier_reports": tuple(verifier_reports),
                "conflicts": conflicts,
                "adjudication": adjudication,
                "model_runs": tuple(budget.model_runs),
                "tool_calls": tuple(budget.tool_calls),
                "degradation_reason": degradation_reason,
            }
        )

    def _requires_dynamic_verification(
        self,
        report: AnalyzerReport,
        program_verifications: tuple[ClaimProgramVerification, ...],
    ) -> bool:
        unsupported = any(
            item.review_status
            in {
                ClaimReviewStatus.INSUFFICIENT,
                ClaimReviewStatus.UNSUPPORTED,
            }
            for item in report.claims
        )
        conflicting = any(
            item.status is ProgramVerificationStatus.INVALID for item in program_verifications
        ) or any(
            item.review_status is ClaimReviewStatus.CONTRADICTED or item.contradiction_score > 0.0
            for item in report.claims
        )
        return (self._policy.verify_unsupported_claims and unsupported) or (
            self._policy.verify_conflicting_evidence and conflicting
        )

    async def _run_verifier_slot(
        self,
        client: ResilientModelClient,
        package: EvidencePackage,
        claims: tuple[BlindClaim, ...],
        program_verifications: tuple[ClaimProgramVerification, ...],
        base_tool_results: tuple[ToolResult, ...],
        *,
        position: int,
        budget: _ExecutionBudget,
    ) -> VerifierReport | None:
        slot_id = _verifier_slot_id(package, position)
        visible_results = list(base_tool_results)
        definitions = (
            self._gateway.definitions(self._allowed_tools)
            if client.provider.capabilities().tools
            else ()
        )
        while len(budget.model_runs) < self._policy.max_model_runs_per_incident:
            request = build_verifier_request(
                package,
                verifier_slot_id=slot_id,
                claims=claims,
                program_verifications=program_verifications,
                tool_results=tuple(visible_results),
                tools=definitions,
                max_output_tokens=self._policy.max_output_tokens,
                run_index=len(budget.model_runs),
            )
            response = await self._complete_followup_request(client, package, request, budget)
            if response is None:
                return None
            if response.tool_calls and response.structured_output is not None:
                budget.degradation_reasons.append(
                    "Verifier returned tools and a final report in one response"
                )
                return None
            if response.tool_calls:
                if not await self._execute_followup_tools(
                    package,
                    response.tool_calls,
                    visible_results,
                    budget,
                ):
                    return None
                continue
            verifier = self._validate_verifier_report(
                package,
                slot_id,
                claims,
                tuple(visible_results),
                response.structured_output,
            )
            if verifier is None:
                budget.degradation_reasons.append(
                    "Verifier report failed the blind evidence-closure contract"
                )
            return verifier
        budget.degradation_reasons.append("model run budget exhausted before Verifier output")
        return None

    async def _run_adjudicator(
        self,
        client: ResilientModelClient,
        package: EvidencePackage,
        claims: tuple[BlindClaim, ...],
        program_verifications: tuple[ClaimProgramVerification, ...],
        verifier_reports: tuple[VerifierReport, ...],
        conflicts: tuple[ClaimConflict, ...],
        budget: _ExecutionBudget,
    ) -> AdjudicationReport | None:
        visible_results = list(budget.tool_results)
        definitions = (
            self._gateway.definitions(self._allowed_tools)
            if client.provider.capabilities().tools
            else ()
        )
        while len(budget.model_runs) < self._policy.max_model_runs_per_incident:
            request = build_adjudicator_request(
                package,
                claims=claims,
                program_verifications=program_verifications,
                verifier_reports=verifier_reports,
                conflicts=conflicts,
                tool_results=tuple(visible_results),
                tools=definitions,
                max_output_tokens=self._policy.max_output_tokens,
                run_index=len(budget.model_runs),
            )
            response = await self._complete_followup_request(client, package, request, budget)
            if response is None:
                return None
            if response.tool_calls and response.structured_output is not None:
                budget.degradation_reasons.append(
                    "Adjudicator returned tools and a final report in one response"
                )
                return None
            if response.tool_calls:
                if not await self._execute_followup_tools(
                    package,
                    response.tool_calls,
                    visible_results,
                    budget,
                ):
                    return None
                continue
            adjudication = self._validate_adjudication_report(
                package,
                program_verifications,
                conflicts,
                tuple(visible_results),
                response.structured_output,
            )
            if adjudication is None:
                budget.degradation_reasons.append(
                    "Adjudication failed deterministic-priority or evidence closure"
                )
            return adjudication
        budget.degradation_reasons.append("model run budget exhausted before Adjudicator output")
        return None

    async def _complete_followup_request(
        self,
        client: ResilientModelClient,
        package: EvidencePackage,
        request: ModelRequest,
        budget: _ExecutionBudget,
    ) -> ModelResponse | None:
        request_hash = _request_hash(request)
        context_limit = min(
            self._policy.max_context_tokens,
            client.provider.capabilities().context_tokens,
        )
        if _estimate_tokens(request) + request.max_output_tokens > context_limit:
            budget.degradation_reasons.append(
                f"{request.role.value} context token budget exhausted before provider call"
            )
            return None
        try:
            call_result = await client.complete(request)
        except CircuitOpenError as error:
            budget.model_runs.append(
                self._failed_run_for(
                    client,
                    package,
                    request,
                    request_hash,
                    error,
                    ModelRunStatus.CIRCUIT_OPEN,
                )
            )
            budget.degradation_reasons.append(f"{request.role.value} provider circuit is open")
            return None
        except ProviderCallFailed as error:
            budget.model_runs.append(
                self._failed_run_for(
                    client,
                    package,
                    request,
                    request_hash,
                    error,
                    ModelRunStatus.FAILED,
                )
            )
            budget.degradation_reasons.append(f"{request.role.value} provider call failed")
            return None

        response = call_result.response
        budget.model_runs.append(
            ModelRunSummary(
                run_id=_run_id(package, request, client.provider.provider_name),
                provider=client.provider.provider_name,
                model=client.provider.model_name,
                role=request.role,
                status=ModelRunStatus.COMPLETED,
                evidence_count=len(package.evidence_ids),
                usage=response.usage,
                latency_ms=call_result.latency_ms,
                retry_count=call_result.retry_count,
                tool_call_count=len(response.tool_calls),
                request_sha256=request_hash,
                response_sha256=response.response_sha256,
            )
        )
        budget.total_cost += response.usage.cost_usd
        if (
            response.usage.input_tokens + response.usage.output_tokens > context_limit
            or budget.total_cost > self._policy.max_cost_usd_per_incident
        ):
            budget.degradation_reasons.append(
                f"{request.role.value} usage exceeded the shared token or cost budget"
            )
            return None
        return response

    async def _execute_followup_tools(
        self,
        package: EvidencePackage,
        calls: tuple[ModelToolCall, ...],
        visible_results: list[ToolResult],
        budget: _ExecutionBudget,
    ) -> bool:
        run_id = budget.model_runs[-1].run_id
        if len(budget.tool_calls) + len(calls) > self._policy.max_tool_calls:
            budget.tool_calls.extend(
                _rejected_tool_audit(call, run_id, "tool_call_budget_exhausted") for call in calls
            )
            budget.degradation_reasons.append("shared tool call budget exhausted")
            return False
        for call in calls:
            if call.call_id in budget.seen_call_ids:
                budget.tool_calls.append(
                    _rejected_tool_audit(call, run_id, "duplicate_tool_call_id")
                )
                budget.degradation_reasons.append("model reused a tool call ID")
                return False
            budget.seen_call_ids.add(call.call_id)
            try:
                result = await self._gateway.execute(package, call)
            except ToolGatewayError as error:
                budget.tool_calls.append(_rejected_tool_audit(call, run_id, type(error).__name__))
                budget.degradation_reasons.append(
                    "model requested an invalid or unauthorized tool call"
                )
                return False
            visible_results.append(result)
            budget.tool_results.append(result)
            budget.tool_calls.append(
                ToolCallAudit(
                    call_id=call.call_id,
                    run_id=run_id,
                    tool_name=call.name,
                    status=ToolCallAuditStatus.COMPLETED,
                    arguments=call.arguments,
                    arguments_sha256=sha256_hex(_canonical_json(call.arguments)),
                    result=result,
                )
            )
        return True

    @staticmethod
    def _validate_verifier_report(
        package: EvidencePackage,
        slot_id: str,
        claims: tuple[BlindClaim, ...],
        tool_results: tuple[ToolResult, ...],
        raw: dict[str, object] | None,
    ) -> VerifierReport | None:
        if raw is None:
            return None
        try:
            report = VerifierReport.model_validate(raw)
        except ValidationError:
            return None
        if report.incident_id != package.incident_id or report.verifier_slot_id != slot_id:
            return None
        known_claims = {item.claim_id for item in claims}
        reviewed_claims = [item.claim_id for item in report.reviews]
        if (
            len(reviewed_claims) != len(set(reviewed_claims))
            or not set(reviewed_claims) <= known_claims
        ):
            return None
        allowed_evidence = set(package.evidence_ids) | _tool_evidence_ids(tool_results)
        if any(not set(item.evidence_ids) <= allowed_evidence for item in report.reviews):
            return None
        return report

    @staticmethod
    def _validate_adjudication_report(
        package: EvidencePackage,
        program_verifications: tuple[ClaimProgramVerification, ...],
        conflicts: tuple[ClaimConflict, ...],
        tool_results: tuple[ToolResult, ...],
        raw: dict[str, object] | None,
    ) -> AdjudicationReport | None:
        if raw is None:
            return None
        try:
            report = AdjudicationReport.model_validate(raw)
        except ValidationError:
            return None
        if report.incident_id != package.incident_id:
            return None
        conflict_ids = {item.conflict_id for item in conflicts}
        conflict_claim_ids = {item.claim_id for item in conflicts}
        resolution_claim_ids = [item.claim_id for item in report.resolutions]
        if (
            len(resolution_claim_ids) != len(set(resolution_claim_ids))
            or not set(resolution_claim_ids) <= conflict_claim_ids
            or not set(report.unresolved_conflict_ids) <= conflict_ids
        ):
            return None
        addressed_claim_ids = set(resolution_claim_ids)
        if any(
            item.conflict_id not in report.unresolved_conflict_ids
            and item.claim_id not in addressed_claim_ids
            for item in conflicts
        ):
            return None
        allowed_evidence = set(package.evidence_ids) | _tool_evidence_ids(tool_results)
        if any(not set(item.evidence_ids) <= allowed_evidence for item in report.resolutions):
            return None
        invalid_claims = {
            item.claim_id
            for item in program_verifications
            if item.status is ProgramVerificationStatus.INVALID
        }
        if any(
            item.claim_id in invalid_claims
            and item.final_status
            in {
                ClaimReviewStatus.SUPPORTED,
                ClaimReviewStatus.PARTIALLY_SUPPORTED,
            }
            for item in report.resolutions
        ):
            return None
        return report

    @staticmethod
    def _unresolved_conflicts(
        conflicts: tuple[ClaimConflict, ...],
        adjudication: AdjudicationReport | None,
    ) -> tuple[ClaimConflict, ...]:
        if adjudication is None:
            return conflicts
        unresolved_ids = set(adjudication.unresolved_conflict_ids)
        human_claims = {item.claim_id for item in adjudication.resolutions if item.requires_human}
        return tuple(
            item
            for item in conflicts
            if item.conflict_id in unresolved_ids or item.claim_id in human_claims
        )

    @staticmethod
    def _assurance_level(
        outcome: ReviewOutcome,
        *,
        verification_required: bool,
        verifier_reports: tuple[VerifierReport, ...],
        verifier_identities: tuple[tuple[str, str], ...],
        human_review_required: bool,
    ) -> AssuranceLevel:
        if not verification_required:
            return AssuranceLevel.BASIC
        if not verifier_reports:
            return AssuranceLevel.UNREVIEWED

        analyzer_identity = next(
            (
                (item.provider, item.model)
                for item in outcome.model_runs
                if item.role is ModelRole.ANALYZER and item.status is ModelRunStatus.COMPLETED
            ),
            None,
        )
        if analyzer_identity is None:
            return AssuranceLevel.DETERMINISTIC_ONLY
        identities = {analyzer_identity, *verifier_identities}
        if human_review_required:
            return AssuranceLevel.BASIC
        if len(verifier_reports) >= 2 and len(identities) >= 3:
            return AssuranceLevel.HIGH
        if any(item != analyzer_identity for item in verifier_identities):
            return AssuranceLevel.ENHANCED
        return AssuranceLevel.BASIC

    @staticmethod
    def _failed_run_for(
        client: ResilientModelClient,
        package: EvidencePackage,
        request: ModelRequest,
        request_hash: str,
        error: ProviderCallFailed,
        status: ModelRunStatus,
    ) -> ModelRunSummary:
        return ModelRunSummary(
            run_id=_run_id(package, request, client.provider.provider_name),
            provider=client.provider.provider_name,
            model=client.provider.model_name,
            role=request.role,
            status=status,
            evidence_count=len(package.evidence_ids),
            usage=ModelUsage(),
            latency_ms=error.latency_ms,
            retry_count=error.retry_count,
            tool_call_count=0,
            request_sha256=request_hash,
            degradation_reason=error.reason,
        )

    def _failed_run(
        self,
        package: EvidencePackage,
        request: ModelRequest,
        request_hash: str,
        error: ProviderCallFailed,
        status: ModelRunStatus,
    ) -> ModelRunSummary:
        return self._failed_run_for(
            self._client,
            package,
            request,
            request_hash,
            error,
            status,
        )

    @staticmethod
    def _validate_report(
        package: EvidencePackage,
        tool_results: tuple[ToolResult, ...],
        raw: dict[str, object] | None,
    ) -> AnalyzerReport | None:
        if raw is None:
            return None
        try:
            report = AnalyzerReport.model_validate(raw)
        except ValidationError:
            return None
        if report.incident_id != package.incident_id:
            return None
        claim_ids = [claim.claim_id for claim in report.claims]
        if len(claim_ids) != len(set(claim_ids)):
            return None
        allowed_evidence = set(package.evidence_ids)
        allowed_evidence.update(_tool_evidence_ids(tool_results))
        if any(not set(claim.evidence_ids) <= allowed_evidence for claim in report.claims):
            return None
        return report

    @staticmethod
    def _degraded(
        decision: ReviewDecision,
        package: EvidencePackage,
        status: ReviewExecutionStatus,
        reason: str,
        *,
        model_runs: tuple[ModelRunSummary, ...] = (),
        tool_calls: tuple[ToolCallAudit, ...] = (),
    ) -> ReviewOutcome:
        return ReviewOutcome(
            review_task_id=package.review_task_id,
            decision=decision,
            status=status,
            evidence_package=package,
            model_runs=model_runs,
            tool_calls=tool_calls,
            degradation_reason=reason,
        )


def _tool_evidence_ids(results: tuple[ToolResult, ...]) -> set[str]:
    evidence: set[str] = set()
    for result in results:
        for row in result.rows:
            for key in ("event_id", "evidence_id"):
                value = row.get(key)
                if isinstance(value, str):
                    evidence.add(value)
            values = row.get("evidence_event_ids")
            if isinstance(values, list | tuple):
                evidence.update(item for item in values if isinstance(item, str))
    return evidence


def _rejected_tool_audit(
    call: ModelToolCall,
    run_id: str,
    reason: str,
) -> ToolCallAudit:
    return ToolCallAudit(
        call_id=call.call_id,
        run_id=run_id,
        tool_name=call.name,
        status=ToolCallAuditStatus.REJECTED,
        arguments=call.arguments,
        arguments_sha256=sha256_hex(_canonical_json(call.arguments)),
        degradation_reason=reason,
    )


def _request_hash(request: ModelRequest) -> str:
    return sha256_hex(_canonical_json(request.model_dump(mode="json")))


def _run_id(package: EvidencePackage, request: ModelRequest, provider: str) -> str:
    material = f"{package.review_task_id}\0{request.request_id}\0{provider}\0{request.role.value}"
    return f"mrun_{sha256_hex(material.encode())[:24]}"


def _verifier_slot_id(package: EvidencePackage, position: int) -> str:
    material = f"{package.review_task_id}\0verifier\0{position}"
    return f"vslot_{sha256_hex(material.encode())[:16]}"


def _history_routing_score(
    client: ResilientModelClient,
    history: tuple[ModelHistoryScore, ...],
    role: ModelRole,
    scenarios: tuple[str, ...],
) -> float:
    exact = (
        item.routing_score
        for item in history
        if item.provider == client.provider.provider_name
        and item.model == client.provider.model_name
        and item.role is role
        and item.scenario in scenarios
    )
    exact_score = max(exact, default=None)
    if exact_score is not None:
        return exact_score
    fallback = (
        item.routing_score
        for item in history
        if item.provider == client.provider.provider_name
        and item.model == client.provider.model_name
        and item.role is role
        and item.scenario == "default"
    )
    return max(fallback, default=0.5)


def _estimate_tokens(request: ModelRequest) -> int:
    byte_count = len(_canonical_json(request.model_dump(mode="json")))
    return max(1, (byte_count + 3) // 4)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


__all__ = ["AiReviewOrchestrator", "ReviewRateLimiter"]
