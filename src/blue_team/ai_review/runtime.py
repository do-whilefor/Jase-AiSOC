"""Build the optional P7 provider runtime from validated application settings."""

from __future__ import annotations

from dataclasses import dataclass

from blue_team.ai_review.orchestrator import ReviewRateLimiter
from blue_team.ai_review.providers import (
    PROVIDER_PRESETS,
    GlmProvider,
    KimiProvider,
    ModelProvider,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
    ResilientModelClient,
)
from blue_team.config.settings import Settings
from blue_team.domain.ai_review import AiReviewPolicy
from blue_team.domain.resources import IncidentSeverity


@dataclass(frozen=True, slots=True)
class AiReviewRuntime:
    policy: AiReviewPolicy
    model_client: ResilientModelClient
    verifier_clients: tuple[ResilientModelClient, ...]
    adjudicator_client: ResilientModelClient | None
    rate_limiter: ReviewRateLimiter


def ai_review_policy_from_settings(settings: Settings) -> AiReviewPolicy:
    return AiReviewPolicy(
        policy_version=settings.ai_review_policy_version,
        minimum_severity=IncidentSeverity(settings.ai_review_minimum_severity),
        minimum_risk_score=settings.ai_review_minimum_risk_score,
        critical_asset_always_review=settings.ai_review_critical_asset_always_review,
        max_raw_log_samples=settings.ai_review_max_raw_log_samples,
        max_context_tokens=settings.ai_review_max_context_tokens,
        max_output_tokens=settings.ai_review_max_output_tokens,
        max_tool_calls=settings.ai_review_max_tool_calls,
        max_model_runs_per_incident=settings.ai_review_max_model_runs_per_incident,
        max_reviews_per_minute=settings.ai_review_max_reviews_per_minute,
        max_cost_usd_per_incident=settings.ai_review_max_cost_usd_per_incident,
        provider_timeout_seconds=settings.ai_review_provider_timeout_seconds,
        provider_max_retries=settings.ai_review_provider_max_retries,
        circuit_failure_threshold=settings.ai_review_circuit_failure_threshold,
        circuit_recovery_seconds=settings.ai_review_circuit_recovery_seconds,
        tool_max_result_rows=settings.ai_review_tool_max_result_rows,
        tool_max_result_bytes=settings.ai_review_tool_max_result_bytes,
        verification_minimum_severity=IncidentSeverity(
            settings.ai_review_verification_minimum_severity
        ),
        verification_minimum_risk_score=settings.ai_review_verification_minimum_risk_score,
        verify_critical_asset=settings.ai_review_verify_critical_asset,
        verify_unsupported_claims=settings.ai_review_verify_unsupported_claims,
        verify_conflicting_evidence=settings.ai_review_verify_conflicting_evidence,
        verify_destructive_action=settings.ai_review_verify_destructive_action,
        max_verifier_slots=settings.ai_review_max_verifier_slots,
        adjudicator_enabled=settings.ai_review_adjudicator_enabled,
    )


def build_model_provider(settings: Settings) -> ModelProvider:
    api_key = settings.ai_review_api_key
    model_name = settings.ai_review_model_name
    if api_key is None or model_name is None:
        raise ValueError("AI review provider credentials are incomplete")
    common: dict[str, object] = {
        "api_key": api_key,
        "model_name": model_name,
        "context_tokens": settings.ai_review_model_context_tokens,
        "timeout_seconds": settings.ai_review_provider_timeout_seconds,
        "max_response_bytes": settings.ai_review_model_max_response_bytes,
        "input_cost_per_million_tokens": settings.ai_review_input_cost_per_million_tokens,
        "output_cost_per_million_tokens": settings.ai_review_output_cost_per_million_tokens,
    }
    if settings.ai_review_provider == "kimi":
        return KimiProvider(**common)  # type: ignore[arg-type]
    if settings.ai_review_provider == "glm":
        return GlmProvider(**common)  # type: ignore[arg-type]
    if settings.ai_review_provider in PROVIDER_PRESETS:
        return OpenAICompatibleProvider(
            OpenAICompatibleConfig.from_preset(
                settings.ai_review_provider,
                api_key=api_key,
                model_name=model_name,
                context_tokens=settings.ai_review_model_context_tokens,
                timeout_seconds=settings.ai_review_provider_timeout_seconds,
                max_response_bytes=settings.ai_review_model_max_response_bytes,
                input_cost_per_million_tokens=settings.ai_review_input_cost_per_million_tokens,
                output_cost_per_million_tokens=settings.ai_review_output_cost_per_million_tokens,
            )
        )
    if settings.ai_review_base_url is None:
        raise ValueError("OpenAI-compatible provider requires ai_review_base_url")
    return OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_name="openai_compatible",
            base_url=settings.ai_review_base_url,
            api_key=api_key,
            model_name=model_name,
            supports_tools=settings.ai_review_supports_tools,
            supports_json_schema=settings.ai_review_supports_json_schema,
            context_tokens=settings.ai_review_model_context_tokens,
            timeout_seconds=settings.ai_review_provider_timeout_seconds,
            max_response_bytes=settings.ai_review_model_max_response_bytes,
            input_cost_per_million_tokens=settings.ai_review_input_cost_per_million_tokens,
            output_cost_per_million_tokens=settings.ai_review_output_cost_per_million_tokens,
        )
    )


def build_ai_review_runtime(
    settings: Settings,
    *,
    provider: ModelProvider | None = None,
    verifier_providers: tuple[ModelProvider, ...] | None = None,
    adjudicator_provider: ModelProvider | None = None,
) -> AiReviewRuntime | None:
    if not settings.ai_review_enabled and provider is None:
        return None
    policy = ai_review_policy_from_settings(settings)
    actual_provider = provider or build_model_provider(settings)
    actual_verifiers = ((actual_provider,) if verifier_providers is None else verifier_providers)[
        : policy.max_verifier_slots
    ]
    actual_adjudicator = (
        adjudicator_provider
        if adjudicator_provider is not None
        else actual_provider
        if policy.adjudicator_enabled
        else None
    )
    return AiReviewRuntime(
        policy=policy,
        model_client=ResilientModelClient(actual_provider, policy),
        verifier_clients=tuple(ResilientModelClient(item, policy) for item in actual_verifiers),
        adjudicator_client=(
            ResilientModelClient(actual_adjudicator, policy)
            if actual_adjudicator is not None
            else None
        ),
        rate_limiter=ReviewRateLimiter(policy.max_reviews_per_minute),
    )


__all__ = [
    "AiReviewRuntime",
    "ai_review_policy_from_settings",
    "build_ai_review_runtime",
    "build_model_provider",
]
