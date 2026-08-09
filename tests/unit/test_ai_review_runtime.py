"""P7 optional runtime and provider configuration tests."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import SecretStr

from blue_team.ai_review.providers import (
    GlmProvider,
    KimiProvider,
    OpenAICompatibleProvider,
)
from blue_team.ai_review.runtime import (
    ai_review_policy_from_settings,
    build_ai_review_runtime,
    build_model_provider,
)
from blue_team.config import Settings
from blue_team.domain import (
    ModelCapabilities,
    ModelHealth,
    ModelHealthStatus,
    ModelRequest,
    ModelResponse,
)


class InjectedProvider:
    @property
    def provider_name(self) -> str:
        return "injected"

    @property
    def model_name(self) -> str:
        return "injected-model"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            tools=True,
            json_schema=True,
            stream=False,
            context_tokens=32_000,
        )

    async def health(self) -> ModelHealth:
        return ModelHealth(
            status=ModelHealthStatus.AVAILABLE,
            provider=self.provider_name,
            model=self.model_name,
            checked_at=datetime.now(UTC),
        )

    async def complete(self, request: ModelRequest) -> ModelResponse:
        del request
        raise AssertionError("not called by runtime construction")


def test_disabled_runtime_constructs_no_provider_or_client() -> None:
    assert build_ai_review_runtime(Settings()) is None


def test_injected_provider_can_enable_test_runtime_without_credentials() -> None:
    settings = Settings(
        ai_review_max_reviews_per_minute=7,
        ai_review_max_tool_calls=3,
    )

    runtime = build_ai_review_runtime(settings, provider=InjectedProvider())

    assert runtime is not None
    assert runtime.policy.max_reviews_per_minute == 7
    assert runtime.policy.max_tool_calls == 3
    assert runtime.model_client.provider.provider_name == "injected"
    assert len(runtime.verifier_clients) == 1
    assert runtime.verifier_clients[0].provider.provider_name == "injected"
    assert runtime.adjudicator_client is not None
    assert runtime.adjudicator_client.provider.provider_name == "injected"


def test_settings_map_to_policy_without_changing_authoritative_defaults() -> None:
    policy = ai_review_policy_from_settings(Settings())

    assert policy.max_raw_log_samples == 20
    assert policy.max_context_tokens == 16_000
    assert policy.max_tool_calls == 8
    assert policy.max_model_runs_per_incident == 3
    assert policy.max_reviews_per_minute == 30
    assert policy.verification_minimum_severity.value == "high"
    assert policy.verification_minimum_risk_score == 80
    assert policy.max_verifier_slots == 1


def test_provider_factory_selects_custom_kimi_and_glm_adapters() -> None:
    custom = build_model_provider(
        Settings(
            ai_review_enabled=True,
            ai_review_api_key=SecretStr("provider-key"),
            ai_review_model_name="model",
            ai_review_provider="openai_compatible",
            ai_review_base_url="https://model.example",
        )
    )
    kimi = build_model_provider(
        Settings(
            ai_review_enabled=True,
            ai_review_api_key=SecretStr("provider-key"),
            ai_review_model_name="model",
            ai_review_provider="kimi",
        )
    )
    glm = build_model_provider(
        Settings(
            ai_review_enabled=True,
            ai_review_api_key=SecretStr("provider-key"),
            ai_review_model_name="model",
            ai_review_provider="glm",
        )
    )

    assert isinstance(custom, OpenAICompatibleProvider)
    assert custom.provider_name == "openai_compatible"
    assert isinstance(kimi, KimiProvider)
    assert kimi.provider_name == "kimi"
    assert isinstance(glm, GlmProvider)
    assert glm.provider_name == "glm"
