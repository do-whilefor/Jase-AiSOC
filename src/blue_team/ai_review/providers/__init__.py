"""P7 model provider contracts and OpenAI-compatible adapters."""

from blue_team.ai_review.providers.base import ModelProvider, ModelProviderError
from blue_team.ai_review.providers.client import (
    CircuitOpenError,
    ProviderCallFailed,
    ProviderCallResult,
    ResilientModelClient,
)
from blue_team.ai_review.providers.openai_compatible import (
    PROVIDER_PRESETS,
    DeepSeekProvider,
    GlmProvider,
    KimiProvider,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
    OpenAIProvider,
    ProviderPreset,
)

__all__ = [
    "PROVIDER_PRESETS",
    "CircuitOpenError",
    "DeepSeekProvider",
    "GlmProvider",
    "KimiProvider",
    "ModelProvider",
    "ModelProviderError",
    "OpenAICompatibleConfig",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "ProviderCallFailed",
    "ProviderCallResult",
    "ProviderPreset",
    "ResilientModelClient",
]
