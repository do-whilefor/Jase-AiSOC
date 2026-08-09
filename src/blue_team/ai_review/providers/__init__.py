"""P7 model provider contracts and OpenAI-compatible adapters."""

from blue_team.ai_review.providers.base import ModelProvider, ModelProviderError
from blue_team.ai_review.providers.client import (
    CircuitOpenError,
    ProviderCallFailed,
    ProviderCallResult,
    ResilientModelClient,
)
from blue_team.ai_review.providers.openai_compatible import (
    GlmProvider,
    KimiProvider,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)

__all__ = [
    "CircuitOpenError",
    "GlmProvider",
    "KimiProvider",
    "ModelProvider",
    "ModelProviderError",
    "OpenAICompatibleConfig",
    "OpenAICompatibleProvider",
    "ProviderCallFailed",
    "ProviderCallResult",
    "ResilientModelClient",
]
