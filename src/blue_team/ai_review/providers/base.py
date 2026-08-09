"""Provider-neutral P7 model interface and failure taxonomy."""

from __future__ import annotations

from typing import Protocol

from blue_team.domain.ai_review import (
    ModelCapabilities,
    ModelHealth,
    ModelRequest,
    ModelResponse,
)


class ModelProviderError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


class ModelProvider(Protocol):
    @property
    def provider_name(self) -> str: ...

    @property
    def model_name(self) -> str: ...

    def capabilities(self) -> ModelCapabilities: ...

    async def health(self) -> ModelHealth: ...

    async def complete(self, request: ModelRequest) -> ModelResponse: ...


__all__ = ["ModelProvider", "ModelProviderError"]
