"""Timeout, retry, and circuit-breaker wrapper for one provider slot."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aisoc.ai_review.providers.base import ModelProvider, ModelProviderError
from aisoc.domain.ai_review import AiReviewPolicy, ModelRequest, ModelResponse


class ProviderCallFailed(RuntimeError):
    def __init__(self, reason: str, *, retry_count: int, latency_ms: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_count = retry_count
        self.latency_ms = latency_ms


class CircuitOpenError(ProviderCallFailed):
    pass


@dataclass(frozen=True, slots=True)
class ProviderCallResult:
    response: ModelResponse
    retry_count: int
    latency_ms: int


class ResilientModelClient:
    def __init__(
        self,
        provider: ModelProvider,
        policy: AiReviewPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._provider = provider
        self._policy = policy
        self._clock = clock
        self._sleep = sleep
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    @property
    def provider(self) -> ModelProvider:
        return self._provider

    async def complete(self, request: ModelRequest) -> ProviderCallResult:
        now = self._clock()
        if self._opened_at is not None:
            if now - self._opened_at < self._policy.circuit_recovery_seconds:
                raise CircuitOpenError(
                    "circuit_open",
                    retry_count=0,
                    latency_ms=0,
                )
            self._opened_at = None
            self._consecutive_failures = 0

        started = self._clock()
        retries = 0
        while True:
            try:
                response = await asyncio.wait_for(
                    self._provider.complete(request),
                    timeout=self._policy.provider_timeout_seconds,
                )
            except TimeoutError as error:
                retryable = True
                last_error: Exception = error
            except ModelProviderError as error:
                retryable = error.retryable
                last_error = error
            except Exception as error:
                retryable = False
                last_error = error
            else:
                self._consecutive_failures = 0
                self._opened_at = None
                return ProviderCallResult(
                    response=response,
                    retry_count=retries,
                    latency_ms=max(0, round((self._clock() - started) * 1000)),
                )

            self._consecutive_failures += 1
            if self._consecutive_failures >= self._policy.circuit_failure_threshold:
                self._opened_at = self._clock()
            if not retryable or retries >= self._policy.provider_max_retries:
                raise ProviderCallFailed(
                    type(last_error).__name__,
                    retry_count=retries,
                    latency_ms=max(0, round((self._clock() - started) * 1000)),
                ) from None
            retries += 1
            await self._sleep(min(2.0, 0.1 * (2 ** (retries - 1))))


__all__ = [
    "CircuitOpenError",
    "ProviderCallFailed",
    "ProviderCallResult",
    "ResilientModelClient",
]
