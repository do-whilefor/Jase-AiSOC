"""OpenAI-compatible provider used by Kimi, GLM, vLLM, and custom HTTP."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, Self
from urllib.parse import urlparse

import aiohttp
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from aisoc._rustcore import sha256_hex
from aisoc.ai_review.providers.base import ModelProviderError
from aisoc.domain.ai_review import (
    ModelCapabilities,
    ModelHealth,
    ModelHealthStatus,
    ModelRequest,
    ModelResponse,
    ModelToolCall,
    ModelUsage,
)


class JsonHttpTransport(Protocol):
    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[int, dict[str, object]]: ...

    async def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[int, dict[str, object]]: ...


class AioHttpJsonTransport:
    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object] | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[int, dict[str, object]]:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with (
            aiohttp.ClientSession(timeout=timeout) as session,
            session.request(
                method,
                url,
                headers=headers,
                json=payload,
                allow_redirects=False,
            ) as response,
        ):
            try:
                body = await response.content.readexactly(max_response_bytes + 1)
            except asyncio.IncompleteReadError as error:
                body = error.partial
            if len(body) > max_response_bytes:
                raise ModelProviderError(
                    "provider response exceeded the configured byte limit",
                    retryable=False,
                )
            try:
                decoded = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ModelProviderError(
                    "provider returned a non-JSON response", retryable=False
                ) from error
            if not isinstance(decoded, dict):
                raise ModelProviderError(
                    "provider response root must be an object", retryable=False
                )
            return response.status, decoded

    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[int, dict[str, object]]:
        return await self._request(
            "GET",
            url,
            headers=headers,
            payload=None,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    async def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[int, dict[str, object]]:
        return await self._request(
            "POST",
            url,
            headers=headers,
            payload=payload,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )


class OpenAICompatibleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    provider_name: str = Field(min_length=1, max_length=64)
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: SecretStr
    model_name: str = Field(min_length=1, max_length=128)
    completion_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    supports_tools: bool = True
    supports_json_schema: bool = True
    supports_stream: bool = False
    context_tokens: int = Field(default=32_000, ge=1)
    timeout_seconds: float = Field(default=30.0, ge=0.1, le=600.0)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=20 * 1024 * 1024)
    input_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)
    output_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)

    @field_validator("base_url")
    @classmethod
    def require_safe_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain query or fragment components")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("plain HTTP is allowed only for a loopback local provider")
        return value.rstrip("/")

    @field_validator("completion_path", "models_path")
    @classmethod
    def require_relative_api_path(cls, value: str) -> str:
        parsed = urlparse(value)
        if not value.startswith("/") or parsed.scheme or parsed.netloc:
            raise ValueError("provider API paths must start with one slash")
        if parsed.query or parsed.fragment or ".." in parsed.path.split("/"):
            raise ValueError("provider API paths must not contain traversal, query, or fragment")
        return "/" + value.lstrip("/")

    @model_validator(mode="after")
    def require_nonempty_secret(self) -> Self:
        if not self.api_key.get_secret_value():
            raise ValueError("api_key cannot be empty")
        return self

    @classmethod
    def from_preset(
        cls,
        preset_name: str,
        *,
        api_key: SecretStr,
        model_name: str,
        context_tokens: int,
        timeout_seconds: float,
        max_response_bytes: int,
        input_cost_per_million_tokens: float,
        output_cost_per_million_tokens: float,
    ) -> OpenAICompatibleConfig:
        """Build a config from a fixed-base :data:`PROVIDER_PRESETS` entry.

        Centralizes the base_url/completion_path/models_path/capability data so
        adding a new fixed-base provider is one preset entry plus one thin
        subclass, rather than data duplicated across files. ``"openai_compatible"``
        is not a preset — it uses a caller-supplied ``base_url``.
        """
        if preset_name not in PROVIDER_PRESETS:
            raise ValueError(f"unknown model provider preset: {preset_name!r}")
        preset = PROVIDER_PRESETS[preset_name]
        return cls(
            provider_name=preset.provider_name,
            base_url=preset.base_url,
            api_key=api_key,
            model_name=model_name,
            completion_path=preset.completion_path,
            models_path=preset.models_path,
            supports_tools=preset.supports_tools,
            supports_json_schema=preset.supports_json_schema,
            context_tokens=context_tokens,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            input_cost_per_million_tokens=input_cost_per_million_tokens,
            output_cost_per_million_tokens=output_cost_per_million_tokens,
        )


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """Fixed-base provider endpoint and capability data (no secrets)."""

    provider_name: str
    base_url: str
    completion_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    supports_tools: bool = True
    supports_json_schema: bool = True


PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "kimi": ProviderPreset(
        "kimi",
        "https://api.moonshot.cn",
        supports_json_schema=False,
    ),
    "glm": ProviderPreset(
        "glm",
        "https://open.bigmodel.cn/api/paas/v4",
        completion_path="/chat/completions",
        models_path="/models",
        supports_json_schema=False,
    ),
    "deepseek": ProviderPreset(
        "deepseek",
        "https://api.deepseek.com",
        completion_path="/chat/completions",
        models_path="/models",
        supports_json_schema=False,
    ),
    # OpenAI's base_url already carries the /v1 version prefix, so the API paths
    # must NOT repeat it (else the joined URL becomes .../v1/v1/chat/completions).
    "openai": ProviderPreset(
        "openai",
        "https://api.openai.com/v1",
        completion_path="/chat/completions",
        models_path="/models",
    ),
}


class OpenAICompatibleProvider:
    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        transport: JsonHttpTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport or AioHttpJsonTransport()

    @property
    def provider_name(self) -> str:
        return self._config.provider_name

    @property
    def model_name(self) -> str:
        return self._config.model_name

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            tools=self._config.supports_tools,
            json_schema=self._config.supports_json_schema,
            stream=self._config.supports_stream,
            context_tokens=self._config.context_tokens,
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._config.api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def health(self) -> ModelHealth:
        try:
            status, _ = await self._transport.get_json(
                f"{self._config.base_url}{self._config.models_path}",
                headers=self._headers(),
                timeout_seconds=self._config.timeout_seconds,
                max_response_bytes=self._config.max_response_bytes,
            )
        except Exception as error:
            return ModelHealth(
                status=ModelHealthStatus.UNAVAILABLE,
                provider=self.provider_name,
                model=self.model_name,
                detail=type(error).__name__,
                checked_at=datetime.now(UTC),
            )
        return ModelHealth(
            status=(
                ModelHealthStatus.AVAILABLE
                if 200 <= status < 300
                else ModelHealthStatus.UNAVAILABLE
            ),
            provider=self.provider_name,
            model=self.model_name,
            detail=None if 200 <= status < 300 else f"HTTP {status}",
            checked_at=datetime.now(UTC),
        )

    async def complete(self, request: ModelRequest) -> ModelResponse:
        payload = self._request_payload(request)
        status, body = await self._transport.post_json(
            f"{self._config.base_url}{self._config.completion_path}",
            headers=self._headers(),
            payload=payload,
            timeout_seconds=self._config.timeout_seconds,
            max_response_bytes=self._config.max_response_bytes,
        )
        if not 200 <= status < 300:
            raise ModelProviderError(
                f"provider returned HTTP {status}",
                retryable=status == 429 or status >= 500,
            )
        return self._parse_response(body)

    def _request_payload(self, request: ModelRequest) -> dict[str, object]:
        schema_text = json.dumps(
            request.output_schema,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        trusted_instructions = (
            request.trusted_system_instructions
            + "\nRequired output JSON Schema (trusted configuration):\n"
            + schema_text
        )
        untrusted_input = json.dumps(
            request.input.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": trusted_instructions},
                {"role": "user", "content": untrusted_input},
            ],
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
        }
        if self._config.supports_json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "analyzer_report",
                    "strict": True,
                    "schema": request.output_schema,
                },
            }
        else:
            payload["response_format"] = {"type": "json_object"}
        if request.tools and self._config.supports_tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": item.name,
                        "description": item.description,
                        "parameters": item.input_schema,
                    },
                }
                for item in request.tools
            ]
            payload["tool_choice"] = "auto"
        return payload

    def _parse_response(self, body: dict[str, object]) -> ModelResponse:
        try:
            choices = body["choices"]
            if not isinstance(choices, list) or not choices:
                raise TypeError("choices")
            choice = choices[0]
            if not isinstance(choice, dict):
                raise TypeError("choice")
            message = choice["message"]
            if not isinstance(message, dict):
                raise TypeError("message")
            structured = self._structured_content(message.get("content"))
            tool_calls = self._tool_calls(message.get("tool_calls"))
            usage_raw = body.get("usage", {})
            if not isinstance(usage_raw, dict):
                raise TypeError("usage")
            input_tokens = self._nonnegative_int(usage_raw.get("prompt_tokens", 0))
            output_tokens = self._nonnegative_int(usage_raw.get("completion_tokens", 0))
            finish_reason = str(choice.get("finish_reason") or "stop")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ModelProviderError(
                "provider response did not match the OpenAI-compatible contract",
                retryable=False,
            ) from error
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        cost = (
            input_tokens * self._config.input_cost_per_million_tokens
            + output_tokens * self._config.output_cost_per_million_tokens
        ) / 1_000_000
        return ModelResponse(
            structured_output=structured,
            tool_calls=tool_calls,
            usage=ModelUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost,
            ),
            finish_reason=finish_reason,
            response_sha256=sha256_hex(canonical.encode()),
        )

    @staticmethod
    def _structured_content(value: object) -> dict[str, object] | None:
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise TypeError("message content")
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise TypeError("structured output")
        return decoded

    @staticmethod
    def _tool_calls(value: object) -> tuple[ModelToolCall, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise TypeError("tool_calls")
        calls: list[ModelToolCall] = []
        for raw in value:
            if not isinstance(raw, dict) or not isinstance(raw.get("function"), dict):
                raise TypeError("tool_call")
            function = raw["function"]
            arguments = json.loads(str(function.get("arguments", "{}")))
            if not isinstance(arguments, dict):
                raise TypeError("tool arguments")
            calls.append(
                ModelToolCall(
                    call_id=str(raw.get("id", "")),
                    name=str(function.get("name", "")),
                    arguments=arguments,
                )
            )
        return tuple(calls)

    @staticmethod
    def _nonnegative_int(value: object) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise TypeError("token usage")
        return value


class KimiProvider(OpenAICompatibleProvider):
    def __init__(
        self,
        *,
        api_key: SecretStr,
        model_name: str,
        transport: JsonHttpTransport | None = None,
        context_tokens: int = 32_000,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        input_cost_per_million_tokens: float = 0.0,
        output_cost_per_million_tokens: float = 0.0,
    ) -> None:
        super().__init__(
            OpenAICompatibleConfig.from_preset(
                "kimi",
                api_key=api_key,
                model_name=model_name,
                context_tokens=context_tokens,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                input_cost_per_million_tokens=input_cost_per_million_tokens,
                output_cost_per_million_tokens=output_cost_per_million_tokens,
            ),
            transport=transport,
        )


class GlmProvider(OpenAICompatibleProvider):
    def __init__(
        self,
        *,
        api_key: SecretStr,
        model_name: str,
        transport: JsonHttpTransport | None = None,
        context_tokens: int = 32_000,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        input_cost_per_million_tokens: float = 0.0,
        output_cost_per_million_tokens: float = 0.0,
    ) -> None:
        super().__init__(
            OpenAICompatibleConfig.from_preset(
                "glm",
                api_key=api_key,
                model_name=model_name,
                context_tokens=context_tokens,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                input_cost_per_million_tokens=input_cost_per_million_tokens,
                output_cost_per_million_tokens=output_cost_per_million_tokens,
            ),
            transport=transport,
        )


class DeepSeekProvider(OpenAICompatibleProvider):
    """DeepSeek (``https://api.deepseek.com``) OpenAI-compatible adapter."""

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model_name: str,
        transport: JsonHttpTransport | None = None,
        context_tokens: int = 32_000,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        input_cost_per_million_tokens: float = 0.0,
        output_cost_per_million_tokens: float = 0.0,
    ) -> None:
        super().__init__(
            OpenAICompatibleConfig.from_preset(
                "deepseek",
                api_key=api_key,
                model_name=model_name,
                context_tokens=context_tokens,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                input_cost_per_million_tokens=input_cost_per_million_tokens,
                output_cost_per_million_tokens=output_cost_per_million_tokens,
            ),
            transport=transport,
        )


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI official (``https://api.openai.com/v1``) adapter."""

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model_name: str,
        transport: JsonHttpTransport | None = None,
        context_tokens: int = 32_000,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        input_cost_per_million_tokens: float = 0.0,
        output_cost_per_million_tokens: float = 0.0,
    ) -> None:
        super().__init__(
            OpenAICompatibleConfig.from_preset(
                "openai",
                api_key=api_key,
                model_name=model_name,
                context_tokens=context_tokens,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                input_cost_per_million_tokens=input_cost_per_million_tokens,
                output_cost_per_million_tokens=output_cost_per_million_tokens,
            ),
            transport=transport,
        )


__all__ = [
    "PROVIDER_PRESETS",
    "AioHttpJsonTransport",
    "DeepSeekProvider",
    "GlmProvider",
    "JsonHttpTransport",
    "KimiProvider",
    "OpenAICompatibleConfig",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "ProviderPreset",
]
