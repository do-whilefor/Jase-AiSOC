"""Structured logging with context binding and sensitive-key redaction."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar, Token
from typing import Any, cast

import structlog

from aisoc.config import Settings

_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "database_url",
        "password",
        "secret",
        "token",
    }
)


def _redact_sensitive(
    _logger: object,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    for key in tuple(event_dict):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = "[REDACTED]"
    if trace_id := _trace_id.get():
        event_dict.setdefault("trace_id", trace_id)
    return event_dict


def configure_logging(settings: Settings) -> None:
    level = getattr(logging, settings.log_level)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level, force=True)

    renderer: structlog.types.Processor
    if settings.log_format == "console":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact_sensitive,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))


def bind_trace_id(value: str) -> Token[str | None]:
    return _trace_id.set(value)


def reset_trace_id(token: Token[str | None]) -> None:
    _trace_id.reset(token)
