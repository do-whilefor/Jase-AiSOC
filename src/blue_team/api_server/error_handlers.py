"""Stable JSON error envelope without stack or secret disclosure."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from blue_team.errors import AppError
from blue_team.observability import get_logger

logger = get_logger(__name__)


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    trace_id: str
    details: dict[str, object] | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


def _trace_id(request: Request) -> str:
    value: str = request.state.trace_id
    return value


def _redact_details(details: dict[str, object] | None) -> dict[str, object] | None:
    """Strip internal quarantine:// references from error details.

    ``quarantine://`` refs are internal storage pointers that must never be
    exposed through a public API response. This is a defense-in-depth scrub:
    no current request path raises a ref-bearing error, but this prevents a
    future regression from leaking the ref.
    """
    if details is None:
        return None
    redacted: dict[str, object] = {}
    for key, value in details.items():
        if isinstance(value, str) and value.startswith("quarantine://"):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, error: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content=ErrorResponse(
                error=ErrorBody(
                    code=error.code,
                    message=error.message,
                    trace_id=_trace_id(request),
                    details=_redact_details(error.details),
                )
            ).model_dump(mode="json"),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        fields: list[dict[str, object]] = [
            {
                "location": [str(part) for part in item["loc"]],
                "message": item["msg"],
                "type": item["type"],
            }
            for item in error.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=ErrorBody(
                    code="validation_error",
                    message="request validation failed",
                    trace_id=_trace_id(request),
                    details={"fields": fields},
                )
            ).model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, error: Exception) -> JSONResponse:
        logger.exception("unhandled_api_error", error_type=type(error).__name__)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error=ErrorBody(
                    code="internal_error",
                    message="an unexpected error occurred",
                    trace_id=_trace_id(request),
                )
            ).model_dump(mode="json"),
        )
