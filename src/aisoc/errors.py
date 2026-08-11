"""Application errors that cross service and HTTP boundaries predictably."""

from __future__ import annotations

from http import HTTPStatus


class AppError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


class NotFoundError(AppError):
    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(
            "not_found",
            f"{resource} was not found",
            status_code=HTTPStatus.NOT_FOUND,
            details={"resource": resource, "resource_id": resource_id},
        )


class ConflictError(AppError):
    def __init__(self, resource: str, field: str) -> None:
        super().__init__(
            "conflict",
            f"{resource} already exists",
            status_code=HTTPStatus.CONFLICT,
            details={"resource": resource, "field": field},
        )


class StateConflictError(AppError):
    def __init__(self, resource: str, resource_id: str, reason: str) -> None:
        super().__init__(
            "state_conflict",
            f"{resource} is not in a valid state for this operation",
            status_code=HTTPStatus.CONFLICT,
            details={
                "resource": resource,
                "resource_id": resource_id,
                "reason": reason,
            },
        )


class AuthenticationError(AppError):
    def __init__(self, message: str = "authentication is required") -> None:
        super().__init__(
            "authentication_required",
            message,
            status_code=HTTPStatus.UNAUTHORIZED,
        )


class AuthorizationError(AppError):
    def __init__(self, message: str = "operation is not permitted") -> None:
        super().__init__(
            "forbidden",
            message,
            status_code=HTTPStatus.FORBIDDEN,
        )


class ServiceUnavailableError(AppError):
    def __init__(self, component: str) -> None:
        super().__init__(
            "service_unavailable",
            f"{component} is unavailable",
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            details={"component": component},
        )


class EvidenceIntegrityError(AppError):
    def __init__(self, evidence_ref: str) -> None:
        super().__init__(
            "evidence_integrity_failed",
            "stored evidence failed its integrity check",
            status_code=HTTPStatus.CONFLICT,
            details={"evidence_ref": evidence_ref},
        )


class SampleIntegrityError(AppError):
    def __init__(self, sample_ref: str) -> None:
        super().__init__(
            "sample_integrity_failed",
            "quarantined sample failed authenticated decryption or integrity validation",
            status_code=HTTPStatus.CONFLICT,
            details={"sample_ref": sample_ref},
        )


class PayloadTooLargeError(AppError):
    def __init__(self, *, maximum_bytes: int) -> None:
        super().__init__(
            "payload_too_large",
            "request body exceeds the configured size limit",
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            details={"maximum_bytes": maximum_bytes},
        )


class InvalidRequestError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(
            "invalid_request",
            message,
            status_code=HTTPStatus.BAD_REQUEST,
        )
