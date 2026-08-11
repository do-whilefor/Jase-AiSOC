"""Opaque control-plane credential issuance and constant-time verification."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from aisoc._rustcore import secure_compare, sha256_hex

_CREDENTIAL_ID = re.compile(r"^cred_[a-f0-9]{32}$")
_TOKEN_SECRET = re.compile(r"^[A-Za-z0-9_-]{40,128}$")


@dataclass(frozen=True, slots=True)
class IssuedTenantToken:
    credential_id: str
    token_digest: str
    value: str = field(repr=False)


def issue_tenant_token(credential_id: str) -> IssuedTenantToken:
    """Create a high-entropy bearer token whose public prefix supports indexed lookup."""
    if _CREDENTIAL_ID.fullmatch(credential_id) is None:
        raise ValueError("invalid credential identifier")
    value = f"{credential_id}.{secrets.token_urlsafe(32)}"
    return IssuedTenantToken(
        credential_id=credential_id,
        token_digest=_digest(value),
        value=value,
    )


def credential_id_from_token(value: str) -> str | None:
    """Return a well-formed public credential ID without trusting the token secret."""
    credential_id, separator, secret = value.partition(".")
    if (
        separator != "."
        or _CREDENTIAL_ID.fullmatch(credential_id) is None
        or _TOKEN_SECRET.fullmatch(secret) is None
    ):
        return None
    return credential_id


def token_matches(value: str, expected_digest: str) -> bool:
    """Compare a presented bearer token with a stored SHA-256 digest."""
    return secure_compare(_digest(value), expected_digest)


def _digest(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))


__all__ = [
    "IssuedTenantToken",
    "credential_id_from_token",
    "issue_tenant_token",
    "token_matches",
]
