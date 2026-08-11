"""Opaque, one-time Agent enrollment token primitives."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

from aisoc._rustcore import sha256_hex

_TOKEN_ID = re.compile(r"^enrtok_[a-f0-9]{32}$")
_TOKEN_SECRET = re.compile(r"^[A-Za-z0-9_-]{40,128}$")


@dataclass(frozen=True, slots=True)
class IssuedEnrollmentToken:
    token_id: str
    token_digest: str
    value: str = field(repr=False)


def issue_enrollment_token(token_id: str) -> IssuedEnrollmentToken:
    if _TOKEN_ID.fullmatch(token_id) is None:
        raise ValueError("invalid enrollment token identifier")
    value = f"{token_id}.{secrets.token_urlsafe(32)}"
    return IssuedEnrollmentToken(
        token_id=token_id,
        token_digest=enrollment_token_digest(value),
        value=value,
    )


def enrollment_token_id(value: str) -> str | None:
    token_id, separator, secret = value.partition(".")
    if (
        separator != "."
        or _TOKEN_ID.fullmatch(token_id) is None
        or _TOKEN_SECRET.fullmatch(secret) is None
    ):
        return None
    return token_id


def enrollment_token_matches(value: str, expected_digest: str) -> bool:
    return secrets.compare_digest(enrollment_token_digest(value), expected_digest)


def enrollment_token_digest(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))
