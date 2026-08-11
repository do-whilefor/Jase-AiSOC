"""Backward-compatible import surface for control-plane credential helpers."""

from aisoc.credentials import (
    IssuedTenantToken,
    credential_id_from_token,
    issue_tenant_token,
    token_matches,
)

__all__ = [
    "IssuedTenantToken",
    "credential_id_from_token",
    "issue_tenant_token",
    "token_matches",
]
