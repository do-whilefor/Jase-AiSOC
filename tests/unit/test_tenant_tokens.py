from __future__ import annotations

from aisoc.api_server.tenant_tokens import (
    credential_id_from_token,
    issue_tenant_token,
    token_matches,
)


def test_issued_tenant_token_can_be_looked_up_and_verified() -> None:
    issued = issue_tenant_token("cred_0123456789abcdef0123456789abcdef")

    assert credential_id_from_token(issued.value) == issued.credential_id
    assert token_matches(issued.value, issued.token_digest)
    assert issued.value not in repr(issued)


def test_malformed_or_modified_tenant_tokens_are_rejected() -> None:
    issued = issue_tenant_token("cred_0123456789abcdef0123456789abcdef")

    assert credential_id_from_token("not-a-token") is None
    assert credential_id_from_token("cred_0123456789abcdef0123456789abcdef.short") is None
    assert not token_matches(f"{issued.value}x", issued.token_digest)
