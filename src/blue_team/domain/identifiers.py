"""Shared identifier contracts for every control-plane and Agent boundary."""

from __future__ import annotations

import re
from typing import Annotated, Final

from pydantic import Field

TENANT_ID_PATTERN: Final = r"^ten_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$"
AGENT_ID_PATTERN: Final = r"^agent_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$"
HOST_ID_PATTERN: Final = r"^host_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$"
INSTALLATION_ID_PATTERN: Final = r"^inst_[A-Za-z0-9][A-Za-z0-9_-]{3,127}$"

TenantId = Annotated[str, Field(pattern=TENANT_ID_PATTERN)]
AgentId = Annotated[str, Field(pattern=AGENT_ID_PATTERN)]
HostId = Annotated[str, Field(pattern=HOST_ID_PATTERN)]
InstallationId = Annotated[str, Field(pattern=INSTALLATION_ID_PATTERN)]

_PATTERNS: Final = {
    "tenant_id": re.compile(TENANT_ID_PATTERN),
    "agent_id": re.compile(AGENT_ID_PATTERN),
    "host_id": re.compile(HOST_ID_PATTERN),
    "installation_id": re.compile(INSTALLATION_ID_PATTERN),
}


def is_valid_identifier(kind: str, value: str) -> bool:
    """Return whether *value* satisfies the named cross-service identifier contract."""
    try:
        pattern = _PATTERNS[kind]
    except KeyError as error:
        raise ValueError(f"unknown identifier kind: {kind}") from error
    return pattern.fullmatch(value) is not None
