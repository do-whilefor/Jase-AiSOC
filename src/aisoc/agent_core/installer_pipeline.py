"""Network-aware release pipeline: manifest preflight -> download -> verify -> install.

Glues :func:`aisoc.agent_core.downloader.download_payload` (allowlisted,
bounded HTTPS fetch) with :class:`ReleaseVerifier` and :class:`ReleaseInstaller` so an
Agent can apply a signed release from a URL without the caller re-implementing
the verify/health-gate/commit sequence. The pipeline never executes the payload
before verification and never skips the installer's health gate.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from aisoc.agent_core.downloader import download_payload
from aisoc.agent_core.installer import (
    InstalledRelease,
    ReleaseInstaller,
    ReleaseInstallResult,
)
from aisoc.agent_core.releases import ReleaseVerifier, SignedRelease


def install_release_from_url(
    *,
    url: str,
    download_allowed_hosts: tuple[str, ...],
    signed: SignedRelease,
    verifier: ReleaseVerifier,
    installer: ReleaseInstaller,
    health_check: Callable[[InstalledRelease], bool],
    download_client: httpx.Client | None = None,
    download_timeout_seconds: float = 60.0,
    now: datetime | None = None,
) -> ReleaseInstallResult:
    """Download, verify, and install a signed release in one transaction.

    The persisted release state is loaded fresh from ``installer.state_store``.
    Signature, key authority, target, validity, anti-rollback, and approval
    policy are checked before network I/O. The download is independently size
    bounded, then its SHA-256 is checked before the payload reaches the installer.
    """
    state = installer.state_store.load()
    verifier.preflight(signed, state, now=now)
    payload = download_payload(
        url,
        allowed_hosts=download_allowed_hosts,
        expected_sha256=signed.manifest.payload_sha256,
        expected_size=signed.manifest.payload_size,
        max_size=installer.config.max_payload_bytes,
        timeout_seconds=download_timeout_seconds,
        client=download_client,
    )
    verified = verifier.verify(signed, payload, state, now=now)
    return installer.install(
        verified,
        payload,
        verifier=verifier,
        health_check=health_check,
        now=now,
    )
