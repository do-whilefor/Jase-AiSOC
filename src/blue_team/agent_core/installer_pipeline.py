"""Network-aware release pipeline: download -> verify -> install.

Glues :func:`blue_team.agent_core.downloader.download_payload` (integrity-checked
HTTPS fetch) with :class:`ReleaseVerifier` and :class:`ReleaseInstaller` so an
Agent can apply a signed release from a URL without the caller re-implementing
the verify/health-gate/commit sequence. The pipeline never executes the payload
before verification and never skips the installer's health gate.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from blue_team.agent_core.downloader import download_payload
from blue_team.agent_core.installer import (
    InstalledRelease,
    ReleaseInstaller,
    ReleaseInstallResult,
)
from blue_team.agent_core.releases import ReleaseVerifier, SignedRelease


def install_release_from_url(
    *,
    url: str,
    signed: SignedRelease,
    verifier: ReleaseVerifier,
    installer: ReleaseInstaller,
    health_check: Callable[[InstalledRelease], bool],
    download_client: httpx.Client | None = None,
    download_timeout_seconds: float = 60.0,
    now: datetime | None = None,
) -> ReleaseInstallResult:
    """Download, verify, and install a signed release in one transaction.

    The persisted release state is loaded fresh from ``installer.state_store``
    so the verification revision matches what the installer will commit. The
    download is aborted early if the trailer exceeds the manifest size, and the
    SHA-256 is checked before the payload reaches the installer.
    """
    state = installer.state_store.load()
    payload = download_payload(
        url,
        expected_sha256=signed.manifest.payload_sha256,
        expected_size=signed.manifest.payload_size,
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
