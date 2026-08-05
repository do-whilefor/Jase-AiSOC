"""Streamed download of a signed Agent release payload with integrity checks.

The downloader is the network leg of the release pipeline: it fetches bytes
from an HTTPS artifact source, rejects trailers that exceed the manifest size,
and verifies the SHA-256 before returning the payload to
``ReleaseVerifier.verify`` + ``ReleaseInstaller.install``. It never executes
or parses the payload.
"""

from __future__ import annotations

import hashlib

import httpx


class DownloadError(RuntimeError):
    """Raised when a release payload download fails integrity or transport checks."""


def download_payload(
    url: str,
    *,
    expected_sha256: str,
    expected_size: int,
    timeout_seconds: float = 60.0,
    client: httpx.Client | None = None,
) -> bytes:
    """Download ``url`` and verify its size and SHA-256 against the manifest.

    The download is streamed in 64 KiB chunks; if the running total exceeds
    ``expected_size`` the connection is aborted immediately to bound memory and
    reject zip-bomb-style payloads. A ``client`` can be injected for tests
    (e.g. ``httpx.MockTransport``); when omitted a short-lived client is created.
    """
    if expected_size < 0:
        raise DownloadError("expected_size must be non-negative")
    digest = hashlib.sha256()
    chunks = bytearray()
    owns_client = client is None
    transport_client = client or httpx.Client(timeout=timeout_seconds)
    try:
        try:
            with transport_client.stream("GET", url) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes(chunk_size=65536):
                    if not chunk:
                        continue
                    digest.update(chunk)
                    chunks.extend(chunk)
                    if len(chunks) > expected_size:
                        raise DownloadError(
                            "downloaded payload exceeds the manifest size before completion"
                        )
        except httpx.HTTPError as error:
            raise DownloadError(f"release payload download from {url} failed") from error
    finally:
        if owns_client:
            transport_client.close()

    payload = bytes(chunks)
    if len(payload) != expected_size:
        raise DownloadError(
            f"downloaded payload size {len(payload)} does not match manifest {expected_size}"
        )
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise DownloadError("downloaded payload sha256 does not match the manifest")
    return payload
