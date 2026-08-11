"""Allowlisted streamed download of a signed Agent release payload.

The downloader is the network leg of the release pipeline: it fetches bytes
only from an exact allowlisted HTTPS artifact source, rejects redirects and
payloads that exceed either the manifest or deployment bound, and verifies the
SHA-256 before returning the payload to
``ReleaseVerifier.verify`` + ``ReleaseInstaller.install``. It never executes
or parses the payload.
"""

from __future__ import annotations

import hashlib
from ipaddress import ip_address
from urllib.parse import urlsplit

import httpx


class DownloadError(RuntimeError):
    """Raised when a release payload download fails integrity or transport checks."""


def download_payload(
    url: str,
    *,
    allowed_hosts: tuple[str, ...],
    expected_sha256: str,
    expected_size: int,
    max_size: int = 512 * 1024 * 1024,
    timeout_seconds: float = 60.0,
    client: httpx.Client | None = None,
) -> bytes:
    """Download ``url`` and verify its size and SHA-256 against the manifest.

    The download is streamed in 64 KiB chunks; if the manifest or running total
    exceeds ``max_size``/``expected_size`` the request is rejected or aborted
    immediately to bound memory. ``allowed_hosts`` is an exact normalized
    destination allowlist. A ``client`` can be injected for tests
    (e.g. ``httpx.MockTransport``); when omitted a short-lived client is created.
    """
    _validate_artifact_url(url, allowed_hosts=allowed_hosts)
    if expected_size < 0:
        raise DownloadError("expected_size must be non-negative")
    if max_size < 1 or max_size > 4 * 1024**3:
        raise DownloadError("max_size is outside the supported range")
    if expected_size > max_size:
        raise DownloadError("manifest payload size exceeds the configured download limit")
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise DownloadError("expected_sha256 must be a lowercase SHA-256 digest")
    digest = hashlib.sha256()
    chunks = bytearray()
    owns_client = client is None
    transport_client = client or httpx.Client(
        timeout=timeout_seconds,
        trust_env=False,
        follow_redirects=False,
    )
    try:
        try:
            with transport_client.stream("GET", url, follow_redirects=False) as response:
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
        except httpx.HTTPError:
            # HTTPX exceptions retain the request URL, which may carry a
            # short-lived signature in its query string. Do not chain it into
            # logs or API errors.
            raise DownloadError("release payload download failed") from None
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


def _validate_artifact_url(url: str, *, allowed_hosts: tuple[str, ...]) -> None:
    if not url or len(url) > 4096:
        raise DownloadError("release payload URL is empty or too long")
    if not allowed_hosts:
        raise DownloadError("release payload host allowlist cannot be empty")
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise DownloadError("release payload URL authority is invalid") from None
    if parts.scheme != "https":
        raise DownloadError("release payload URL must use HTTPS")
    if parts.username is not None or parts.password is not None:
        raise DownloadError("release payload URL cannot contain user information")
    if parts.fragment:
        raise DownloadError("release payload URL cannot contain a fragment")
    if not hostname:
        raise DownloadError("release payload URL must include a host")
    if port == 0:
        raise DownloadError("release payload URL port is invalid")
    host = _normalize_host(hostname)
    normalized_allowed = tuple(_normalize_host(value) for value in allowed_hosts)
    if (
        allowed_hosts != normalized_allowed
        or tuple(sorted(set(normalized_allowed))) != allowed_hosts
    ):
        raise DownloadError("release payload allowed_hosts must be normalized, sorted, and unique")
    if host not in normalized_allowed:
        raise DownloadError("release payload URL host is not allowlisted")


def _normalize_host(host: str) -> str:
    value = host.strip().rstrip(".")
    if not value or any(character in value for character in "/\\@#?%\x00\r\n\t"):
        raise DownloadError("release payload host is invalid")
    try:
        address = ip_address(value)
    except ValueError:
        try:
            normalized = value.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise DownloadError("release payload host is invalid") from error
        labels = normalized.split(".")
        if (
            len(normalized) > 253
            or any(
                not label
                or len(label) > 63
                or label[0] == "-"
                or label[-1] == "-"
                or not all(character.isalnum() or character == "-" for character in label)
                for label in labels
            )
        ):
            raise DownloadError("release payload host is invalid")
        return normalized
    if address.is_unspecified:
        raise DownloadError("release payload host is invalid")
    return address.compressed
