"""Unit tests for the release payload downloader and install-from-URL pipeline."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aisoc.agent_core.artifact_builder import build_signed_artifact
from aisoc.agent_core.downloader import DownloadError, download_payload
from aisoc.agent_core.installer import ReleaseInstaller, ReleaseInstallerConfig
from aisoc.agent_core.installer_pipeline import install_release_from_url
from aisoc.agent_core.releases import (
    ArtifactKind,
    ReleaseStateStore,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerificationError,
    ReleaseVerifier,
    SignedRelease,
)

URL = "https://artifact.test.example/agent.tar.gz"
ALLOWED_HOSTS = ("artifact.test.example",)


def _client(payload: bytes) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=payload))
    )


def test_download_payload_happy_path() -> None:
    payload = b"release payload bytes" * 16
    client = _client(payload)
    result = download_payload(
        URL,
        allowed_hosts=ALLOWED_HOSTS,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        expected_size=len(payload),
        client=client,
    )
    assert result == payload


def test_download_payload_rejects_sha256_mismatch() -> None:
    payload = b"tampered payload"
    client = _client(payload)
    with pytest.raises(DownloadError, match="sha256"):
        download_payload(
            URL,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256="0" * 64,
            expected_size=len(payload),
            client=client,
        )


def test_download_payload_rejects_size_mismatch() -> None:
    payload = b"short"
    client = _client(payload)
    with pytest.raises(DownloadError, match="size"):
        download_payload(
            URL,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size=100,
            client=client,
        )


def test_download_payload_aborts_when_trailer_exceeds_expected_size() -> None:
    payload = b"x" * 200
    client = _client(payload)
    with pytest.raises(DownloadError, match="exceeds the manifest size"):
        download_payload(
            URL,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size=50,
            client=client,
        )


def test_download_payload_wraps_http_errors() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    with pytest.raises(DownloadError):
        download_payload(
            URL,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256="0" * 64,
            expected_size=10,
            client=client,
        )


@pytest.mark.parametrize(
    ("url", "allowed_hosts"),
    [
        ("http://artifact.test.example/agent.tar.gz", ALLOWED_HOSTS),
        ("https://metadata.internal/agent.tar.gz", ALLOWED_HOSTS),
        (URL, ()),
        ("https://user:secret@artifact.test.example/agent.tar.gz", ALLOWED_HOSTS),
        (URL, ("Artifact.test.example",)),
        ("https://0.0.0.0/agent.tar.gz", ("0.0.0.0",)),
        ("https://[::1/agent.tar.gz", ("::1",)),
    ],
)
def test_download_payload_rejects_untrusted_destination(
    url: str,
    allowed_hosts: tuple[str, ...],
) -> None:
    with pytest.raises(DownloadError):
        download_payload(
            url,
            allowed_hosts=allowed_hosts,
            expected_sha256="0" * 64,
            expected_size=0,
            client=_client(b""),
        )


def test_download_payload_does_not_follow_redirect_or_echo_signed_url() -> None:
    signed_url = f"{URL}?signature=must-not-leak"
    client = httpx.Client(
        follow_redirects=True,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"Location": "https://metadata.internal/"})
        ),
    )
    with pytest.raises(DownloadError) as captured:
        download_payload(
            signed_url,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256="0" * 64,
            expected_size=0,
            client=client,
        )
    assert "must-not-leak" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_download_payload_rejects_manifest_size_above_bound_before_http() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=b"")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(DownloadError, match="download limit"):
        download_payload(
            URL,
            allowed_hosts=ALLOWED_HOSTS,
            expected_sha256="0" * 64,
            expected_size=11,
            max_size=10,
            client=client,
        )
    assert requests == 0


def _make_artifact(
    tmp_path: Path,
) -> tuple[bytes, SignedRelease, ReleaseVerifier, str, str]:
    source = tmp_path / "agent-root"
    (source / "bin").mkdir(parents=True)
    (source / "bin" / "aisoc-agent").write_text(
        "#!/bin/sh\nexec python -m aisoc.agent_core\n"
    )
    (source / "lib").mkdir(parents=True)
    (source / "lib" / "marker.txt").write_text("offline runtime marker\n")
    key = Ed25519PrivateKey.generate()
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(days=30)
    target = ReleaseTarget(operating_system="linux", architecture="x86_64", distro="debian")
    signed, payload = build_signed_artifact(
        source=source,
        private_key=key,
        key_id="release-agent-v1",
        artifact_id="agent-linux-x86_64",
        version="0.1.0",
        sequence=1,
        target=target,
        minimum_allowed_version="0.1.0",
        rollout_id="rollout-0.1.0",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    trust_key = ReleaseTrustKey(
        key_id="release-agent-v1",
        public_key=key.public_key(),
        allowed_kinds=frozenset({ArtifactKind.AGENT}),
    )
    verifier = ReleaseVerifier(
        trust_keys=(trust_key,),
        installation_id="inst_01JTESTINSTALL01",
        operating_system="linux",
        architecture="x86_64",
        distro="debian",
    )
    return payload, signed, verifier, "release-agent-v1", "agent-linux-x86_64"


def test_install_release_from_url_downloads_verifies_and_installs(tmp_path: Path) -> None:
    payload, signed, verifier, _key_id, artifact_id = _make_artifact(tmp_path)
    client = _client(payload)

    install_root = tmp_path / "install"
    state_root = tmp_path / "state"
    installer = ReleaseInstaller(
        ReleaseInstallerConfig(root=install_root),
        state_store=ReleaseStateStore(state_root),
    )

    result = install_release_from_url(
        url=URL,
        download_allowed_hosts=ALLOWED_HOSTS,
        signed=signed,
        verifier=verifier,
        installer=installer,
        health_check=lambda installed: True,
        download_client=client,
    )
    assert result.active.artifact_id == artifact_id
    assert installer.active_release(artifact_id) is not None


def test_install_release_from_url_rejects_tampered_download(tmp_path: Path) -> None:
    _payload, signed, verifier, _key_id, _artifact_id = _make_artifact(tmp_path)
    client = _client(b"completely different bytes")

    installer = ReleaseInstaller(
        ReleaseInstallerConfig(root=tmp_path / "install"),
        state_store=ReleaseStateStore(tmp_path / "state"),
    )

    with pytest.raises(DownloadError, match="does not match"):
        install_release_from_url(
            url=URL,
            download_allowed_hosts=ALLOWED_HOSTS,
            signed=signed,
            verifier=verifier,
            installer=installer,
            health_check=lambda installed: True,
            download_client=client,
        )
    assert installer.active_release("agent-linux-x86_64") is None


def test_install_release_from_url_rejects_manifest_before_http(tmp_path: Path) -> None:
    _payload, signed, verifier, _key_id, _artifact_id = _make_artifact(tmp_path)
    forged = signed.model_copy(update={"signature": "A" * 86})
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=b"untrusted")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    installer = ReleaseInstaller(
        ReleaseInstallerConfig(root=tmp_path / "install"),
        state_store=ReleaseStateStore(tmp_path / "state"),
    )

    with pytest.raises(ReleaseVerificationError, match="signature"):
        install_release_from_url(
            url=URL,
            download_allowed_hosts=ALLOWED_HOSTS,
            signed=forged,
            verifier=verifier,
            installer=installer,
            health_check=lambda installed: True,
            download_client=client,
        )
    assert requests == 0
