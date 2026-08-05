"""Unit tests for the release payload downloader and install-from-URL pipeline."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blue_team.agent_core.artifact_builder import build_signed_artifact
from blue_team.agent_core.downloader import DownloadError, download_payload
from blue_team.agent_core.installer import ReleaseInstaller, ReleaseInstallerConfig
from blue_team.agent_core.installer_pipeline import install_release_from_url
from blue_team.agent_core.releases import (
    ArtifactKind,
    ReleaseStateStore,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerifier,
)

URL = "https://artifact.test.example/agent.tar.gz"


def _client(payload: bytes) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=payload))
    )


def test_download_payload_happy_path() -> None:
    payload = b"release payload bytes" * 16
    client = _client(payload)
    result = download_payload(
        URL,
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
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            expected_size=50,
            client=client,
        )


def test_download_payload_wraps_http_errors() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    with pytest.raises(DownloadError):
        download_payload(URL, expected_sha256="0" * 64, expected_size=10, client=client)


def _make_artifact(tmp_path: Path) -> tuple[bytes, object, object, str, str]:
    source = tmp_path / "agent-root"
    (source / "bin").mkdir(parents=True)
    (source / "bin" / "blue-team-agent").write_text(
        "#!/bin/sh\nexec python -m blue_team.agent_core\n"
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
        signed=signed,  # type: ignore[arg-type]
        verifier=verifier,  # type: ignore[arg-type]
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
            signed=signed,  # type: ignore[arg-type]
            verifier=verifier,  # type: ignore[arg-type]
            installer=installer,
            health_check=lambda installed: True,
            download_client=client,
        )
    assert installer.active_release("agent-linux-x86_64") is None
