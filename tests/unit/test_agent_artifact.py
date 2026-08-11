"""Unit tests for the offline Agent artifact builder."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aisoc.agent_core.artifact_builder import (
    build_payload_tar,
    build_signed_artifact,
    default_validity,
)
from aisoc.agent_core.releases import (
    ArtifactKind,
    ReleaseDecisionStatus,
    ReleaseState,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerifier,
)


def _make_source(tmp_path: Path) -> Path:
    root = tmp_path / "agent-root"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "aisoc-agent").write_text(
        "#!/bin/sh\nexec python -m aisoc.agent_core\n"
    )
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "marker.txt").write_text("offline runtime marker\n")
    (root / "alembic.ini").write_text("[alembic]\nscript_location = migrations\n")
    return root


def test_build_payload_tar_rejects_symlinks(tmp_path: Path) -> None:
    source = _make_source(tmp_path)
    link = source / "lib" / "alias"
    link.symlink_to("../bin/aisoc-agent")
    with pytest.raises(ValueError, match="symlinks"):
        build_payload_tar(source)


def test_build_signed_artifact_verifies_with_release_verifier(tmp_path: Path) -> None:
    source = _make_source(tmp_path)
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

    assert signed.manifest.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert signed.manifest.payload_size == len(payload)
    assert signed.manifest.kind is ArtifactKind.AGENT
    assert signed.manifest.target.distro == "debian"

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
    verified = verifier.verify(signed, payload, ReleaseState())
    assert verified.status is ReleaseDecisionStatus.READY
    assert verified.manifest.artifact_id == "agent-linux-x86_64"


def test_default_validity_orders_expires_after_issued() -> None:
    now = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
    issued_at, expires_at = default_validity(now, days=10)
    assert issued_at == now
    assert expires_at == now + timedelta(days=10)
