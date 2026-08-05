"""Assemble and sign a self-contained Agent release artifact.

This is the offline release tooling called by ``scripts/build_agent_artifact.py``.
It packs a source directory into a PAX ``tar.gz`` payload, builds a
``ReleaseManifest`` bound to a Linux target, and signs it with an Ed25519 key
via :func:`blue_team.agent_core.releases.sign_release`. The output is consumable
by ``ReleaseVerifier.verify`` + ``ReleaseInstaller.install``.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blue_team.agent_core.releases import (
    ArtifactKind,
    ReleaseManifest,
    ReleaseTarget,
    SignedRelease,
    sign_release,
)

_DEFAULT_VALIDITY_DAYS = 365
_MAX_MEMBERS = 4096
_MAX_MEMBER_SIZE = 256 * 1024 * 1024
_MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024


class ArtifactBuildError(ValueError):
    """Raised when the artifact source or signing inputs are invalid."""


def load_signing_key(key_path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file with basic safety checks."""
    if not key_path.is_file():
        raise ArtifactBuildError(f"signing key file not found: {key_path}")
    if os.name != "nt" and key_path.stat().st_mode & 0o077:
        raise ArtifactBuildError("signing key file must not be accessible by group or other users")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ArtifactBuildError("signing key must be an Ed25519 private key")
    return key


def build_payload_tar(source: Path) -> bytes:
    """Pack ``source`` into a deterministic-ish PAX ``tar.gz`` payload.

    Symlinks, device files, absolute paths, parent traversals and special files
    are rejected so the payload is safe for ``ReleaseInstaller._extract_tar``.
    """
    if not source.is_dir():
        raise ArtifactBuildError(f"artifact source must be a directory: {source}")
    buffer = io.BytesIO()
    total = 0
    members = 0
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source)
            if not relative.parts:
                continue
            member = tarfile.TarInfo(path.relative_to(source).as_posix())
            stat = path.lstat()
            if os.path.islink(path):
                raise ArtifactBuildError(f"symlinks are not allowed in the payload: {relative}")
            member.mode = stat.st_mode & 0o777
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            if path.is_dir():
                member.type = tarfile.DIRTYPE
                member.size = 0
                tar.addfile(member)
            elif path.is_file():
                if stat.st_size > _MAX_MEMBER_SIZE:
                    raise ArtifactBuildError(f"payload member too large: {relative}")
                total += stat.st_size
                if total > _MAX_TOTAL_SIZE:
                    raise ArtifactBuildError("payload total size exceeds the 4 GiB ceiling")
                member.type = tarfile.REGTYPE
                member.size = stat.st_size
                with path.open("rb") as handle:
                    tar.addfile(member, fileobj=handle)
            else:
                raise ArtifactBuildError(f"unsupported file type in payload: {relative}")
            members += 1
            if members > _MAX_MEMBERS:
                raise ArtifactBuildError("payload member count exceeds the ceiling")
    return buffer.getvalue()


def build_signed_artifact(
    *,
    source: Path,
    private_key: Ed25519PrivateKey,
    key_id: str,
    artifact_id: str,
    version: str,
    sequence: int,
    target: ReleaseTarget,
    minimum_allowed_version: str,
    rollout_id: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[SignedRelease, bytes]:
    """Build the signed release manifest + payload bytes for the source tree."""
    if expires_at <= issued_at:
        raise ArtifactBuildError("expires_at must be later than issued_at")
    payload = build_payload_tar(source)
    manifest = ReleaseManifest(
        artifact_id=artifact_id,
        kind=ArtifactKind.AGENT,
        version=version,
        sequence=sequence,
        target=target,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size=len(payload),
        issued_at=issued_at,
        expires_at=expires_at,
        minimum_allowed_version=minimum_allowed_version,
        rollout_id=rollout_id,
    )
    signed = sign_release(manifest, key_id=key_id, private_key=private_key)
    return signed, payload


def default_validity(
    now: datetime, days: int = _DEFAULT_VALIDITY_DAYS
) -> tuple[datetime, datetime]:
    """Return a (issued_at, expires_at) pair from ``now``."""
    expires = now + timedelta(days=days)
    return now, expires


def serialize_signed_release(signed: SignedRelease) -> bytes:
    """Canonical JSON for the signed release envelope written next to the payload."""
    return signed.model_dump_json(indent=2, by_alias=False).encode("utf-8")
