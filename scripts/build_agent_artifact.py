#!/usr/bin/env python3
"""Build and sign a self-contained Linux Agent release artifact.

Packs ``--source`` into a signed ``tar.gz`` payload (Ed25519 manifest) ready
for ``ReleaseVerifier.verify`` + ``ReleaseInstaller.install``. Run inside the
project virtual environment (``.venv/Scripts/python scripts/build_agent_artifact.py``).

Example::

    python scripts/build_agent_artifact.py \
        --source dist/agent-root \
        --key-file keys/release-ed25519.pem \
        --key-id release-agent-v1 \
        --artifact-id agent-linux-x86_64 \
        --version 0.1.0 \
        --sequence 1 \
        --arch x86_64 \
        --distro debian \
        --minimum-version 0.1.0 \
        --out-dir dist/signed
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from blue_team.agent_core.artifact_builder import (
    ArtifactBuildError,
    build_signed_artifact,
    default_validity,
    load_signing_key,
    serialize_signed_release,
)
from blue_team.agent_core.releases import ReleaseTarget


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="artifact source directory")
    parser.add_argument("--key-file", type=Path, required=True, help="Ed25519 PEM private key")
    parser.add_argument("--key-id", required=True, help="trust key identifier")
    parser.add_argument("--artifact-id", required=True, help="release artifact_id")
    parser.add_argument("--version", required=True, help="semantic version, e.g. 0.1.0")
    parser.add_argument("--sequence", type=int, required=True, help="monotonic release sequence")
    parser.add_argument("--arch", required=True, help="target architecture, e.g. x86_64")
    parser.add_argument("--distro", default=None, help="optional target distro, e.g. debian")
    parser.add_argument("--minimum-version", required=True, help="anti-rollback floor version")
    parser.add_argument(
        "--rollout-id",
        default=None,
        help="rollout identifier (defaults to rollout-<version>)",
    )
    parser.add_argument("--out-dir", type=Path, required=True, help="output directory")
    parser.add_argument("--validity-days", type=int, default=365, help="manifest validity in days")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        key = load_signing_key(args.key_file)
    except ArtifactBuildError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    issued_at, expires_at = default_validity(now, days=args.validity_days)
    rollout_id = args.rollout_id or f"rollout-{args.version}"
    target = ReleaseTarget(operating_system="linux", architecture=args.arch, distro=args.distro)
    try:
        signed, payload = build_signed_artifact(
            source=args.source,
            private_key=key,
            key_id=args.key_id,
            artifact_id=args.artifact_id,
            version=args.version,
            sequence=args.sequence,
            target=target,
            minimum_allowed_version=args.minimum_version,
            rollout_id=rollout_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (ArtifactBuildError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    payload_name = f"{args.artifact_id}-{args.version}.tar.gz"
    manifest_name = f"{args.artifact_id}-{args.version}.signed.json"
    (args.out_dir / payload_name).write_bytes(payload)
    (args.out_dir / manifest_name).write_bytes(serialize_signed_release(signed))
    print(
        f"built {payload_name} ({len(payload)} bytes, sha256 "
        f"{signed.manifest.payload_sha256}) + {manifest_name}",
        file=sys.stdout,
    )
    print(f"rollout_id={rollout_id} sequence={args.sequence} target={target}", file=sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
