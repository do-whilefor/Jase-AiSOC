from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from blue_team.agent_core import (
    AppliedRelease,
    ArtifactKind,
    ReleaseDecisionStatus,
    ReleaseManifest,
    ReleaseState,
    ReleaseStateError,
    ReleaseStateStore,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerificationError,
    ReleaseVerifier,
    RollbackAuthorization,
    SignedRelease,
    sign_release,
)

NOW = datetime(2026, 8, 3, 12, tzinfo=UTC)
PAYLOAD = b"verified-agent-release-payload"
ARTIFACT_ID = "agent.runtime"
KEY_ID = "release_primary"


def manifest(
    payload: bytes = PAYLOAD,
    *,
    version: str = "1.0.0",
    sequence: int = 1,
    kind: ArtifactKind = ArtifactKind.AGENT,
    target: ReleaseTarget | None = None,
    minimum_allowed_version: str = "1.0.0",
    rollout_id: str = "rollout.primary",
    rollout_percentage: int = 100,
    rollback: RollbackAuthorization | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ReleaseManifest:
    return ReleaseManifest(
        artifact_id=ARTIFACT_ID,
        kind=kind,
        version=version,
        sequence=sequence,
        target=target or ReleaseTarget(architecture="x86_64", distro="debian"),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size=len(payload),
        issued_at=issued_at or NOW - timedelta(hours=1),
        expires_at=expires_at or NOW + timedelta(hours=1),
        minimum_allowed_version=minimum_allowed_version,
        rollout_id=rollout_id,
        rollout_percentage=rollout_percentage,
        rollback=rollback,
    )


def verifier(
    private_key: Ed25519PrivateKey,
    *,
    installation_id: str = "inst_primary",
    allowed_kinds: frozenset[ArtifactKind] = frozenset({ArtifactKind.AGENT}),
    may_authorize_rollback: bool = False,
) -> ReleaseVerifier:
    return ReleaseVerifier(
        (
            ReleaseTrustKey(
                key_id=KEY_ID,
                public_key=private_key.public_key(),
                allowed_kinds=allowed_kinds,
                may_authorize_rollback=may_authorize_rollback,
            ),
        ),
        installation_id=installation_id,
        operating_system="linux",
        architecture="x86_64",
        distro="debian",
    )


def applied_state(
    *,
    version: str = "2.0.0",
    sequence: int = 2,
    minimum_version: str = "1.0.0",
) -> ReleaseState:
    return ReleaseState(
        revision=1,
        artifacts={
            ARTIFACT_ID: AppliedRelease(
                kind=ArtifactKind.AGENT,
                version=version,
                sequence=sequence,
                manifest_sha256="a" * 64,
                payload_sha256="b" * 64,
                applied_at=NOW - timedelta(minutes=30),
            )
        },
        minimum_versions={ARTIFACT_ID: minimum_version},
    )


def rollback_approval() -> RollbackAuthorization:
    return RollbackAuthorization(
        approval_id="approval_rollback01",
        reason="approved recovery to the last known good release",
        expires_at=NOW + timedelta(minutes=30),
    )


def test_signed_release_is_verified_recorded_and_loaded_after_restart(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_release(manifest(), key_id=KEY_ID, private_key=private_key)
    release_verifier = verifier(private_key)
    store = ReleaseStateStore(tmp_path / "release-state")

    initial = store.load()
    verified = release_verifier.verify(signed, PAYLOAD, initial, now=NOW)
    recorded = release_verifier.record_applied(verified, initial, now=NOW)
    store.save(recorded)

    restarted = ReleaseStateStore(tmp_path / "release-state").load()
    assert verified.status is ReleaseDecisionStatus.READY
    assert restarted.revision == 1
    assert restarted.artifacts[ARTIFACT_ID].version == "1.0.0"
    assert restarted.minimum_versions[ARTIFACT_ID] == "1.0.0"
    assert (
        release_verifier.verify(signed, PAYLOAD, restarted, now=NOW).status
        is ReleaseDecisionStatus.ALREADY_APPLIED
    )
    if os.name != "nt":
        assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.state_path.stat().st_mode) == 0o600


def test_payload_signature_manifest_and_target_tampering_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    release_verifier = verifier(private_key)
    signed = sign_release(manifest(), key_id=KEY_ID, private_key=private_key)

    with pytest.raises(ReleaseVerificationError, match="payload digest"):
        release_verifier.verify(signed, b"tampered-agent-release-payload", ReleaseState(), now=NOW)
    with pytest.raises(ReleaseVerificationError, match="payload size"):
        release_verifier.verify(signed, PAYLOAD + b"x", ReleaseState(), now=NOW)

    invalid_signature = SignedRelease(
        manifest=signed.manifest,
        key_id=KEY_ID,
        signature="A" * 86,
    )
    with pytest.raises(ReleaseVerificationError, match="signature is invalid"):
        release_verifier.verify(invalid_signature, PAYLOAD, ReleaseState(), now=NOW)

    changed_manifest = SignedRelease(
        manifest=manifest(version="1.0.1"),
        key_id=KEY_ID,
        signature=signed.signature,
    )
    with pytest.raises(ReleaseVerificationError, match="signature is invalid"):
        release_verifier.verify(changed_manifest, PAYLOAD, ReleaseState(), now=NOW)

    wrong_target = sign_release(
        manifest(target=ReleaseTarget(architecture="aarch64", distro="debian")),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="target does not match"):
        release_verifier.verify(wrong_target, PAYLOAD, ReleaseState(), now=NOW)

    expired = sign_release(
        manifest(
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="validity period"):
        release_verifier.verify(expired, PAYLOAD, ReleaseState(), now=NOW)


def test_untrusted_key_and_unauthorized_artifact_kind_are_rejected() -> None:
    trusted_key = Ed25519PrivateKey.generate()
    untrusted_key = Ed25519PrivateKey.generate()
    release_verifier = verifier(trusted_key)
    unknown = sign_release(manifest(), key_id="release_untrusted", private_key=untrusted_key)

    with pytest.raises(ReleaseVerificationError, match="key is not trusted"):
        release_verifier.verify(unknown, PAYLOAD, ReleaseState(), now=NOW)

    policy = sign_release(
        manifest(kind=ArtifactKind.POLICY),
        key_id=KEY_ID,
        private_key=trusted_key,
    )
    with pytest.raises(ReleaseVerificationError, match="not authorized for this kind"):
        release_verifier.verify(policy, PAYLOAD, ReleaseState(), now=NOW)


def test_sequence_replay_reuse_and_same_version_with_new_sequence_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    release_verifier = verifier(private_key, may_authorize_rollback=True)
    state = applied_state()

    replay = sign_release(
        manifest(
            version="1.5.0",
            sequence=1,
            rollback=rollback_approval(),
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="sequence replay"):
        release_verifier.verify(replay, PAYLOAD, state, now=NOW)

    reused_sequence = sign_release(
        manifest(version="2.0.1", sequence=2),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="sequence was reused"):
        release_verifier.verify(reused_sequence, PAYLOAD, state, now=NOW)

    reused_version = sign_release(
        manifest(version="2.0.0", sequence=3),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="version cannot be reused"):
        release_verifier.verify(reused_version, PAYLOAD, state, now=NOW)

    changed_kind = sign_release(
        manifest(
            version="2.1.0",
            sequence=3,
            kind=ArtifactKind.POLICY,
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="kind cannot change"):
        verifier(
            private_key,
            allowed_kinds=frozenset({ArtifactKind.AGENT, ArtifactKind.POLICY}),
        ).verify(changed_kind, PAYLOAD, state, now=NOW)


def test_downgrade_requires_separate_rollback_permission() -> None:
    private_key = Ed25519PrivateKey.generate()
    downgrade = sign_release(
        manifest(
            version="1.5.0",
            sequence=3,
            rollback=rollback_approval(),
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )

    with pytest.raises(ReleaseVerificationError, match="authorized rollback approval"):
        verifier(private_key).verify(downgrade, PAYLOAD, applied_state(), now=NOW)

    verified = verifier(private_key, may_authorize_rollback=True).verify(
        downgrade,
        PAYLOAD,
        applied_state(),
        now=NOW,
    )
    assert verified.status is ReleaseDecisionStatus.READY

    expired_approval = RollbackAuthorization(
        approval_id="approval_expired01",
        reason="expired recovery approval must fail closed",
        expires_at=NOW - timedelta(minutes=1),
    )
    expired_downgrade = sign_release(
        manifest(
            version="1.5.0",
            sequence=3,
            rollback=expired_approval,
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="approval has expired"):
        verifier(private_key, may_authorize_rollback=True).verify(
            expired_downgrade,
            PAYLOAD,
            applied_state(),
            now=NOW,
        )


def test_persisted_security_floor_cannot_be_lowered_by_a_signed_rollback() -> None:
    private_key = Ed25519PrivateKey.generate()
    downgrade = sign_release(
        manifest(
            version="1.5.0",
            sequence=4,
            minimum_allowed_version="1.0.0",
            rollback=rollback_approval(),
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )

    with pytest.raises(ReleaseVerificationError, match="persisted security floor"):
        verifier(private_key, may_authorize_rollback=True).verify(
            downgrade,
            PAYLOAD,
            applied_state(version="3.0.0", sequence=3, minimum_version="2.0.0"),
            now=NOW,
        )


def test_rollback_approval_is_audited_and_cannot_be_reused() -> None:
    private_key = Ed25519PrivateKey.generate()
    release_verifier = verifier(private_key, may_authorize_rollback=True)
    initial = applied_state()
    approval = rollback_approval()
    downgrade = sign_release(
        manifest(
            version="1.5.0",
            sequence=3,
            rollback=approval,
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    verified_downgrade = release_verifier.verify(downgrade, PAYLOAD, initial, now=NOW)
    downgraded = release_verifier.record_applied(verified_downgrade, initial, now=NOW)

    assert downgraded.rollback_approvals[approval.approval_id] == (
        verified_downgrade.manifest_sha256
    )
    assert downgraded.artifacts[ARTIFACT_ID].rollback_approval_id == approval.approval_id
    assert downgraded.artifacts[ARTIFACT_ID].rollback_reason == approval.reason

    upgrade = sign_release(
        manifest(version="2.1.0", sequence=4),
        key_id=KEY_ID,
        private_key=private_key,
    )
    verified_upgrade = release_verifier.verify(upgrade, PAYLOAD, downgraded, now=NOW)
    upgraded = release_verifier.record_applied(verified_upgrade, downgraded, now=NOW)
    reused_approval = sign_release(
        manifest(
            version="1.6.0",
            sequence=5,
            rollback=approval,
        ),
        key_id=KEY_ID,
        private_key=private_key,
    )
    with pytest.raises(ReleaseVerificationError, match="approval was already used"):
        release_verifier.verify(reused_approval, PAYLOAD, upgraded, now=NOW)


def test_rollout_selection_is_deterministic_and_deferred_release_cannot_be_recorded() -> None:
    private_key = Ed25519PrivateKey.generate()
    rollout_id = "rollout.canary"
    installation_id = next(
        candidate
        for index in range(1000)
        if (candidate := f"inst_node{index:04d}")
        and int.from_bytes(
            hashlib.sha256(f"{rollout_id}\0{candidate}".encode()).digest()[:8],
            "big",
        )
        % 10_000
        >= 100
    )
    signed = sign_release(
        manifest(rollout_id=rollout_id, rollout_percentage=1),
        key_id=KEY_ID,
        private_key=private_key,
    )
    release_verifier = verifier(private_key, installation_id=installation_id)

    first = release_verifier.verify(signed, PAYLOAD, ReleaseState(), now=NOW)
    second = release_verifier.verify(signed, PAYLOAD, ReleaseState(), now=NOW)
    assert first.status is ReleaseDecisionStatus.DEFERRED
    assert second.status is first.status
    with pytest.raises(ReleaseStateError, match="rollout-selected"):
        release_verifier.record_applied(first, ReleaseState(), now=NOW)


def test_state_revision_change_blocks_stale_verified_release() -> None:
    private_key = Ed25519PrivateKey.generate()
    release_verifier = verifier(private_key)
    initial = ReleaseState()
    first = release_verifier.verify(
        sign_release(manifest(), key_id=KEY_ID, private_key=private_key),
        PAYLOAD,
        initial,
        now=NOW,
    )
    competing = release_verifier.verify(
        sign_release(
            manifest(version="1.1.0", sequence=2),
            key_id=KEY_ID,
            private_key=private_key,
        ),
        PAYLOAD,
        initial,
        now=NOW,
    )
    changed = release_verifier.record_applied(first, initial, now=NOW)

    with pytest.raises(ReleaseStateError, match="changed after verification"):
        release_verifier.record_applied(competing, changed, now=NOW)


def test_release_state_store_rejects_a_stale_persistent_revision(tmp_path: Path) -> None:
    store = ReleaseStateStore(tmp_path / "state")
    first = applied_state()
    competing = ReleaseState(
        revision=1,
        artifacts={},
        minimum_versions={ARTIFACT_ID: "1.1.0"},
    )

    store.save(first)
    with pytest.raises(ReleaseStateError, match="revision conflict"):
        store.save(competing)
    assert store.load() == first


def test_release_state_store_rejects_non_regular_and_linked_state(tmp_path: Path) -> None:
    store = ReleaseStateStore(tmp_path / "state")
    assert store.load() == ReleaseState()
    store.state_path.mkdir()
    with pytest.raises(ReleaseStateError, match="private regular file"):
        store.load()

    store.state_path.rmdir()
    target = tmp_path / "attacker-state.json"
    target.write_text(ReleaseState().model_dump_json(), encoding="utf-8")
    try:
        store.state_path.symlink_to(target)
    except OSError:
        pytest.skip("this Windows account cannot create symbolic links")
    with pytest.raises(ReleaseStateError, match="private regular file"):
        store.load()


def test_release_state_store_rejects_a_symlink_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-state"
    real_root.mkdir()
    linked_root = tmp_path / "linked-state"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except OSError:
        pytest.skip("this Windows account cannot create symbolic links")

    with pytest.raises(ReleaseStateError, match="private directory"):
        ReleaseStateStore(linked_root).load()


def test_manifest_rejects_invalid_version_window_and_security_floor() -> None:
    with pytest.raises(ValidationError, match="strict semantic versioning"):
        manifest(version="01.0.0")
    with pytest.raises(ValidationError, match="cannot exceed"):
        manifest(version="1.0.0", minimum_allowed_version="1.0.1")
    with pytest.raises(ValidationError, match="later than issued_at"):
        ReleaseManifest(
            artifact_id=ARTIFACT_ID,
            kind=ArtifactKind.AGENT,
            version="1.0.0",
            sequence=1,
            target=ReleaseTarget(architecture="x86_64"),
            payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
            payload_size=len(PAYLOAD),
            issued_at=NOW,
            expires_at=NOW,
            minimum_allowed_version="1.0.0",
            rollout_id="rollout.primary",
        )
