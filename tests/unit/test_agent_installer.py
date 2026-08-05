from __future__ import annotations

import hashlib
import os
import stat
import tarfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blue_team.agent_core import (
    ActiveRelease,
    AgentProcessSupervisor,
    AgentProcessSupervisorConfig,
    ArtifactKind,
    InstalledRelease,
    InstalledReleaseProcessHealthCheck,
    RecoveryAction,
    ReleaseActivationError,
    ReleaseArchiveError,
    ReleaseInstallationError,
    ReleaseInstallBusyError,
    ReleaseInstaller,
    ReleaseInstallerConfig,
    ReleaseManifest,
    ReleaseState,
    ReleaseStateStore,
    ReleaseTarget,
    ReleaseTrustKey,
    ReleaseVerifier,
    VerifiedRelease,
    sign_release,
)

NOW = datetime(2026, 8, 3, 16, tzinfo=UTC)
ARTIFACT_ID = "agent.runtime"
KEY_ID = "release_primary"


class SimulatedCrash(BaseException):
    pass


def tar_payload(
    files: tuple[tuple[str, bytes, int], ...],
    *,
    extra_members: tuple[tarfile.TarInfo, ...] = (),
) -> bytes:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, content, mode in files:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = mode
            member.mtime = 0
            archive.addfile(member, BytesIO(content))
        for member in extra_members:
            member.mtime = 0
            archive.addfile(member)
    return output.getvalue()


def agent_payload(version: str = "1.0.0") -> bytes:
    bin_directory = tarfile.TarInfo("bin/")
    bin_directory.type = tarfile.DIRTYPE
    bin_directory.mode = 0o755
    config_directory = tarfile.TarInfo("config/")
    config_directory.type = tarfile.DIRTYPE
    config_directory.mode = 0o755
    return tar_payload(
        (
            ("bin/blue-team-agent", f"agent-{version}".encode(), 0o755),
            ("config/default.json", b'{"profile":"base"}', 0o644),
        ),
        extra_members=(bin_directory, config_directory),
    )


def manifest(
    payload: bytes,
    *,
    version: str = "1.0.0",
    sequence: int = 1,
) -> ReleaseManifest:
    return ReleaseManifest(
        artifact_id=ARTIFACT_ID,
        kind=ArtifactKind.AGENT,
        version=version,
        sequence=sequence,
        target=ReleaseTarget(architecture="x86_64", distro="debian"),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size=len(payload),
        issued_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        minimum_allowed_version="1.0.0",
        rollout_id="rollout.primary",
    )


def release_verifier(private_key: Ed25519PrivateKey) -> ReleaseVerifier:
    return ReleaseVerifier(
        (
            ReleaseTrustKey(
                key_id=KEY_ID,
                public_key=private_key.public_key(),
                allowed_kinds=frozenset({ArtifactKind.AGENT}),
            ),
        ),
        installation_id="inst_primary",
        operating_system="linux",
        architecture="x86_64",
        distro="debian",
    )


def verified_release(
    payload: bytes,
    private_key: Ed25519PrivateKey,
    verifier: ReleaseVerifier,
    state: ReleaseState,
    *,
    version: str = "1.0.0",
    sequence: int = 1,
) -> VerifiedRelease:
    signed = sign_release(
        manifest(payload, version=version, sequence=sequence),
        key_id=KEY_ID,
        private_key=private_key,
    )
    return verifier.verify(signed, payload, state, now=NOW)


def installer(tmp_path: Path, state_store: ReleaseStateStore) -> ReleaseInstaller:
    return ReleaseInstaller(
        ReleaseInstallerConfig(root=tmp_path / "install"),
        state_store=state_store,
    )


def installed_file_path(
    release_installer: ReleaseInstaller,
    deployment_dir: str,
    relative: str,
) -> Path:
    return (
        release_installer.artifacts_root
        / ARTIFACT_ID
        / "versions"
        / deployment_dir
        / "content"
        / Path(relative)
    )


def test_verified_bundle_is_health_checked_activated_and_upgraded(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    first_payload = agent_payload()
    first_verified = verified_release(
        first_payload,
        private_key,
        verifier,
        state_store.load(),
    )
    health_observations: list[bytes] = []

    def observe_health(installed: InstalledRelease) -> bool:
        health_observations.append(
            installed_file_path(
                release_installer,
                installed.deployment_dir,
                "bin/blue-team-agent",
            ).read_bytes()
        )
        return True

    first = release_installer.install(
        first_verified,
        first_payload,
        verifier=verifier,
        health_check=observe_health,
        now=NOW,
    )

    assert health_observations == [b"agent-1.0.0"]
    assert first.state.revision == 1
    assert release_installer.active_release(ARTIFACT_ID) == first.active
    assert state_store.load() == first.state
    assert first.previous is None
    first_deployment = first.installed.deployment_dir

    second_payload = agent_payload("1.1.0")
    second_verified = verified_release(
        second_payload,
        private_key,
        verifier,
        state_store.load(),
        version="1.1.0",
        sequence=2,
    )
    second = release_installer.install(
        second_verified,
        second_payload,
        verifier=verifier,
        health_check=lambda _installed: True,
        now=NOW,
    )

    assert second.previous == first.active
    assert second.state.revision == 2
    assert release_installer.active_release(ARTIFACT_ID) == second.active
    assert (
        installed_file_path(
            release_installer,
            first_deployment,
            "bin/blue-team-agent",
        ).read_bytes()
        == b"agent-1.0.0"
    )


def unsafe_payload(case: str) -> bytes:
    if case == "parent":
        return tar_payload((("../escaped", b"bad", 0o644),))
    if case == "absolute":
        return tar_payload((("/tmp/escaped", b"bad", 0o644),))
    if case == "backslash":
        return tar_payload(((r"..\escaped", b"bad", 0o644),))
    if case == "case_collision":
        return tar_payload((("Readme", b"one", 0o644), ("README", b"two", 0o644)))
    if case == "file_prefix":
        return tar_payload((("bin", b"file", 0o644), ("bin/agent", b"bad", 0o755)))
    if case == "empty_directory":
        directory = tarfile.TarInfo("empty/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        return tar_payload((("bin/agent", b"good", 0o755),), extra_members=(directory,))
    link = tarfile.TarInfo("bin/linked-agent")
    link.type = tarfile.SYMTYPE if case == "symlink" else tarfile.LNKTYPE
    link.linkname = "../outside"
    link.mode = 0o777
    return tar_payload((("bin/agent", b"good", 0o755),), extra_members=(link,))


@pytest.mark.parametrize(
    "case",
    [
        "parent",
        "absolute",
        "backslash",
        "case_collision",
        "file_prefix",
        "empty_directory",
        "symlink",
        "hardlink",
    ],
)
def test_archive_paths_links_and_collisions_are_rejected(
    tmp_path: Path,
    case: str,
) -> None:
    payload = unsafe_payload(case)
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())

    with pytest.raises(ReleaseArchiveError):
        release_installer.install(
            verified,
            payload,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )

    assert state_store.load() == ReleaseState()
    assert not (tmp_path / "escaped").exists()
    assert not list(release_installer.artifacts_root.rglob(".staging-*"))


def test_archive_entry_and_unpacked_size_limits_are_enforced(tmp_path: Path) -> None:
    payload = tar_payload((("one", b"1234", 0o644), ("two", b"5678", 0o644)))
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    verified = verified_release(payload, private_key, verifier, state_store.load())

    too_many = ReleaseInstaller(
        ReleaseInstallerConfig(root=tmp_path / "entries", max_files=1),
        state_store=state_store,
    )
    with pytest.raises(ReleaseArchiveError, match="too many entries"):
        too_many.install(
            verified,
            payload,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )

    too_large = ReleaseInstaller(
        ReleaseInstallerConfig(
            root=tmp_path / "size",
            max_files=2,
            max_unpacked_bytes=7,
            max_file_bytes=4,
        ),
        state_store=state_store,
    )
    with pytest.raises(ReleaseArchiveError, match="unpacked size limit"):
        too_large.install(
            verified,
            payload,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )


def test_payload_is_rechecked_between_verification_and_install(tmp_path: Path) -> None:
    original = agent_payload()
    changed = agent_payload("9.9.9")
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    verified = verified_release(original, private_key, verifier, state_store.load())

    with pytest.raises(ReleaseInstallationError, match="payload"):
        installer(tmp_path, state_store).install(
            verified,
            changed,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )

    assert state_store.load() == ReleaseState()


def test_failed_health_gate_restores_previous_release_and_preserves_queue(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    first_payload = agent_payload()
    first = release_installer.install(
        verified_release(first_payload, private_key, verifier, state_store.load()),
        first_payload,
        verifier=verifier,
        health_check=lambda _installed: True,
        now=NOW,
    )
    queue_sentinel = tmp_path / "queue.sqlite3"
    queue_sentinel.write_bytes(b"queue-must-survive")
    second_payload = agent_payload("1.1.0")
    second_verified = verified_release(
        second_payload,
        private_key,
        verifier,
        state_store.load(),
        version="1.1.0",
        sequence=2,
    )

    with pytest.raises(ReleaseActivationError, match="health check"):
        release_installer.install(
            second_verified,
            second_payload,
            verifier=verifier,
            health_check=lambda _installed: False,
            now=NOW,
        )

    assert release_installer.active_release(ARTIFACT_ID) == first.active
    assert state_store.load() == first.state
    assert queue_sentinel.read_bytes() == b"queue-must-survive"


def test_content_changed_during_health_check_is_rejected(tmp_path: Path) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())

    def tamper(installed: InstalledRelease) -> bool:
        target = installed_file_path(
            release_installer,
            installed.deployment_dir,
            "bin/blue-team-agent",
        )
        target.chmod(0o600)
        target.write_bytes(b"tampered")
        return True

    with pytest.raises(ReleaseActivationError, match="contents changed"):
        release_installer.install(
            verified,
            payload,
            verifier=verifier,
            health_check=tamper,
            now=NOW,
        )

    assert state_store.load() == ReleaseState()
    assert release_installer.active_release(ARTIFACT_ID) is None


def test_recovery_rolls_back_candidate_when_state_was_not_committed(tmp_path: Path) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())

    def crash(_installed: InstalledRelease) -> bool:
        raise SimulatedCrash

    with pytest.raises(SimulatedCrash):
        release_installer.install(
            verified,
            payload,
            verifier=verifier,
            health_check=crash,
            now=NOW,
        )

    recovered = installer(tmp_path, state_store).recover()
    assert len(recovered) == 1
    assert recovered[0].action is RecoveryAction.ROLLED_BACK_CANDIDATE
    assert recovered[0].active is None
    assert state_store.load() == ReleaseState()


def test_recovery_removes_orphaned_staging_and_metadata_temp_files(tmp_path: Path) -> None:
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    assert release_installer.recover() == ()
    artifact_root = release_installer.artifacts_root / ARTIFACT_ID
    artifact_root.mkdir(mode=0o700)
    staging = artifact_root / f".staging-{'a' * 32}"
    staging.mkdir(mode=0o700)
    (staging / "partial").write_bytes(b"partial")
    temporary = artifact_root / f".active.json-{'b' * 32}.tmp"
    temporary.write_bytes(b"partial")
    if os.name != "nt":
        temporary.chmod(0o600)

    assert release_installer.recover() == ()
    assert not staging.exists()
    assert not temporary.exists()


def test_recovery_finalizes_candidate_when_state_was_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())

    def crash_after_state_commit(_artifact_id: str) -> None:
        raise SimulatedCrash

    monkeypatch.setattr(release_installer, "_delete_journal", crash_after_state_commit)
    with pytest.raises(SimulatedCrash):
        release_installer.install(
            verified,
            payload,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )

    assert state_store.load().revision == 1
    recovered = installer(tmp_path, state_store).recover()
    assert len(recovered) == 1
    assert recovered[0].action is RecoveryAction.FINALIZED_COMMIT
    assert recovered[0].active is not None
    assert installer(tmp_path, state_store).active_release(ARTIFACT_ID) == recovered[0].active


def test_recovery_activates_commit_after_crash_before_pointer_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())

    def crash_before_pointer(_active: ActiveRelease) -> None:
        raise SimulatedCrash

    monkeypatch.setattr(release_installer, "_write_active", crash_before_pointer)
    with pytest.raises(SimulatedCrash):
        release_installer.install(
            verified,
            payload,
            verifier=verifier,
            health_check=lambda _installed: True,
            now=NOW,
        )

    assert state_store.load().revision == 1
    recovered = installer(tmp_path, state_store).recover()
    assert len(recovered) == 1
    assert recovered[0].action is RecoveryAction.FINALIZED_COMMIT
    assert installer(tmp_path, state_store).active_release(ARTIFACT_ID) == recovered[0].active


def test_unexpected_file_after_install_is_detected(tmp_path: Path) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    result = release_installer.install(
        verified_release(payload, private_key, verifier, state_store.load()),
        payload,
        verifier=verifier,
        health_check=lambda _installed: True,
        now=NOW,
    )
    content_root = installed_file_path(
        release_installer,
        result.installed.deployment_dir,
        "bin/blue-team-agent",
    ).parents[1]
    if os.name != "nt":
        content_root.chmod(0o700)
    unexpected = content_root / "unexpected"
    unexpected.write_bytes(b"tampered")
    if os.name != "nt":
        unexpected.chmod(0o400)
        content_root.chmod(0o500)

    with pytest.raises(ReleaseInstallationError, match="unexpected file"):
        release_installer.active_release(ARTIFACT_ID)


def test_installed_file_hardlink_substitution_is_detected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX hardlink semantics require Linux")
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    result = release_installer.install(
        verified_release(payload, private_key, verifier, state_store.load()),
        payload,
        verifier=verifier,
        health_check=lambda _installed: True,
        now=NOW,
    )
    executable = installed_file_path(
        release_installer,
        result.installed.deployment_dir,
        "bin/blue-team-agent",
    )
    os.link(executable, tmp_path / "second-name")

    with pytest.raises(ReleaseInstallationError, match="cannot be links"):
        release_installer.active_release(ARTIFACT_ID)


def test_install_lock_rejects_reentrant_competing_installer(tmp_path: Path) -> None:
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    first_installer = installer(tmp_path, state_store)
    second_installer = installer(tmp_path, state_store)
    verified = verified_release(payload, private_key, verifier, state_store.load())
    busy_errors: list[ReleaseInstallBusyError] = []

    def competing_health(_installed: InstalledRelease) -> bool:
        try:
            second_installer.install(
                verified,
                payload,
                verifier=verifier,
                health_check=lambda _release: True,
                now=NOW,
            )
        except ReleaseInstallBusyError as error:
            busy_errors.append(error)
        return True

    first_installer.install(
        verified,
        payload,
        verifier=verifier,
        health_check=competing_health,
        now=NOW,
    )
    assert len(busy_errors) == 1


def test_installed_tree_is_private_and_read_only_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode semantics require Linux")
    payload = agent_payload()
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    result = release_installer.install(
        verified_release(payload, private_key, verifier, state_store.load()),
        payload,
        verifier=verifier,
        health_check=lambda _installed: True,
        now=NOW,
    )

    executable = installed_file_path(
        release_installer,
        result.installed.deployment_dir,
        "bin/blue-team-agent",
    )
    config = installed_file_path(
        release_installer,
        result.installed.deployment_dir,
        "config/default.json",
    )
    assert stat.S_IMODE(executable.stat().st_mode) == 0o500
    assert stat.S_IMODE(config.stat().st_mode) == 0o400


def test_real_candidate_process_health_gate_commits_only_manageable_release(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("direct executable candidate probes require Linux")
    healthy_script = b"""#!/bin/sh
stopping=0
trap 'stopping=1' TERM INT
printf 'BLUE_TEAM_AGENT_HEALTH_V1 STARTED\n'
printf 'BLUE_TEAM_AGENT_HEALTH_V1 HEALTHY\n'
while [ "$stopping" -eq 0 ]; do sleep 0.05; done
"""
    bin_directory = tarfile.TarInfo("bin/")
    bin_directory.type = tarfile.DIRTYPE
    bin_directory.mode = 0o755
    healthy_payload = tar_payload(
        (("bin/blue-team-agent", healthy_script, 0o755),),
        extra_members=(bin_directory,),
    )
    private_key = Ed25519PrivateKey.generate()
    verifier = release_verifier(private_key)
    state_store = ReleaseStateStore(tmp_path / "state")
    release_installer = installer(tmp_path, state_store)
    process_supervisor = AgentProcessSupervisor(
        AgentProcessSupervisorConfig(
            startup_timeout_seconds=1,
            health_timeout_seconds=1,
            stop_timeout_seconds=1,
            kill_timeout_seconds=1,
            max_output_bytes=16 * 1024,
        )
    )
    gate = InstalledReleaseProcessHealthCheck(
        release_installer.root,
        process_supervisor,
    )

    first = release_installer.install(
        verified_release(
            healthy_payload,
            private_key,
            verifier,
            state_store.load(),
        ),
        healthy_payload,
        verifier=verifier,
        health_check=gate,
        now=NOW,
    )
    assert first.state.revision == 1
    assert release_installer.active_release(ARTIFACT_ID) == first.active

    unhealthy_script = b"""#!/bin/sh
printf 'BLUE_TEAM_AGENT_HEALTH_V1 STARTED\n'
sleep 30
"""
    unhealthy_payload = tar_payload(
        (("bin/blue-team-agent", unhealthy_script, 0o755),),
        extra_members=(bin_directory,),
    )
    queue_sentinel = tmp_path / "queue.sqlite3"
    queue_sentinel.write_bytes(b"preserved-queue")
    with pytest.raises(ReleaseActivationError, match="health check"):
        release_installer.install(
            verified_release(
                unhealthy_payload,
                private_key,
                verifier,
                state_store.load(),
                version="1.0.1",
                sequence=2,
            ),
            unhealthy_payload,
            verifier=verifier,
            health_check=gate,
            now=NOW,
        )

    assert state_store.load() == first.state
    assert release_installer.active_release(ARTIFACT_ID) == first.active
    assert queue_sentinel.read_bytes() == b"preserved-queue"
