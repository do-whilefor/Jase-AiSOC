"""Crash-recoverable installation for verified, signed Agent tar bundles."""

from __future__ import annotations

import errno
import hashlib
import fcntl
import json
import os
import re
import secrets
import stat
import tarfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aisoc._rustcore import secure_compare, sha256_hex
from aisoc.agent_core.releases import (
    ArtifactKind,
    ReleaseDecisionStatus,
    ReleaseState,
    ReleaseStateError,
    ReleaseStateStore,
    ReleaseVerifier,
    VerifiedRelease,
    canonical_manifest_bytes,
)

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_DEPLOYMENT_DIR_PATTERN = r"^[0-9]{20}-[a-f0-9]{16}$"
_ARTIFACT_ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
_VERSION_PATTERN = r"^[0-9A-Za-z.+-]{5,128}$"
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_DESCRIPTOR_NAME = "deployment.json"
_CONTENT_NAME = "content"
_ACTIVE_NAME = "active.json"
_JOURNAL_NAME = "install-journal.json"
_LOCK_NAME = ".install.lock"
_STAGING_NAME = re.compile(r"^\.staging-[a-f0-9]{32}$")
_METADATA_TEMP_NAME = re.compile(r"^\.(?:active|install-journal)\.json-[a-f0-9]{32}\.tmp$")

class ReleaseInstallationError(ValueError):
    """A verified release could not be safely installed."""


class ReleaseArchiveError(ReleaseInstallationError):
    """A release tar bundle violated extraction constraints."""


class ReleaseActivationError(ReleaseInstallationError):
    """A candidate release failed its activation health gate."""


class ReleaseInstallBusyError(ReleaseInstallationError):
    """Another process owns the release installation transaction."""


class ReleaseRecoveryError(ReleaseInstallationError):
    """An interrupted release transaction could not be reconciled."""


class RecoveryAction(StrEnum):
    ROLLED_BACK_CANDIDATE = "rolled_back_candidate"
    FINALIZED_COMMIT = "finalized_commit"


class _InstallerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class InstalledFile(_InstallerModel):
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    size: Annotated[int, Field(ge=0)]
    sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    executable: bool = False

    @field_validator("path")
    @classmethod
    def require_safe_path(cls, value: str) -> str:
        _validate_archive_path(value, is_directory=False, max_path_bytes=4096)
        return value


class InstalledRelease(_InstallerModel):
    format_version: Literal[1] = 1
    artifact_id: Annotated[str, Field(pattern=_ARTIFACT_ID_PATTERN)]
    kind: ArtifactKind
    version: Annotated[str, Field(pattern=_VERSION_PATTERN)]
    sequence: Annotated[int, Field(ge=1)]
    manifest_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    payload_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    deployment_dir: Annotated[str, Field(pattern=_DEPLOYMENT_DIR_PATTERN)]
    files: tuple[InstalledFile, ...]


class ActiveRelease(_InstallerModel):
    format_version: Literal[1] = 1
    artifact_id: Annotated[str, Field(pattern=_ARTIFACT_ID_PATTERN)]
    kind: ArtifactKind
    version: Annotated[str, Field(pattern=_VERSION_PATTERN)]
    sequence: Annotated[int, Field(ge=1)]
    manifest_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    payload_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    deployment_dir: Annotated[str, Field(pattern=_DEPLOYMENT_DIR_PATTERN)]


class _InstallJournal(_InstallerModel):
    format_version: Literal[1] = 1
    source_state_revision: Annotated[int, Field(ge=0)]
    target_state_revision: Annotated[int, Field(ge=1)]
    previous: ActiveRelease | None
    target: ActiveRelease


@dataclass(frozen=True, slots=True)
class ReleaseInstallerConfig:
    root: Path
    max_payload_bytes: int = 512 * 1024 * 1024
    max_files: int = 4096
    max_unpacked_bytes: int = 1024 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    max_path_bytes: int = 1024

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.expanduser().absolute())
        if self.max_payload_bytes < 1 or self.max_payload_bytes > 4 * 1024**3:
            raise ReleaseInstallationError("max_payload_bytes is outside the supported range")
        if self.max_files < 1 or self.max_files > 100_000:
            raise ReleaseInstallationError("max_files is outside the supported range")
        if self.max_unpacked_bytes < 1 or self.max_unpacked_bytes > 4 * 1024**3:
            raise ReleaseInstallationError("max_unpacked_bytes is outside the supported range")
        if self.max_file_bytes < 1 or self.max_file_bytes > self.max_unpacked_bytes:
            raise ReleaseInstallationError("max_file_bytes is outside the supported range")
        if self.max_path_bytes < 32 or self.max_path_bytes > 4096:
            raise ReleaseInstallationError("max_path_bytes is outside the supported range")


@dataclass(frozen=True, slots=True)
class ReleaseInstallResult:
    installed: InstalledRelease
    active: ActiveRelease
    previous: ActiveRelease | None
    state: ReleaseState


@dataclass(frozen=True, slots=True)
class ReleaseRecoveryResult:
    artifact_id: str
    action: RecoveryAction
    active: ActiveRelease | None


@dataclass(frozen=True, slots=True)
class _ArchiveMember:
    member: tarfile.TarInfo
    path: str
    parts: tuple[str, ...]
    is_directory: bool



class ReleaseInstaller:
    """Install verified tar payloads using a health-gated, recoverable transaction."""

    def __init__(
        self,
        config: ReleaseInstallerConfig,
        *,
        state_store: ReleaseStateStore,
    ) -> None:
        self.config = config
        self.state_store = state_store
        self.root = config.root
        self.artifacts_root = self.root / "artifacts"
        self.lock_path = self.root / _LOCK_NAME

    def install(
        self,
        verified: VerifiedRelease,
        payload: bytes,
        *,
        verifier: ReleaseVerifier,
        health_check: Callable[[InstalledRelease], bool],
        now: datetime | None = None,
    ) -> ReleaseInstallResult:
        checked_at = _aware(now or datetime.now(UTC))
        self._prepare_root()
        with _exclusive_lock(self.lock_path):
            self._recover_all_locked()
            return self._install_locked(
                verified,
                payload,
                verifier=verifier,
                health_check=health_check,
                checked_at=checked_at,
            )

    def recover(self) -> tuple[ReleaseRecoveryResult, ...]:
        self._prepare_root()
        with _exclusive_lock(self.lock_path):
            return self._recover_all_locked()

    def active_release(self, artifact_id: str) -> ActiveRelease | None:
        self._prepare_root()
        with _exclusive_lock(self.lock_path):
            self._recover_all_locked()
            state = self.state_store.load()
            active = self._load_active(artifact_id)
            self._require_state_matches_active(state, artifact_id, active)
            return active

    def _install_locked(
        self,
        verified: VerifiedRelease,
        payload: bytes,
        *,
        verifier: ReleaseVerifier,
        health_check: Callable[[InstalledRelease], bool],
        checked_at: datetime,
    ) -> ReleaseInstallResult:
        manifest = verified.manifest
        if verified.status is not ReleaseDecisionStatus.READY:
            raise ReleaseInstallationError("only a rollout-ready release may be installed")
        if manifest.payload_format != "tar":
            raise ReleaseInstallationError("the installer only accepts signed tar payloads")
        if len(payload) > self.config.max_payload_bytes:
            raise ReleaseInstallationError("release payload exceeds the configured size limit")
        if len(payload) != manifest.payload_size:
            raise ReleaseInstallationError("release payload size changed after verification")
        payload_sha256 = sha256_hex(payload)
        if not secure_compare(payload_sha256, manifest.payload_sha256):
            raise ReleaseInstallationError("release payload changed after verification")
        manifest_sha256 = sha256_hex(canonical_manifest_bytes(manifest))
        if not secure_compare(manifest_sha256, verified.manifest_sha256):
            raise ReleaseInstallationError("release manifest changed after verification")

        state = self.state_store.load()
        if state.revision != verified.state_revision:
            raise ReleaseInstallationError("release state changed before installation")
        previous = self._load_active(manifest.artifact_id)
        self._require_state_matches_active(state, manifest.artifact_id, previous)
        next_state = verifier.record_applied(verified, state, now=checked_at)
        installed = self._prepare_deployment(verified, payload)
        target = _active_from_installed(installed)
        journal = _InstallJournal(
            source_state_revision=state.revision,
            target_state_revision=next_state.revision,
            previous=previous,
            target=target,
        )
        self._write_journal(journal)

        try:
            healthy = health_check(installed)
        except Exception as error:
            self._rollback_uncommitted(journal)
            raise ReleaseActivationError("release health check raised an error") from error
        if not healthy:
            self._rollback_uncommitted(journal)
            raise ReleaseActivationError("release failed its activation health check")
        try:
            self._validate_deployment(installed)
        except ReleaseInstallationError as error:
            self._rollback_uncommitted(journal)
            raise ReleaseActivationError(
                "release contents changed during the activation health check"
            ) from error

        try:
            self.state_store.save(next_state)
        except ReleaseStateError as error:
            self._rollback_uncommitted(journal)
            raise ReleaseInstallationError("failed to commit release state") from error
        try:
            self._write_active(target)
        except ReleaseInstallationError as error:
            raise ReleaseRecoveryError(
                "release state committed but active pointer recovery is required"
            ) from error
        self._delete_journal(manifest.artifact_id)
        return ReleaseInstallResult(
            installed=installed,
            active=target,
            previous=previous,
            state=next_state,
        )

    def _prepare_deployment(
        self,
        verified: VerifiedRelease,
        payload: bytes,
    ) -> InstalledRelease:
        artifact_root = self._artifact_root(verified.manifest.artifact_id, create=True)
        versions_root = artifact_root / "versions"
        _prepare_private_directory(versions_root)
        deployment_dir = f"{verified.manifest.sequence:020d}-{verified.manifest_sha256[:16]}"
        destination = versions_root / deployment_dir
        staging = artifact_root / f".staging-{secrets.token_hex(16)}"
        created_destination = False
        try:
            staging.mkdir(mode=0o700)
            content_root = staging / _CONTENT_NAME
            content_root.mkdir(mode=0o700)
            files = self._extract_tar(payload, content_root)
            installed = InstalledRelease(
                artifact_id=verified.manifest.artifact_id,
                kind=verified.manifest.kind,
                version=verified.manifest.version,
                sequence=verified.manifest.sequence,
                manifest_sha256=verified.manifest_sha256,
                payload_sha256=verified.manifest.payload_sha256,
                deployment_dir=deployment_dir,
                files=files,
            )
            _atomic_write_model(staging / _DESCRIPTOR_NAME, installed)
            if _lexists(destination):
                existing = self._load_deployment(destination)
                if existing != installed:
                    raise ReleaseInstallationError(
                        "the release deployment directory already contains different content"
                    )
                self._validate_deployment(existing, require_hardened=False)
                _harden_deployment_tree(destination, existing)
                self._validate_deployment(existing)
                _safe_remove_tree(staging)
                return existing
            os.replace(staging, destination)
            created_destination = True
            self._validate_deployment(installed, require_hardened=False)
            _harden_deployment_tree(destination, installed)
            _fsync_directory(versions_root)
            self._validate_deployment(installed)
            return installed
        except ReleaseInstallationError:
            if created_destination and _lexists(destination):
                with suppress(OSError, ReleaseInstallationError):
                    _safe_remove_tree(destination)
            raise
        except (OSError, tarfile.TarError) as error:
            if created_destination and _lexists(destination):
                with suppress(OSError, ReleaseInstallationError):
                    _safe_remove_tree(destination)
            raise ReleaseArchiveError("failed to stage the release tar bundle") from error
        finally:
            if _lexists(staging):
                with suppress(OSError, ReleaseInstallationError):
                    _safe_remove_tree(staging)

    def _extract_tar(self, payload: bytes, content_root: Path) -> tuple[InstalledFile, ...]:
        files: list[InstalledFile] = []
        total_size = 0
        try:
            with tarfile.open(fileobj=BytesIO(payload), mode="r:*") as archive:
                members: list[_ArchiveMember] = []
                seen: set[str] = set()
                regular_paths: set[str] = set()
                for member in archive:
                    if len(members) >= self.config.max_files:
                        raise ReleaseArchiveError("release archive contains too many entries")
                    is_directory = member.isdir()
                    if not is_directory and not member.isreg():
                        raise ReleaseArchiveError("release archive contains a link or special file")
                    path, parts = _validate_archive_path(
                        member.name,
                        is_directory=is_directory,
                        max_path_bytes=self.config.max_path_bytes,
                    )
                    comparable = path.casefold()
                    if comparable in seen:
                        raise ReleaseArchiveError(
                            "release archive contains duplicate or case-colliding paths"
                        )
                    seen.add(comparable)
                    if not is_directory:
                        if member.size < 0:
                            raise ReleaseArchiveError(
                                "release archive file has a negative declared size"
                            )
                        if member.size > self.config.max_file_bytes:
                            raise ReleaseArchiveError(
                                "release archive file exceeds the per-file size limit"
                            )
                        total_size += member.size
                        if total_size > self.config.max_unpacked_bytes:
                            raise ReleaseArchiveError(
                                "release archive exceeds the unpacked size limit"
                            )
                        regular_paths.add(comparable)
                    members.append(_ArchiveMember(member, path, parts, is_directory))

                for candidate in members:
                    prefixes = (
                        "/".join(candidate.parts[:index]).casefold()
                        for index in range(1, len(candidate.parts))
                    )
                    if any(prefix in regular_paths for prefix in prefixes):
                        raise ReleaseArchiveError(
                            "release archive nests content beneath a regular file"
                        )
                    if candidate.is_directory:
                        prefix = f"{candidate.path.casefold()}/"
                        if not any(path.startswith(prefix) for path in regular_paths):
                            raise ReleaseArchiveError(
                                "release archive contains an untracked empty directory"
                            )

                for candidate in members:
                    target = content_root.joinpath(*candidate.parts)
                    if candidate.is_directory:
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        _require_private_directory(target)
                        continue
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    _require_private_directory(target.parent)
                    extracted = archive.extractfile(candidate.member)
                    if extracted is None:
                        raise ReleaseArchiveError("release archive file content is unavailable")
                    digest = hashlib.sha256()
                    written = 0
                    descriptor = _exclusive_open(target, 0o600)
                    try:
                        with os.fdopen(descriptor, "wb", closefd=False) as output:
                            while True:
                                chunk = extracted.read(1024 * 1024)
                                if not chunk:
                                    break
                                written += len(chunk)
                                if written > candidate.member.size:
                                    raise ReleaseArchiveError(
                                        "release archive expanded beyond the declared file size"
                                    )
                                output.write(chunk)
                                digest.update(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                    finally:
                        os.close(descriptor)
                        extracted.close()
                    if written != candidate.member.size:
                        raise ReleaseArchiveError(
                            "release archive file size differs from its declaration"
                        )
                    executable = bool(candidate.member.mode & 0o111)
                    files.append(
                        InstalledFile(
                            path=candidate.path,
                            size=written,
                            sha256=digest.hexdigest(),
                            executable=executable,
                        )
                    )
        except (OSError, EOFError, tarfile.TarError) as error:
            raise ReleaseArchiveError("release payload is not a valid tar bundle") from error
        if not files:
            raise ReleaseArchiveError("release archive contains no regular files")
        return tuple(sorted(files, key=lambda item: item.path))

    def _validate_deployment(
        self,
        expected: InstalledRelease,
        *,
        require_hardened: bool = True,
    ) -> None:
        deployment_root = self._deployment_path(expected)
        actual = self._load_deployment(deployment_root)
        if actual != expected:
            raise ReleaseInstallationError("installed release descriptor changed")
        if (
            require_hardened
            and stat.S_IMODE((deployment_root / _DESCRIPTOR_NAME).stat().st_mode) != 0o400
        ):
            raise ReleaseInstallationError("installed release descriptor mode changed")
        content_root = deployment_root / _CONTENT_NAME
        _require_private_directory(content_root)
        expected_files = {item.path: item for item in expected.files}
        observed: set[str] = set()
        expected_directories = {
            "/".join(PurePosixPath(item.path).parts[:index])
            for item in expected.files
            for index in range(1, len(PurePosixPath(item.path).parts))
        }
        observed_directories: set[str] = set()
        for path, is_directory in _walk_release_tree(
            content_root,
            require_hardened=require_hardened,
        ):
            relative = path.relative_to(content_root).as_posix()
            if is_directory:
                observed_directories.add(relative)
                continue
            item = expected_files.get(relative)
            if item is None:
                raise ReleaseInstallationError("installed release contains an unexpected file")
            metadata = path.lstat()
            if metadata.st_size != item.size:
                raise ReleaseInstallationError("installed release file size changed")
            digest = _hash_private_file(path)
            if not secure_compare(digest, item.sha256):
                raise ReleaseInstallationError("installed release file digest changed")
            if require_hardened:
                expected_mode = 0o500 if item.executable else 0o400
                if stat.S_IMODE(metadata.st_mode) != expected_mode:
                    raise ReleaseInstallationError("installed release file mode changed")
            observed.add(relative)
        if observed != set(expected_files):
            raise ReleaseInstallationError("installed release is missing a declared file")
        if observed_directories != expected_directories:
            raise ReleaseInstallationError("installed release directory structure changed")

    def _load_deployment(self, deployment_root: Path) -> InstalledRelease:
        _require_private_directory(deployment_root)
        return _read_model(deployment_root / _DESCRIPTOR_NAME, InstalledRelease)

    def _deployment_path(self, release: InstalledRelease | ActiveRelease) -> Path:
        return (
            self._artifact_root(release.artifact_id, create=False)
            / "versions"
            / release.deployment_dir
        )

    def _load_active(self, artifact_id: str) -> ActiveRelease | None:
        artifact_root = self._artifact_root(artifact_id, create=False)
        if not _lexists(artifact_root):
            return None
        _require_private_directory(artifact_root)
        path = artifact_root / _ACTIVE_NAME
        if not _lexists(path):
            return None
        active = _read_model(path, ActiveRelease)
        if active.artifact_id != artifact_id:
            raise ReleaseInstallationError("active release belongs to another artifact")
        installed = self._load_deployment(self._deployment_path(active))
        if _active_from_installed(installed) != active:
            raise ReleaseInstallationError("active release pointer does not match its deployment")
        self._validate_deployment(installed)
        return active

    def _write_active(self, active: ActiveRelease) -> None:
        self._validate_deployment(self._load_deployment(self._deployment_path(active)))
        artifact_root = self._artifact_root(active.artifact_id, create=True)
        _atomic_write_model(artifact_root / _ACTIVE_NAME, active)

    def _delete_active(self, artifact_id: str) -> None:
        path = self._artifact_root(artifact_id, create=False) / _ACTIVE_NAME
        if _lexists(path):
            _unlink_private_file(path)

    def _write_journal(self, journal: _InstallJournal) -> None:
        artifact_root = self._artifact_root(journal.target.artifact_id, create=True)
        path = artifact_root / _JOURNAL_NAME
        if _lexists(path):
            raise ReleaseRecoveryError("an unresolved release install journal already exists")
        _atomic_write_model(path, journal)

    def _delete_journal(self, artifact_id: str) -> None:
        path = self._artifact_root(artifact_id, create=False) / _JOURNAL_NAME
        if not _lexists(path):
            raise ReleaseRecoveryError("release install journal disappeared before commit")
        _unlink_private_file(path)

    def _rollback_uncommitted(self, journal: _InstallJournal) -> None:
        try:
            if journal.previous is None:
                self._delete_active(journal.target.artifact_id)
            else:
                self._write_active(journal.previous)
            target_path = self._deployment_path(journal.target)
            if _lexists(target_path):
                _safe_remove_tree(target_path)
            self._delete_journal(journal.target.artifact_id)
        except (OSError, ReleaseInstallationError) as error:
            raise ReleaseRecoveryError(
                "failed to restore the previous release after activation failure"
            ) from error

    def _recover_all_locked(self) -> tuple[ReleaseRecoveryResult, ...]:
        results: list[ReleaseRecoveryResult] = []
        for entry in sorted(self.artifacts_root.iterdir(), key=lambda path: path.name):
            _require_private_directory(entry)
            if not _artifact_id_is_safe(entry.name):
                raise ReleaseRecoveryError("release root contains an invalid artifact directory")
            self._cleanup_interrupted_files(entry)
            journal_path = entry / _JOURNAL_NAME
            if not _lexists(journal_path):
                continue
            journal = _read_model(journal_path, _InstallJournal)
            if journal.target.artifact_id != entry.name:
                raise ReleaseRecoveryError("release install journal artifact mismatch")
            results.append(self._recover_journal(journal))
        return tuple(results)

    @staticmethod
    def _cleanup_interrupted_files(artifact_root: Path) -> None:
        for entry in list(artifact_root.iterdir()):
            if _STAGING_NAME.fullmatch(entry.name):
                _safe_remove_tree(entry)
            elif _METADATA_TEMP_NAME.fullmatch(entry.name):
                _unlink_private_file(entry)

    def _recover_journal(self, journal: _InstallJournal) -> ReleaseRecoveryResult:
        state = self.state_store.load()
        artifact_id = journal.target.artifact_id
        if state.revision == journal.source_state_revision:
            self._require_state_matches_active(state, artifact_id, journal.previous)
            if journal.previous is None:
                self._delete_active(artifact_id)
            else:
                self._write_active(journal.previous)
            target_path = self._deployment_path(journal.target)
            if _lexists(target_path):
                _safe_remove_tree(target_path)
            self._delete_journal(artifact_id)
            return ReleaseRecoveryResult(
                artifact_id=artifact_id,
                action=RecoveryAction.ROLLED_BACK_CANDIDATE,
                active=journal.previous,
            )
        if state.revision == journal.target_state_revision:
            self._require_applied_matches_active(state, journal.target)
            self._write_active(journal.target)
            self._delete_journal(artifact_id)
            return ReleaseRecoveryResult(
                artifact_id=artifact_id,
                action=RecoveryAction.FINALIZED_COMMIT,
                active=journal.target,
            )
        raise ReleaseRecoveryError("release journal does not match persistent state revision")

    def _require_state_matches_active(
        self,
        state: ReleaseState,
        artifact_id: str,
        active: ActiveRelease | None,
    ) -> None:
        applied = state.artifacts.get(artifact_id)
        if applied is None and active is None:
            return
        if applied is None or active is None:
            raise ReleaseInstallationError("release state and active pointer disagree")
        self._require_applied_matches_active(state, active)

    @staticmethod
    def _require_applied_matches_active(
        state: ReleaseState,
        active: ActiveRelease,
    ) -> None:
        applied = state.artifacts.get(active.artifact_id)
        if applied is None or (
            applied.kind != active.kind
            or applied.version != active.version
            or applied.sequence != active.sequence
            or applied.manifest_sha256 != active.manifest_sha256
            or applied.payload_sha256 != active.payload_sha256
        ):
            raise ReleaseInstallationError("release state does not match the active deployment")

    def _artifact_root(self, artifact_id: str, *, create: bool) -> Path:
        if not _artifact_id_is_safe(artifact_id):
            raise ReleaseInstallationError("invalid release artifact_id")
        path = self.artifacts_root / artifact_id
        if create:
            _prepare_private_directory(path)
        return path

    def _prepare_root(self) -> None:
        _prepare_private_directory(self.root)
        _prepare_private_directory(self.artifacts_root)


def _active_from_installed(installed: InstalledRelease) -> ActiveRelease:
    return ActiveRelease(
        artifact_id=installed.artifact_id,
        kind=installed.kind,
        version=installed.version,
        sequence=installed.sequence,
        manifest_sha256=installed.manifest_sha256,
        payload_sha256=installed.payload_sha256,
        deployment_dir=installed.deployment_dir,
    )


def _artifact_id_is_safe(value: str) -> bool:
    return re.fullmatch(_ARTIFACT_ID_PATTERN, value) is not None


def _validate_archive_path(
    value: str,
    *,
    is_directory: bool,
    max_path_bytes: int,
) -> tuple[str, tuple[str, ...]]:
    raw = value[:-1] if is_directory and value.endswith("/") else value
    if (
        not raw
        or raw.startswith("/")
        or "\\" in raw
        or "\x00" in raw
        or len(raw.encode("utf-8")) > max_path_bytes
    ):
        raise ReleaseArchiveError("release archive path is unsafe")
    path = PurePosixPath(raw)
    parts = path.parts
    if not parts or any(
        part in {"", ".", ".."}
        or any(ord(character) < 32 for character in part)
        or ":" in part
        for part in parts
    ):
        raise ReleaseArchiveError("release archive path is unsafe")
    canonical = "/".join(parts)
    if raw != canonical:
        raise ReleaseArchiveError("release archive path is not canonical")
    return canonical, parts


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReleaseInstallationError("release installation time must be timezone-aware")
    return value.astimezone(UTC)


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        _require_private_directory(path)
    except OSError as error:
        raise ReleaseInstallationError("release installation directory is unavailable") from error


def _require_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseInstallationError("release installation directories cannot be links")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReleaseInstallationError(
            "release installation directory is accessible by group or other users"
        )


def _require_private_file(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ReleaseInstallationError("release installation files cannot be links")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReleaseInstallationError(
            "release installation file is accessible by group or other users"
        )
    return metadata


def _exclusive_open(path: Path, mode: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def _hash_private_file(path: Path) -> str:
    _require_private_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseInstallationError("installed release contains a non-regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_model[ModelType: BaseModel](path: Path, model: type[ModelType]) -> ModelType:
    metadata = _require_private_file(path)
    if metadata.st_size > _MAX_METADATA_BYTES:
        raise ReleaseInstallationError("release metadata exceeds its size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(_MAX_METADATA_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > _MAX_METADATA_BYTES:
        raise ReleaseInstallationError("release metadata exceeds its size limit")
    try:
        return model.model_validate_json(content)
    except (ValueError, ValidationError) as error:
        raise ReleaseInstallationError("release metadata is invalid") from error


def _atomic_write_model(path: Path, model: BaseModel) -> None:
    if _lexists(path):
        _require_private_file(path)
    content = json.dumps(
        model.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(content) > _MAX_METADATA_BYTES:
        raise ReleaseInstallationError("release metadata exceeds its size limit")
    temporary = path.parent / f".{path.name}-{secrets.token_hex(16)}.tmp"
    try:
        descriptor = _exclusive_open(temporary, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        path.chmod(0o600)
        _fsync_directory(path.parent)
    except OSError as error:
        raise ReleaseInstallationError("failed to persist release metadata") from error
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _unlink_private_file(path: Path) -> None:
    _require_private_file(path)
    path.unlink()
    _fsync_directory(path.parent)


def _walk_release_tree(
    root: Path,
    *,
    require_hardened: bool,
) -> Iterator[tuple[Path, bool]]:
    for entry in sorted(root.iterdir(), key=lambda path: path.name):
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseInstallationError("installed release contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            if require_hardened and stat.S_IMODE(metadata.st_mode) != 0o500:
                raise ReleaseInstallationError("installed release directory mode changed")
            yield entry, True
            yield from _walk_release_tree(entry, require_hardened=require_hardened)
        elif stat.S_ISREG(metadata.st_mode):
            yield entry, False
        else:
            raise ReleaseInstallationError("installed release contains a special file")


def _harden_deployment_tree(root: Path, installed: InstalledRelease) -> None:
    for item in installed.files:
        path = root / _CONTENT_NAME / Path(item.path)
        path.chmod(0o500 if item.executable else 0o400)
    (root / _DESCRIPTOR_NAME).chmod(0o400)
    directories = [path for path in (root / _CONTENT_NAME).rglob("*") if path.is_dir()]
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        directory.chmod(0o500)
    (root / _CONTENT_NAME).chmod(0o500)
    root.chmod(0o500)


def _safe_remove_tree(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ReleaseInstallationError("refusing to remove a linked release directory")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseInstallationError("release cleanup target is not a directory")
    path.chmod(0o700)
    for entry in list(path.iterdir()):
        child_metadata = entry.lstat()
        if stat.S_ISLNK(child_metadata.st_mode):
            raise ReleaseInstallationError("release cleanup encountered a symbolic link")
        if stat.S_ISDIR(child_metadata.st_mode):
            _safe_remove_tree(entry)
        elif stat.S_ISREG(child_metadata.st_mode):
            entry.unlink()
        else:
            raise ReleaseInstallationError("release cleanup encountered a special file")
    path.rmdir()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    if _lexists(path):
        _require_private_file(path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseInstallationError("release install lock is not a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ReleaseInstallationError("release install lock is not private")
        if metadata.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        _acquire_lock(descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            raise ReleaseInstallBusyError(
                "another release installation transaction is active"
            ) from error
        raise ReleaseInstallationError("release install lock is unavailable") from error
    except ReleaseInstallationError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    try:
        assert descriptor is not None
        yield
    finally:
        try:
            _release_lock(descriptor)
        finally:
            os.close(descriptor)


def _acquire_lock(descriptor: int) -> None:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_lock(descriptor: int) -> None:
    fcntl.flock(descriptor, fcntl.LOCK_UN)
