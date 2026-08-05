"""Signed Agent release manifests, rollout selection, and persistent anti-rollback state."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from blue_team.domain.identifiers import is_valid_identifier

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SAFE_ID = r"^[a-z][a-z0-9_.-]{2,127}$"
_APPROVAL_ID = r"^approval_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$"
_SIGNATURE = r"^[A-Za-z0-9_-]{86}$"
_MAX_STATE_BYTES = 8 * 1024 * 1024


class ReleaseVerificationError(ValueError):
    """A signed release failed a cryptographic, target, or state invariant."""


class ReleaseStateError(ValueError):
    """Persistent release state is missing, malformed, or insecure."""


class ArtifactKind(StrEnum):
    AGENT = "agent"
    POLICY = "policy"
    RULE_PACK = "rule_pack"
    COLLECTOR = "collector"


class ReleaseDecisionStatus(StrEnum):
    READY = "ready"
    DEFERRED = "deferred"
    ALREADY_APPLIED = "already_applied"


class ReleaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ReleaseTarget(ReleaseModel):
    operating_system: Literal["linux"] = "linux"
    architecture: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")]
    distro: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")] | None = None


class RollbackAuthorization(ReleaseModel):
    approval_id: Annotated[str, Field(pattern=_APPROVAL_ID)]
    reason: Annotated[str, Field(min_length=8, max_length=512)]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        return _aware(value, "rollback expires_at")


class ReleaseManifest(ReleaseModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    artifact_id: Annotated[str, Field(pattern=_SAFE_ID)]
    kind: ArtifactKind
    version: Annotated[str, Field(min_length=5, max_length=128)]
    sequence: Annotated[int, Field(ge=1)]
    target: ReleaseTarget
    payload_format: Literal["tar"] = "tar"
    payload_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    payload_size: Annotated[int, Field(ge=0, le=4 * 1024 * 1024 * 1024)]
    issued_at: datetime
    expires_at: datetime
    minimum_allowed_version: Annotated[str, Field(min_length=5, max_length=128)]
    rollout_id: Annotated[str, Field(pattern=_SAFE_ID)]
    rollout_percentage: Annotated[int, Field(ge=1, le=100)] = 100
    rollback: RollbackAuthorization | None = None

    @field_validator("version", "minimum_allowed_version")
    @classmethod
    def require_semver(cls, value: str) -> str:
        _parse_semver(value)
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime, info: ValidationInfo) -> datetime:
        return _aware(value, info.field_name or "release timestamp")

    @model_validator(mode="after")
    def validate_manifest_window_and_floor(self) -> ReleaseManifest:
        if self.expires_at <= self.issued_at:
            raise ValueError("release expires_at must be later than issued_at")
        if _compare_versions(self.minimum_allowed_version, self.version) > 0:
            raise ValueError("minimum_allowed_version cannot exceed the release version")
        if self.rollback is not None and self.rollback.expires_at > self.expires_at:
            raise ValueError("rollback authorization cannot outlive the release manifest")
        return self


class SignedRelease(ReleaseModel):
    manifest: ReleaseManifest
    key_id: Annotated[str, Field(pattern=_SAFE_ID)]
    signature: Annotated[str, Field(pattern=_SIGNATURE, repr=False)]


class AppliedRelease(ReleaseModel):
    kind: ArtifactKind
    version: Annotated[str, Field(min_length=5, max_length=128)]
    sequence: Annotated[int, Field(ge=1)]
    manifest_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    payload_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    applied_at: datetime
    rollback_approval_id: Annotated[str, Field(pattern=_APPROVAL_ID)] | None = None
    rollback_reason: Annotated[str, Field(min_length=8, max_length=512)] | None = None

    @field_validator("version")
    @classmethod
    def require_semver(cls, value: str) -> str:
        _parse_semver(value)
        return value

    @field_validator("applied_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        return _aware(value, "applied_at")

    @model_validator(mode="after")
    def require_complete_rollback_audit(self) -> AppliedRelease:
        if (self.rollback_approval_id is None) != (self.rollback_reason is None):
            raise ValueError("rollback audit requires both approval_id and reason")
        return self


class ReleaseState(ReleaseModel):
    format_version: Literal[2] = 2
    revision: Annotated[int, Field(ge=0)] = 0
    artifacts: dict[str, AppliedRelease] = Field(default_factory=dict)
    minimum_versions: dict[str, str] = Field(default_factory=dict)
    rollback_approvals: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_state_keys_and_versions(self) -> ReleaseState:
        for artifact_id in set(self.artifacts) | set(self.minimum_versions):
            if re.fullmatch(_SAFE_ID, artifact_id) is None:
                raise ValueError("release state contains an invalid artifact_id")
        for version in self.minimum_versions.values():
            _parse_semver(version)
        for approval_id, manifest_sha256 in self.rollback_approvals.items():
            if (
                re.fullmatch(_APPROVAL_ID, approval_id) is None
                or re.fullmatch(r"^[a-f0-9]{64}$", manifest_sha256) is None
            ):
                raise ValueError("release state contains invalid rollback approval audit data")
        return self


@dataclass(frozen=True, slots=True)
class ReleaseTrustKey:
    key_id: str
    public_key: Ed25519PublicKey
    allowed_kinds: frozenset[ArtifactKind]
    may_authorize_rollback: bool = False

    def __post_init__(self) -> None:
        if re.fullmatch(_SAFE_ID, self.key_id) is None:
            raise ReleaseVerificationError("invalid release trust key_id")
        if not self.allowed_kinds:
            raise ReleaseVerificationError(
                "release trust key must allow at least one artifact kind"
            )


@dataclass(frozen=True, slots=True)
class VerifiedRelease:
    manifest: ReleaseManifest
    manifest_sha256: str
    status: ReleaseDecisionStatus
    state_revision: int

    @property
    def selected_for_rollout(self) -> bool:
        return self.status is not ReleaseDecisionStatus.DEFERRED


class ReleaseVerifier:
    """Verify signed payloads without executing or installing their contents."""

    def __init__(
        self,
        trust_keys: tuple[ReleaseTrustKey, ...],
        *,
        installation_id: str,
        operating_system: str,
        architecture: str,
        distro: str | None = None,
    ) -> None:
        if not is_valid_identifier("installation_id", installation_id):
            raise ReleaseVerificationError("invalid installation_id")
        if operating_system != "linux":
            raise ReleaseVerificationError("the P2 release verifier only supports Linux targets")
        if not architecture:
            raise ReleaseVerificationError("architecture is required")
        keys = {key.key_id: key for key in trust_keys}
        if not keys or len(keys) != len(trust_keys):
            raise ReleaseVerificationError("release trust keys must be non-empty and unique")
        self._trust_keys = keys
        self._installation_id = installation_id
        self._operating_system = operating_system
        self._architecture = architecture
        self._distro = distro

    def verify(
        self,
        release: SignedRelease,
        payload: bytes,
        state: ReleaseState,
        *,
        now: datetime | None = None,
    ) -> VerifiedRelease:
        checked_at = _aware(now or datetime.now(UTC), "verification time")
        manifest_bytes = canonical_manifest_bytes(release.manifest)
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        key = self._trust_keys.get(release.key_id)
        if key is None:
            raise ReleaseVerificationError("release signature key is not trusted")
        if release.manifest.kind not in key.allowed_kinds:
            raise ReleaseVerificationError("release signing key is not authorized for this kind")
        try:
            key.public_key.verify(_decode_signature(release.signature), manifest_bytes)
        except InvalidSignature as error:
            raise ReleaseVerificationError("release manifest signature is invalid") from error

        manifest = release.manifest
        if checked_at < manifest.issued_at or checked_at > manifest.expires_at:
            raise ReleaseVerificationError("release manifest is outside its validity period")
        self._verify_target(manifest.target)
        if len(payload) != manifest.payload_size:
            raise ReleaseVerificationError("release payload size does not match the manifest")
        if not _constant_time_equal(hashlib.sha256(payload).hexdigest(), manifest.payload_sha256):
            raise ReleaseVerificationError("release payload digest does not match the manifest")

        current = state.artifacts.get(manifest.artifact_id)
        persisted_floor = state.minimum_versions.get(manifest.artifact_id)
        effective_floor = manifest.minimum_allowed_version
        if persisted_floor is not None and _compare_versions(persisted_floor, effective_floor) > 0:
            effective_floor = persisted_floor
        if _compare_versions(manifest.version, effective_floor) < 0:
            raise ReleaseVerificationError("release version is below the persisted security floor")

        if current is not None:
            if manifest.kind != current.kind:
                raise ReleaseVerificationError(
                    "release artifact kind cannot change after installation"
                )
            if manifest.sequence < current.sequence:
                raise ReleaseVerificationError("release sequence replay or rollback was rejected")
            if manifest.sequence == current.sequence:
                if (
                    manifest_sha256 == current.manifest_sha256
                    and manifest.payload_sha256 == current.payload_sha256
                ):
                    return VerifiedRelease(
                        manifest=manifest,
                        manifest_sha256=manifest_sha256,
                        status=ReleaseDecisionStatus.ALREADY_APPLIED,
                        state_revision=state.revision,
                    )
                raise ReleaseVerificationError("release sequence was reused with different content")

            version_comparison = _compare_versions(manifest.version, current.version)
            if version_comparison == 0:
                raise ReleaseVerificationError(
                    "a release version cannot be reused with a new sequence"
                )
            if version_comparison < 0:
                self._verify_rollback(
                    manifest,
                    key,
                    checked_at,
                    state.rollback_approvals,
                )
            elif manifest.rollback is not None:
                raise ReleaseVerificationError(
                    "rollback authorization is only valid for a downgrade"
                )
        elif manifest.rollback is not None:
            raise ReleaseVerificationError("rollback authorization requires an installed release")

        status = (
            ReleaseDecisionStatus.READY
            if _selected_for_rollout(
                self._installation_id,
                manifest.rollout_id,
                manifest.rollout_percentage,
            )
            else ReleaseDecisionStatus.DEFERRED
        )
        return VerifiedRelease(
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            status=status,
            state_revision=state.revision,
        )

    def record_applied(
        self,
        verified: VerifiedRelease,
        state: ReleaseState,
        *,
        now: datetime | None = None,
    ) -> ReleaseState:
        if verified.status is not ReleaseDecisionStatus.READY:
            raise ReleaseStateError("only a rollout-selected, verified release may be recorded")
        if state.revision != verified.state_revision:
            raise ReleaseStateError("release state changed after verification")
        applied_at = _aware(now or datetime.now(UTC), "applied_at")
        manifest = verified.manifest
        artifacts = dict(state.artifacts)
        artifacts[manifest.artifact_id] = AppliedRelease(
            kind=manifest.kind,
            version=manifest.version,
            sequence=manifest.sequence,
            manifest_sha256=verified.manifest_sha256,
            payload_sha256=manifest.payload_sha256,
            applied_at=applied_at,
            rollback_approval_id=(
                manifest.rollback.approval_id if manifest.rollback is not None else None
            ),
            rollback_reason=(manifest.rollback.reason if manifest.rollback is not None else None),
        )
        floors = dict(state.minimum_versions)
        current_floor = floors.get(manifest.artifact_id)
        if (
            current_floor is None
            or _compare_versions(manifest.minimum_allowed_version, current_floor) > 0
        ):
            floors[manifest.artifact_id] = manifest.minimum_allowed_version
        approvals = dict(state.rollback_approvals)
        if manifest.rollback is not None:
            if manifest.rollback.approval_id in approvals:
                raise ReleaseStateError("release rollback approval was already used")
            approvals[manifest.rollback.approval_id] = verified.manifest_sha256
        return ReleaseState(
            revision=state.revision + 1,
            artifacts=artifacts,
            minimum_versions=floors,
            rollback_approvals=approvals,
        )

    def _verify_target(self, target: ReleaseTarget) -> None:
        if (
            target.operating_system != self._operating_system
            or target.architecture != self._architecture
            or (target.distro is not None and target.distro != self._distro)
        ):
            raise ReleaseVerificationError("release target does not match this Agent")

    @staticmethod
    def _verify_rollback(
        manifest: ReleaseManifest,
        key: ReleaseTrustKey,
        checked_at: datetime,
        used_approvals: dict[str, str],
    ) -> None:
        authorization = manifest.rollback
        if authorization is None or not key.may_authorize_rollback:
            raise ReleaseVerificationError("release downgrade lacks authorized rollback approval")
        if authorization.expires_at < checked_at:
            raise ReleaseVerificationError("release rollback approval has expired")
        if authorization.approval_id in used_approvals:
            raise ReleaseVerificationError("release rollback approval was already used")


class ReleaseStateStore:
    """Persist anti-rollback state in one private, atomically replaced JSON file."""

    def __init__(self, root: Path) -> None:
        # Keep the final path component unresolved so _prepare_root can reject a
        # caller-supplied symlink instead of silently accepting its destination.
        self.root = root.expanduser().absolute()
        self.state_path = self.root / "release-state.json"

    def load(self) -> ReleaseState:
        self._prepare_root()
        try:
            self.state_path.lstat()
        except FileNotFoundError:
            return ReleaseState()
        except OSError as error:
            raise ReleaseStateError("release state file is unavailable") from error
        _require_private_file(self.state_path)
        try:
            return ReleaseState.model_validate_json(_read_private_file(self.state_path))
        except (OSError, ValueError) as error:
            raise ReleaseStateError("persistent release state is invalid") from error

    def save(self, state: ReleaseState) -> None:
        self._prepare_root()
        if state.revision < 1:
            raise ReleaseStateError("release state save must advance the revision")
        persisted = self.load()
        if persisted.revision != state.revision - 1:
            raise ReleaseStateError("persistent release state revision conflict")
        temporary = self.root / (
            f".release-state-{os.getpid()}-{state.revision}-{secrets.token_hex(8)}.tmp"
        )
        content = json.dumps(
            state.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(content) > _MAX_STATE_BYTES:
            raise ReleaseStateError("release state exceeds the maximum supported size")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(descriptor)
            os.replace(temporary, self.state_path)
            if os.name != "nt":
                self.state_path.chmod(0o600)
                _fsync_directory(self.root)
        except OSError as error:
            raise ReleaseStateError("failed to persist release state atomically") from error
        finally:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)

    def _prepare_root(self) -> None:
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = self.root.lstat()
        except OSError as error:
            raise ReleaseStateError("release state root is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseStateError("release state root must be a private directory")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ReleaseStateError("release state root is accessible by group or other users")


def sign_release(
    manifest: ReleaseManifest,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedRelease:
    """Build a signed transport object for offline release tooling and tests."""
    signature = private_key.sign(canonical_manifest_bytes(manifest))
    return SignedRelease(
        manifest=manifest,
        key_id=key_id,
        signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    )


def canonical_manifest_bytes(manifest: ReleaseManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class _SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None


def _parse_semver(value: str) -> _SemVer:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise ValueError("release versions must use strict semantic versioning")
    prerelease = tuple(match.group(4).split(".")) if match.group(4) else None
    if prerelease is not None and any(
        part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease
    ):
        raise ValueError(
            "numeric semantic-version prerelease identifiers cannot have leading zeroes"
        )
    return _SemVer(int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease)


def _compare_versions(left: str, right: str) -> int:
    left_version = _parse_semver(left)
    right_version = _parse_semver(right)
    core_left = (left_version.major, left_version.minor, left_version.patch)
    core_right = (right_version.major, right_version.minor, right_version.patch)
    if core_left != core_right:
        return 1 if core_left > core_right else -1
    if left_version.prerelease is None or right_version.prerelease is None:
        if left_version.prerelease == right_version.prerelease:
            return 0
        return 1 if left_version.prerelease is None else -1
    for left_part, right_part in zip(
        left_version.prerelease,
        right_version.prerelease,
        strict=False,
    ):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_part) > int(right_part) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_part > right_part else -1
    if len(left_version.prerelease) == len(right_version.prerelease):
        return 0
    return 1 if len(left_version.prerelease) > len(right_version.prerelease) else -1


def _selected_for_rollout(installation_id: str, rollout_id: str, percentage: int) -> bool:
    if percentage == 100:
        return True
    digest = hashlib.sha256(f"{rollout_id}\0{installation_id}".encode()).digest()
    bucket = int.from_bytes(digest[:8], "big") % 10_000
    return bucket < percentage * 100


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except (ValueError, binascii.Error) as error:
        raise ReleaseVerificationError("release signature encoding is invalid") from error
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ReleaseVerificationError("release signature encoding is invalid")
    return decoded


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone offset")
    return value.astimezone(UTC)


def _constant_time_equal(left: str, right: str) -> bool:
    return secrets.compare_digest(left, right)


def _read_private_file(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseStateError("release state must be a private regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ReleaseStateError("release state is accessible by group or other users")
        if metadata.st_size > _MAX_STATE_BYTES:
            raise ReleaseStateError("release state exceeds the maximum supported size")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(_MAX_STATE_BYTES + 1)
        if len(content) > _MAX_STATE_BYTES:
            raise ReleaseStateError("release state exceeds the maximum supported size")
        return content
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseStateError("release state file is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseStateError("release state must be a private regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ReleaseStateError("release state is accessible by group or other users")
