"""P11 response, approval, RBAC, target, execution, and rollback contracts."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from blue_team.domain.ai_review import AssuranceLevel
from blue_team.domain.detection import AttackState
from blue_team.domain.identifiers import HostId, TenantId
from blue_team.domain.resources import Criticality

Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ResponseActionId = Annotated[str, Field(pattern=r"^rsa_[a-f0-9]{32}$")]
ResponseApprovalId = Annotated[str, Field(pattern=r"^rap_[a-f0-9]{32}$")]
ResponseExecutionId = Annotated[str, Field(pattern=r"^rex_[a-f0-9]{32}$")]
ResponseRollbackId = Annotated[str, Field(pattern=r"^rrb_[a-f0-9]{32}$")]


class ResponseContract(BaseModel):
    """Strict immutable P11 contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class OperatorRole(StrEnum):
    TENANT_ADMIN = "tenant_admin"
    RESPONDER = "responder"
    APPROVER = "approver"
    AUDITOR = "auditor"


class ResponseTier(StrEnum):
    R0 = "r0_recommendation"
    R1 = "r1_collection"
    R2 = "r2_reversible_containment"
    R3 = "r3_business_impact"


class ResponseActionKind(StrEnum):
    COLLECT_EVIDENCE = "collect_evidence"
    TEMPORARY_BLOCK_IP = "temporary_block_ip"
    ISOLATE_FILE = "isolate_file"
    TERMINATE_PROCESS = "terminate_process"
    DISABLE_ACCOUNT = "disable_account"
    ISOLATE_HOST = "isolate_host"


class ResponseActionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    QUEUED = "queued"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    VERIFICATION_FAILED = "verification_failed"
    FAILED = "failed"
    ROLLBACK_QUEUED = "rollback_queued"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ExecutionResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"


class RollbackResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"


class ResponseOperation(StrEnum):
    FIREWALL_BLOCK = "firewall.block_ip"
    FILE_QUARANTINE = "file.quarantine"
    PROCESS_TERMINATE = "process.terminate"
    ACCOUNT_DISABLE = "account.disable"
    HOST_ISOLATE = "host.isolate"
    EVIDENCE_COLLECT = "evidence.collect"


class FirewallAdapter(StrEnum):
    NFTABLES = "nftables"
    FIREWALLD = "firewalld"


class EvidenceCollectionKind(StrEnum):
    LOGS = "logs"
    PROCESS_TREE = "process_tree"
    FILE_METADATA = "file_metadata"
    PCAP = "pcap"


class IpResponseTarget(ResponseContract):
    target_type: Literal["ip"] = "ip"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    ip_address: Annotated[str, Field(min_length=2, max_length=45)]

    @field_validator("ip_address")
    @classmethod
    def require_canonical_ip(cls, value: str) -> str:
        parsed = ipaddress.ip_address(value)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            raise ValueError("response IP target cannot be loopback, unspecified, or multicast")
        canonical = str(parsed)
        if value != canonical:
            raise ValueError("response IP target must use canonical notation")
        return value


class ProcessResponseTarget(ResponseContract):
    target_type: Literal["process"] = "process"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    pid: Annotated[int, Field(ge=2, le=2_147_483_647)]
    start_ticks: Annotated[int, Field(ge=1)]
    executable_path: Annotated[str, Field(min_length=1, max_length=4096)]
    executable_sha256: Sha256

    @field_validator("executable_path")
    @classmethod
    def require_absolute_process_path(cls, value: str) -> str:
        return _require_absolute_posix_path(value, "process executable_path")


class FileResponseTarget(ResponseContract):
    target_type: Literal["file"] = "file"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Sha256
    inode: Annotated[int, Field(ge=1)]
    device: Annotated[int, Field(ge=0)]
    uid: Annotated[int, Field(ge=0)]
    gid: Annotated[int, Field(ge=0)]
    mode: Annotated[int, Field(ge=0, le=0o7777)]

    @field_validator("path")
    @classmethod
    def require_absolute_file_path(cls, value: str) -> str:
        return _require_absolute_posix_path(value, "file path")


class AccountResponseTarget(ResponseContract):
    target_type: Literal["account"] = "account"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    username: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]
    uid: Annotated[int, Field(ge=0, le=4_294_967_295)]
    shell: Annotated[str, Field(min_length=1, max_length=4096)]
    locked: bool

    @field_validator("shell")
    @classmethod
    def require_absolute_shell_path(cls, value: str) -> str:
        return _require_absolute_posix_path(value, "account shell")


class HostResponseTarget(ResponseContract):
    target_type: Literal["host"] = "host"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    management_ip: Annotated[str, Field(min_length=2, max_length=45)]
    allowlist_ips: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]

    @field_validator("management_ip")
    @classmethod
    def require_management_ip(cls, value: str) -> str:
        return _canonical_unicast_ip(value, "management_ip")

    @field_validator("allowlist_ips")
    @classmethod
    def require_allowlist(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_canonical_unicast_ip(item, "allowlist IP") for item in value)
        if tuple(sorted(set(normalized))) != normalized:
            raise ValueError("allowlist_ips must be sorted, canonical, and unique")
        return normalized

    @model_validator(mode="after")
    def require_management_recovery_path(self) -> Self:
        if self.management_ip not in self.allowlist_ips:
            raise ValueError("host isolation must retain its management IP")
        return self


class EvidenceCollectionTarget(ResponseContract):
    target_type: Literal["evidence_collection"] = "evidence_collection"
    host_id: HostId
    expected_agent_id: Annotated[str, Field(min_length=1, max_length=128)]
    collections: Annotated[tuple[EvidenceCollectionKind, ...], Field(min_length=1, max_length=4)]
    max_bytes: Annotated[int, Field(ge=1024, le=1024 * 1024 * 1024)]
    duration_seconds: Annotated[int, Field(ge=1, le=3600)] = 60

    @field_validator("collections")
    @classmethod
    def require_canonical_collections(
        cls, value: tuple[EvidenceCollectionKind, ...]
    ) -> tuple[EvidenceCollectionKind, ...]:
        if tuple(sorted(set(value), key=lambda item: item.value)) != value:
            raise ValueError("collections must be sorted and unique")
        return value


ResponseTarget = Annotated[
    IpResponseTarget
    | ProcessResponseTarget
    | FileResponseTarget
    | AccountResponseTarget
    | HostResponseTarget
    | EvidenceCollectionTarget,
    Field(discriminator="target_type"),
]


class OperatorCredentialCreate(ResponseContract):
    roles: Annotated[tuple[OperatorRole, ...], Field(min_length=1, max_length=4)]
    expires_at: datetime | None = None

    @field_validator("roles")
    @classmethod
    def require_canonical_roles(cls, value: tuple[OperatorRole, ...]) -> tuple[OperatorRole, ...]:
        if OperatorRole.TENANT_ADMIN in value and len(value) != 1:
            raise ValueError("tenant_admin cannot be combined with other roles")
        if tuple(sorted(set(value), key=lambda item: item.value)) != value:
            raise ValueError("roles must be sorted and unique")
        return value

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiration(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            _require_aware(value, "credential expires_at")
        return value


class OperatorCredentialRead(ResponseContract):
    credential_id: Annotated[str, Field(pattern=r"^cred_[a-f0-9]{32}$")]
    tenant_id: TenantId
    roles: Annotated[tuple[OperatorRole, ...], Field(min_length=1, max_length=4)]
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class OperatorCredentialIssued(OperatorCredentialRead):
    api_token: Annotated[str, Field(min_length=64, max_length=256, repr=False)]


class OperatorCredentialRevoke(ResponseContract):
    reason: Annotated[str, Field(min_length=1, max_length=256)]


class ResponsePlanCreate(ResponseContract):
    incident_revision: Annotated[int, Field(ge=1)]
    action: ResponseActionKind
    target: ResponseTarget
    evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    ttl_seconds: Annotated[int, Field(ge=60, le=86_400)] | None = None

    @field_validator("evidence_ids")
    @classmethod
    def require_canonical_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("response evidence_ids must be sorted and unique")
        return value

    @model_validator(mode="after")
    def require_action_target_shape(self) -> Self:
        expected: dict[ResponseActionKind, type[ResponseContract]] = {
            ResponseActionKind.COLLECT_EVIDENCE: EvidenceCollectionTarget,
            ResponseActionKind.TEMPORARY_BLOCK_IP: IpResponseTarget,
            ResponseActionKind.ISOLATE_FILE: FileResponseTarget,
            ResponseActionKind.TERMINATE_PROCESS: ProcessResponseTarget,
            ResponseActionKind.DISABLE_ACCOUNT: AccountResponseTarget,
            ResponseActionKind.ISOLATE_HOST: HostResponseTarget,
        }
        if not isinstance(self.target, expected[self.action]):
            raise ValueError("response action does not match its typed target")
        if (self.action is ResponseActionKind.TEMPORARY_BLOCK_IP) != (self.ttl_seconds is not None):
            raise ValueError("only temporary_block_ip requires ttl_seconds")
        return self


class ResponsePolicyContext(ResponseContract):
    tenant_id: TenantId
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    incident_revision: Annotated[int, Field(ge=1)]
    incident_open: bool
    host_criticality: Criticality
    attack_state: AttackState
    assurance_level: AssuranceLevel
    human_review_required: bool = False
    active_maintenance_exception: bool = False
    deterministic_evidence_count: Annotated[int, Field(ge=0)]
    active_action_count: Annotated[int, Field(ge=0)] = 0
    active_target_count: Annotated[int, Field(ge=0)] = 0


class ResponsePolicyDecision(ResponseContract):
    policy_version: Literal["p11-response-policy-v0.1.0"] = "p11-response-policy-v0.1.0"
    allowed: bool
    tier: ResponseTier
    required_approvals: Annotated[int, Field(ge=0, le=2)]
    rollback_required: bool
    rollback_supported: bool
    target_revalidation_required: Literal[True] = True
    execution_verification_required: Literal[True] = True
    business_confirmation_required: bool
    reasons: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]


class ResponseActionPlan(ResponseContract):
    schema_version: Literal["0.1.0"] = "0.1.0"
    action_id: ResponseActionId
    tenant_id: TenantId
    incident_id: Annotated[str, Field(min_length=1, max_length=132)]
    incident_revision: Annotated[int, Field(ge=1)]
    action: ResponseActionKind
    tier: ResponseTier
    status: ResponseActionStatus
    target: ResponseTarget
    target_identity_sha256: Sha256
    evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    operation: ResponseOperation
    adapter: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    policy: ResponsePolicyDecision
    requested_by: Annotated[str, Field(min_length=1, max_length=256)]
    approval_count: Annotated[int, Field(ge=0, le=2)] = 0
    ttl_seconds: Annotated[int, Field(ge=60, le=86_400)] | None = None
    created_at: datetime
    expires_at: datetime | None = None
    queued_at: datetime | None = None
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def require_consistent_plan(self) -> Self:
        for name, value in (
            ("created_at", self.created_at),
            ("expires_at", self.expires_at),
            ("queued_at", self.queued_at),
            ("completed_at", self.completed_at),
        ):
            if value is not None:
                _require_aware(value, f"response {name}")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("response expires_at must be after created_at")
        if self.action is ResponseActionKind.TEMPORARY_BLOCK_IP:
            if self.ttl_seconds is None or self.expires_at is None:
                raise ValueError("temporary block plans require TTL and expiration")
        elif self.ttl_seconds is not None:
            raise ValueError("only temporary block plans carry a TTL")
        if self.policy.tier is not self.tier:
            raise ValueError("response policy tier must match the plan tier")
        if self.approval_count > self.policy.required_approvals:
            raise ValueError("approval_count cannot exceed required approvals")
        return self


class ResponseApprovalCreate(ResponseContract):
    decision: ApprovalDecision
    comment: Annotated[str, Field(min_length=1, max_length=512)]
    business_confirmation: bool = False


class ResponseApprovalRead(ResponseContract):
    approval_id: ResponseApprovalId
    action_id: ResponseActionId
    decision: ApprovalDecision
    approver: Annotated[str, Field(min_length=1, max_length=256)]
    comment: Annotated[str, Field(min_length=1, max_length=512)]
    business_confirmation: bool
    created_at: datetime


class ResponseQueueRequest(ResponseContract):
    idempotency_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")]


class ResponseRollbackRequest(ResponseContract):
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    idempotency_key: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")]


class TargetObservation(ResponseContract):
    target: ResponseTarget
    observed_at: datetime
    state_sha256: Sha256
    state: Annotated[dict[str, object], Field(max_length=32)] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_observed_time(cls, value: datetime) -> datetime:
        return _require_aware(value, "target observed_at")


class AdapterExecutionResult(ResponseContract):
    status: ExecutionResultStatus
    adapter: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    operation_reference: Annotated[str, Field(min_length=1, max_length=256)]
    before: TargetObservation
    after: TargetObservation | None = None
    verification_passed: bool
    error_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")] | None = None

    @model_validator(mode="after")
    def require_result_shape(self) -> Self:
        succeeded = self.status is ExecutionResultStatus.SUCCEEDED
        if succeeded != (self.after is not None and self.verification_passed):
            raise ValueError("successful execution requires verified after-state")
        if succeeded == (self.error_code is not None):
            raise ValueError("failed execution requires exactly one error_code")
        return self


class AdapterRollbackResult(ResponseContract):
    status: RollbackResultStatus
    adapter: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    operation_reference: Annotated[str, Field(min_length=1, max_length=256)]
    before: TargetObservation
    after: TargetObservation | None = None
    verification_passed: bool
    error_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")] | None = None

    @model_validator(mode="after")
    def require_result_shape(self) -> Self:
        succeeded = self.status is RollbackResultStatus.SUCCEEDED
        if succeeded != (self.after is not None and self.verification_passed):
            raise ValueError("successful rollback requires verified after-state")
        if succeeded == (self.error_code is not None):
            raise ValueError("failed rollback requires exactly one error_code")
        return self


class ResponseExecutionRead(ResponseContract):
    execution_id: ResponseExecutionId
    action_id: ResponseActionId
    attempt: Annotated[int, Field(ge=1)]
    idempotency_key: Annotated[str, Field(min_length=8, max_length=128)]
    status: ExecutionResultStatus
    result: AdapterExecutionResult
    started_at: datetime
    completed_at: datetime


class ResponseRollbackRead(ResponseContract):
    rollback_id: ResponseRollbackId
    action_id: ResponseActionId
    execution_id: ResponseExecutionId
    idempotency_key: Annotated[str, Field(min_length=8, max_length=128)]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    requested_by: Annotated[str, Field(min_length=1, max_length=256)]
    status: RollbackResultStatus
    result: AdapterRollbackResult
    started_at: datetime
    completed_at: datetime


class ResponseActionEvent(ResponseContract):
    sequence: Annotated[int, Field(ge=1)]
    action_id: ResponseActionId
    from_status: ResponseActionStatus | None = None
    to_status: ResponseActionStatus
    actor: Annotated[str, Field(min_length=1, max_length=256)]
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    created_at: datetime


class ResponseActionDetail(ResponseContract):
    plan: ResponseActionPlan
    approvals: Annotated[tuple[ResponseApprovalRead, ...], Field(max_length=2)] = ()
    executions: Annotated[tuple[ResponseExecutionRead, ...], Field(max_length=100)] = ()
    rollbacks: Annotated[tuple[ResponseRollbackRead, ...], Field(max_length=100)] = ()
    events: Annotated[tuple[ResponseActionEvent, ...], Field(min_length=1, max_length=512)]


class ResponseActionList(ResponseContract):
    items: Annotated[tuple[ResponseActionPlan, ...], Field(max_length=500)]
    total: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def require_total(self) -> Self:
        if self.total < len(self.items):
            raise ValueError("response list total cannot be smaller than returned items")
        return self


def _require_absolute_posix_path(value: str, name: str) -> str:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{name} contains forbidden control characters")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{name} must be an absolute normalized POSIX path")
    if str(path) != value:
        raise ValueError(f"{name} must use normalized POSIX notation")
    return value


def _canonical_unicast_ip(value: str, name: str) -> str:
    parsed = ipaddress.ip_address(value)
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError(f"{name} cannot be loopback, unspecified, or multicast")
    canonical = str(parsed)
    if value != canonical:
        raise ValueError(f"{name} must use canonical notation")
    return canonical


def _require_aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


__all__ = [
    "AccountResponseTarget",
    "AdapterExecutionResult",
    "AdapterRollbackResult",
    "ApprovalDecision",
    "EvidenceCollectionKind",
    "EvidenceCollectionTarget",
    "ExecutionResultStatus",
    "FileResponseTarget",
    "FirewallAdapter",
    "HostResponseTarget",
    "IpResponseTarget",
    "OperatorCredentialCreate",
    "OperatorCredentialIssued",
    "OperatorCredentialRead",
    "OperatorCredentialRevoke",
    "OperatorRole",
    "ProcessResponseTarget",
    "ResponseActionDetail",
    "ResponseActionEvent",
    "ResponseActionKind",
    "ResponseActionList",
    "ResponseActionPlan",
    "ResponseActionStatus",
    "ResponseApprovalCreate",
    "ResponseApprovalRead",
    "ResponseOperation",
    "ResponsePlanCreate",
    "ResponsePolicyContext",
    "ResponsePolicyDecision",
    "ResponseQueueRequest",
    "ResponseRollbackRead",
    "ResponseRollbackRequest",
    "ResponseTarget",
    "ResponseTier",
    "RollbackResultStatus",
    "TargetObservation",
]
