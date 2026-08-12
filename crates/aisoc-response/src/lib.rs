#![forbid(unsafe_code)]

pub mod runner;

use std::path::Path;

use aisoc_contracts::{
    AccountResponseTarget, EvidenceCollectionKind, FileResponseTarget, HostResponseTarget,
    IpResponseTarget, ProcessResponseTarget, ResponseActionPlan, ResponseTarget,
};
use aisoc_core::sha256_file;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("response action is invalid")]
    InvalidAction,
    #[error("target changed since approval")]
    TargetChanged,
    #[error("target cannot be inspected: {0}")]
    TargetIo(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisteredOperation {
    CollectEvidence {
        host_id: String,
        collections: Vec<EvidenceCollectionKind>,
        max_bytes: u64,
        duration_seconds: u16,
    },
    TemporaryIpBlock {
        host_id: String,
        ip: String,
        ttl_seconds: u32,
    },
    QuarantineFile {
        target: FileResponseTarget,
    },
    TerminateProcess {
        target: ProcessResponseTarget,
    },
    DisableAccount {
        target: AccountResponseTarget,
    },
    IsolateHost {
        target: HostResponseTarget,
    },
}

pub fn prepare_operation(plan: &ResponseActionPlan) -> Result<RegisteredOperation, ResponseError> {
    if !plan.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    match &plan.target {
        ResponseTarget::EvidenceCollection(target) => Ok(RegisteredOperation::CollectEvidence {
            host_id: target.host_id.clone(),
            collections: target.collections.clone(),
            max_bytes: target.max_bytes,
            duration_seconds: target.duration_seconds,
        }),
        ResponseTarget::Ip(target) => Ok(RegisteredOperation::TemporaryIpBlock {
            host_id: target.host_id.clone(),
            ip: target.ip_address.clone(),
            ttl_seconds: plan.ttl_seconds.ok_or(ResponseError::InvalidAction)?,
        }),
        ResponseTarget::File(target) => {
            Ok(RegisteredOperation::QuarantineFile { target: target.clone() })
        }
        ResponseTarget::Process(target) => {
            Ok(RegisteredOperation::TerminateProcess { target: target.clone() })
        }
        ResponseTarget::Account(target) => {
            Ok(RegisteredOperation::DisableAccount { target: target.clone() })
        }
        ResponseTarget::Host(target) => {
            Ok(RegisteredOperation::IsolateHost { target: target.clone() })
        }
    }
}

pub fn revalidate_ip_target(target: &IpResponseTarget) -> Result<(), ResponseError> {
    if !target.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    Ok(())
}

pub fn revalidate_file_target(target: &FileResponseTarget) -> Result<(), ResponseError> {
    if !target.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    let path = Path::new(&target.path);
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(ResponseError::TargetChanged);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.ino() != target.inode
            || before.dev() != target.device
            || before.uid() != target.uid
            || before.gid() != target.gid
            || (before.mode() & 0o7777) != u32::from(target.mode)
        {
            return Err(ResponseError::TargetChanged);
        }
    }
    let (actual_sha256, _) = sha256_file(path, 512 * 1024 * 1024)?;
    if actual_sha256 != target.sha256 {
        return Err(ResponseError::TargetChanged);
    }
    let after = std::fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(ResponseError::TargetChanged);
        }
    }
    Ok(())
}

pub fn revalidate_process_target(target: &ProcessResponseTarget) -> Result<(), ResponseError> {
    if !target.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", target.pid))?;
    let close = stat.rfind(')').ok_or(ResponseError::TargetChanged)?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(ResponseError::TargetChanged)?;
    if start_ticks != target.start_ticks {
        return Err(ResponseError::TargetChanged);
    }
    let executable_link = std::fs::read_link(format!("/proc/{}/exe", target.pid))?;
    if executable_link.to_string_lossy() != target.executable_path {
        return Err(ResponseError::TargetChanged);
    }
    let (actual_sha256, _) = sha256_file(&executable_link, 512 * 1024 * 1024)?;
    if actual_sha256 != target.executable_sha256 {
        return Err(ResponseError::TargetChanged);
    }
    Ok(())
}

pub fn revalidate_host_target(target: &HostResponseTarget) -> Result<(), ResponseError> {
    if !target.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    Ok(())
}

pub fn revalidate_account_target(target: &AccountResponseTarget) -> Result<(), ResponseError> {
    if !target.is_valid() {
        return Err(ResponseError::InvalidAction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aisoc_contracts::{
        ResponseActionKind, ResponseActionStatus, ResponseOperation, ResponsePolicyDecision,
        ResponseTier, RESPONSE_ACTION_SCHEMA_VERSION, RESPONSE_POLICY_VERSION,
    };

    use super::*;

    #[test]
    fn response_model_has_no_arbitrary_command_variant() {
        let plan = ResponseActionPlan {
            schema_version: RESPONSE_ACTION_SCHEMA_VERSION.to_owned(),
            action_id: format!("rsa_{}", "a".repeat(32)),
            tenant_id: "ten_12345678".to_owned(),
            incident_id: "inc_12345678".to_owned(),
            incident_revision: 1,
            action: ResponseActionKind::TemporaryBlockIp,
            tier: ResponseTier::R2ReversibleContainment,
            status: ResponseActionStatus::Queued,
            target: ResponseTarget::Ip(IpResponseTarget {
                target_type: "ip".to_owned(),
                host_id: "host_12345678".to_owned(),
                expected_agent_id: "agent_12345678".to_owned(),
                ip_address: "203.0.113.10".to_owned(),
            }),
            target_identity_sha256: "a".repeat(64),
            evidence_ids: vec!["evi_1234567890abcdef12345678".to_owned()],
            reason: "temporary IOC containment".to_owned(),
            operation: ResponseOperation::FirewallBlockIp,
            adapter: "nftables".to_owned(),
            policy: ResponsePolicyDecision {
                policy_version: RESPONSE_POLICY_VERSION.to_owned(),
                allowed: true,
                tier: ResponseTier::R2ReversibleContainment,
                required_approvals: 0,
                rollback_required: true,
                rollback_supported: true,
                target_revalidation_required: true,
                execution_verification_required: true,
                business_confirmation_required: false,
                reasons: vec!["deterministic_ioc".to_owned()],
            },
            requested_by: "operator:test".to_owned(),
            approval_count: 0,
            ttl_seconds: Some(300),
            created_at: "2026-08-11T00:00:00Z".to_owned(),
            expires_at: Some("2026-08-11T00:05:00Z".to_owned()),
            queued_at: Some("2026-08-11T00:00:01Z".to_owned()),
            completed_at: None,
        };
        assert!(matches!(
            prepare_operation(&plan),
            Ok(RegisteredOperation::TemporaryIpBlock { .. })
        ));
    }
}
