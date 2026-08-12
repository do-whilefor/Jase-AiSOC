#![forbid(unsafe_code)]

use std::collections::HashSet;

use aisoc_contracts::{
    ApprovalDecision, ResponseActionDetail, ResponseTier, SecurityState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceLevel {
    Deterministic,
    Verified,
    HumanConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetPolicy {
    pub critical: bool,
    pub allow_automatic_r2: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRejection {
    InvalidAction,
    MissingApproval,
    DuplicateApprover,
    RejectedAction,
    MissingBusinessConfirmation,
    CriticalAssetRequiresApproval,
    InsufficientAssurance,
    PolicyDenied,
}

pub fn authorize_response(
    detail: &ResponseActionDetail,
    state: SecurityState,
    assurance: AssuranceLevel,
    asset: AssetPolicy,
) -> Result<(), PolicyRejection> {
    if !detail.is_valid() {
        return Err(PolicyRejection::InvalidAction);
    }
    let plan = &detail.plan;
    if !plan.policy.allowed {
        return Err(PolicyRejection::PolicyDenied);
    }
    if detail
        .approvals
        .iter()
        .any(|approval| approval.decision == ApprovalDecision::Reject)
    {
        return Err(PolicyRejection::RejectedAction);
    }
    let approvals = detail
        .approvals
        .iter()
        .filter(|approval| approval.decision == ApprovalDecision::Approve)
        .collect::<Vec<_>>();
    let approvers = approvals
        .iter()
        .map(|approval| approval.approver.as_str())
        .collect::<HashSet<_>>();
    if approvers.len() != approvals.len() {
        return Err(PolicyRejection::DuplicateApprover);
    }
    if approvals.len() < plan.policy.required_approvals as usize {
        return Err(PolicyRejection::MissingApproval);
    }
    if plan.policy.business_confirmation_required
        && !approvals.iter().any(|approval| approval.business_confirmation)
    {
        return Err(PolicyRejection::MissingBusinessConfirmation);
    }
    match plan.tier {
        ResponseTier::R0Recommendation | ResponseTier::R1Collection => Ok(()),
        ResponseTier::R2ReversibleContainment => {
            if (asset.critical || !asset.allow_automatic_r2) && approvals.is_empty() {
                return Err(PolicyRejection::CriticalAssetRequiresApproval);
            }
            if matches!(state, SecurityState::Observed) {
                return Err(PolicyRejection::InsufficientAssurance);
            }
            Ok(())
        }
        ResponseTier::R3BusinessImpact => {
            if approvals.is_empty() {
                return Err(PolicyRejection::MissingApproval);
            }
            if assurance != AssuranceLevel::HumanConfirmed
                || state != SecurityState::ConfirmedCompromise
            {
                return Err(PolicyRejection::InsufficientAssurance);
            }
            Ok(())
        }
    }
}
