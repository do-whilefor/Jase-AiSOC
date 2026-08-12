use aisoc_contracts::{ModelAssessment, ModelVerdict, PolicyDecision, SecurityState};
use aisoc_core::sha256_bytes;

use crate::config::GuardMode;
use crate::detection::DetectionOutcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDecision {
    pub action: PolicyDecision,
    pub security_state: SecurityState,
    pub risk_score: u8,
    pub needs_ai_review: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    mode: GuardMode,
    canary_block_ratio: f64,
}

impl PolicyEngine {
    pub fn new(mode: GuardMode) -> Self {
        Self {
            mode,
            canary_block_ratio: 0.05,
        }
    }

    pub fn with_canary_ratio(mode: GuardMode, canary_block_ratio: f64) -> Self {
        Self {
            mode,
            canary_block_ratio: canary_block_ratio.clamp(0.0, 1.0),
        }
    }

    pub fn decide(&self, detection: &DetectionOutcome) -> GuardDecision {
        self.decide_for(detection, "default")
    }

    pub fn decide_for(&self, detection: &DetectionOutcome, request_id: &str) -> GuardDecision {
        let high_confidence = detection.risk_score >= 90;
        let (action, state) = match self.mode {
            GuardMode::Enforce if high_confidence => {
                (PolicyDecision::Block, SecurityState::Blocked)
            }
            GuardMode::Canary if high_confidence && self.canary_selected(request_id) => {
                (PolicyDecision::Block, SecurityState::Blocked)
            }
            GuardMode::Monitor | GuardMode::Shadow | GuardMode::Canary if high_confidence => {
                (PolicyDecision::Monitor, SecurityState::AttackAttempt)
            }
            _ if detection.risk_score >= 35 => {
                (PolicyDecision::Monitor, SecurityState::Observed)
            }
            _ => (PolicyDecision::Allow, SecurityState::Observed),
        };

        GuardDecision {
            action,
            security_state: state,
            risk_score: detection.risk_score,
            needs_ai_review: detection.needs_ai_review,
            reason_codes: detection.reason_codes.clone(),
        }
    }


    pub fn decide_with_model(
        &self,
        detection: &DetectionOutcome,
        assessment: &ModelAssessment,
        request_id: &str,
    ) -> GuardDecision {
        let deterministic = self.decide_for(detection, request_id);
        if detection.risk_score >= 90 || !assessment.is_valid() {
            return deterministic;
        }
        if assessment.verdict == ModelVerdict::Malicious
            && assessment.risk_score >= 80
            && assessment.confidence >= 0.80
        {
            let block = self.mode == GuardMode::Enforce
                || (self.mode == GuardMode::Canary && self.canary_selected(request_id));
            let mut reasons = deterministic.reason_codes;
            reasons.extend(assessment.reason_codes.iter().map(|code| format!("model:{code}")));
            reasons.sort();
            reasons.dedup();
            return GuardDecision {
                action: if block { PolicyDecision::Block } else { PolicyDecision::Monitor },
                security_state: if block {
                    SecurityState::Blocked
                } else {
                    SecurityState::AttackAttempt
                },
                risk_score: detection.risk_score.max(assessment.risk_score),
                needs_ai_review: false,
                reason_codes: reasons,
            };
        }
        deterministic
    }

    fn canary_selected(&self, request_id: &str) -> bool {
        if self.canary_block_ratio <= 0.0 {
            return false;
        }
        if self.canary_block_ratio >= 1.0 {
            return true;
        }
        let digest = sha256_bytes(request_id.as_bytes());
        let bucket = u64::from_be_bytes(digest[..8].try_into().expect("8 byte prefix"));
        let sample = bucket as f64 / u64::MAX as f64;
        sample < self.canary_block_ratio
    }
}

#[cfg(test)]
mod tests {
    use crate::detection::DetectionOutcome;

    use super::*;

    fn outcome(score: u8, needs_ai_review: bool) -> DetectionOutcome {
        DetectionOutcome {
            risk_score: score,
            hits: Vec::new(),
            reason_codes: Vec::new(),
            needs_ai_review,
        }
    }

    #[test]
    fn shadow_mode_never_blocks_high_risk_request() {
        let decision = PolicyEngine::new(GuardMode::Shadow).decide(&outcome(99, false));
        assert_eq!(decision.action, PolicyDecision::Monitor);
        assert_eq!(decision.security_state, SecurityState::AttackAttempt);
    }

    #[test]
    fn enforce_mode_blocks_high_confidence_fast_path() {
        let decision = PolicyEngine::new(GuardMode::Enforce).decide(&outcome(96, false));
        assert_eq!(decision.action, PolicyDecision::Block);
        assert_eq!(decision.security_state, SecurityState::Blocked);
    }

    #[test]
    fn zero_percent_canary_never_blocks() {
        let engine = PolicyEngine::with_canary_ratio(GuardMode::Canary, 0.0);
        assert_eq!(engine.decide_for(&outcome(99, false), "request-a").action, PolicyDecision::Monitor);
    }

    #[test]
    fn full_canary_blocks_all_high_confidence_requests() {
        let engine = PolicyEngine::with_canary_ratio(GuardMode::Canary, 1.0);
        assert_eq!(engine.decide_for(&outcome(99, false), "request-a").action, PolicyDecision::Block);
    }

    #[test]
    fn grey_request_without_model_fails_to_monitor() {
        let decision = PolicyEngine::new(GuardMode::Enforce).decide(&outcome(55, true));
        assert_eq!(decision.action, PolicyDecision::Monitor);
        assert_eq!(decision.security_state, SecurityState::Observed);
    }
}
