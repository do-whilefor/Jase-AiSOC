#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("aisoc-web-guard targets Linux only");

pub mod ai_budget;
pub mod canonical;
pub mod config;
pub mod detection;
pub mod policy;
pub mod request;

pub use ai_budget::AiReviewBudget;
pub use canonical::{canonicalize_text, canonicalize_uri, CanonicalizationError};
pub use config::{GuardConfig, GuardMode};
pub use detection::{DeterministicDetector, DetectionOutcome};
pub use policy::{GuardDecision, PolicyEngine};
pub use request::{build_request_envelope, validate_request_headers, RequestBuildInput};
