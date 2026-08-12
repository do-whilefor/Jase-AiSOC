#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use aisoc_contracts::{
    AdjudicationReport, AgentEnvelope, AgentHeartbeat, AnalyzerReport, BatchAck, BlindVerifierInput, Detection,
    EventBatch, EvidencePackage, IncidentCandidate, ModelAssessment, ReviewOutcome, SecurityEvent, VerifierReport,
    WebRequestEnvelope, WebSecurityEvent,
};
use schemars::schema_for;

fn write_schema<T: schemars::JsonSchema>(output_dir: &Path, name: &str) -> Result<(), String> {
    let schema = schema_for!(T);
    let json = serde_json::to_string_pretty(&schema).map_err(|error| error.to_string())?;
    fs::write(output_dir.join(name), format!("{json}\n")).map_err(|error| error.to_string())
}

fn main() -> Result<(), String> {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas-rust-generated"));
    fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    write_schema::<SecurityEvent>(&output_dir, "security-event-v0.1.schema.json")?;
    write_schema::<AgentEnvelope>(&output_dir, "agent-envelope-v0.1.schema.json")?;
    write_schema::<AgentHeartbeat>(&output_dir, "agent-heartbeat-v0.1.schema.json")?;
    write_schema::<EventBatch>(&output_dir, "event-batch-v0.1.schema.json")?;
    write_schema::<BatchAck>(&output_dir, "batch-ack-v0.1.schema.json")?;
    write_schema::<Detection>(&output_dir, "detection-v0.1.schema.json")?;
    write_schema::<IncidentCandidate>(&output_dir, "incident-candidate-v0.1.schema.json")?;
    write_schema::<EvidencePackage>(&output_dir, "ai-evidence-package-v0.1.schema.json")?;
    write_schema::<AnalyzerReport>(&output_dir, "ai-analyzer-report-v0.1.schema.json")?;
    write_schema::<BlindVerifierInput>(&output_dir, "ai-blind-verifier-input-v0.1.schema.json")?;
    write_schema::<VerifierReport>(&output_dir, "ai-verifier-report-v0.1.schema.json")?;
    write_schema::<AdjudicationReport>(&output_dir, "ai-adjudication-report-v0.1.schema.json")?;
    write_schema::<ReviewOutcome>(&output_dir, "ai-review-outcome-v0.1.schema.json")?;
    write_schema::<WebRequestEnvelope>(&output_dir, "web-request-envelope-v0.1.schema.json")?;
    write_schema::<WebSecurityEvent>(&output_dir, "web-security-event-v0.1.schema.json")?;
    write_schema::<ModelAssessment>(&output_dir, "model-assessment-v0.1.schema.json")?;
    Ok(())
}
