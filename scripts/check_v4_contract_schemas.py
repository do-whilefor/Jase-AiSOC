#!/usr/bin/env python3
"""Offline structural drift checks for authoritative AI-SOC V4 contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"


@dataclass(frozen=True)
class Contract:
    rust_name: str
    source: Path
    schema: str
    version_constant: str | None = None
    version_field: bool = True


CONTRACTS = (
    Contract(
        "SecurityEvent",
        ROOT / "crates/aisoc-contracts/src/event.rs",
        "security-event-v0.1.schema.json",
        "SECURITY_EVENT_SCHEMA_VERSION",
    ),
    Contract(
        "AgentEnvelope",
        ROOT / "crates/aisoc-contracts/src/pipeline.rs",
        "agent-envelope-v0.1.schema.json",
        "AGENT_ENVELOPE_SCHEMA_VERSION",
    ),
    Contract(
        "AgentHeartbeat",
        ROOT / "crates/aisoc-contracts/src/agent.rs",
        "agent-heartbeat-v0.1.schema.json",
        "AGENT_HEARTBEAT_SCHEMA_VERSION",
    ),
    Contract(
        "EventBatch",
        ROOT / "crates/aisoc-contracts/src/pipeline.rs",
        "event-batch-v0.1.schema.json",
        "EVENT_BATCH_SCHEMA_VERSION",
    ),
    Contract(
        "BatchAck",
        ROOT / "crates/aisoc-contracts/src/pipeline.rs",
        "batch-ack-v0.1.schema.json",
        "BATCH_ACK_SCHEMA_VERSION",
    ),
    Contract(
        "Detection",
        ROOT / "crates/aisoc-contracts/src/pipeline.rs",
        "detection-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "IncidentCandidate",
        ROOT / "crates/aisoc-contracts/src/incident.rs",
        "incident-candidate-v0.1.schema.json",
        "INCIDENT_CANDIDATE_SCHEMA_VERSION",
    ),
    Contract(
        "EvidencePackage",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-evidence-package-v0.1.schema.json",
        "AI_REVIEW_SCHEMA_VERSION",
    ),
    Contract(
        "AnalyzerReport",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-analyzer-report-v0.1.schema.json",
        "AI_REVIEW_SCHEMA_VERSION",
    ),
    Contract(
        "BlindVerifierInput",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-blind-verifier-input-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "VerifierReport",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-verifier-report-v0.1.schema.json",
        "AI_REVIEW_SCHEMA_VERSION",
    ),
    Contract(
        "AdjudicationReport",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-adjudication-report-v0.1.schema.json",
        "AI_REVIEW_SCHEMA_VERSION",
    ),
    Contract(
        "ReviewOutcome",
        ROOT / "crates/aisoc-contracts/src/ai_review.rs",
        "ai-review-outcome-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "MalwareAnalysisReport",
        ROOT / "crates/aisoc-contracts/src/malware.rs",
        "malware-analysis-v0.1.schema.json",
        "MALWARE_ANALYSIS_SCHEMA_VERSION",
    ),
    Contract(
        "AttackTraceReport",
        ROOT / "crates/aisoc-contracts/src/trace.rs",
        "attack-trace-report-v0.1.schema.json",
        "ATTACK_TRACE_SCHEMA_VERSION",
    ),
    Contract(
        "TraceGraphQuery",
        ROOT / "crates/aisoc-contracts/src/trace.rs",
        "attack-trace-graph-query-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "TraceGraphQueryResult",
        ROOT / "crates/aisoc-contracts/src/trace.rs",
        "attack-trace-graph-result-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "ResponsePlanCreate",
        ROOT / "crates/aisoc-contracts/src/response.rs",
        "response-plan-input-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "ResponseApprovalCreate",
        ROOT / "crates/aisoc-contracts/src/response.rs",
        "response-approval-input-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "ResponseActionDetail",
        ROOT / "crates/aisoc-contracts/src/response.rs",
        "response-action-v0.1.schema.json",
        version_field=False,
    ),
    Contract(
        "WebRequestEnvelope",
        ROOT / "crates/aisoc-contracts/src/lib.rs",
        "web-request-envelope-v0.1.schema.json",
        "WEB_REQUEST_ENVELOPE_SCHEMA_VERSION",
    ),
    Contract(
        "WebSecurityEvent",
        ROOT / "crates/aisoc-contracts/src/lib.rs",
        "web-security-event-v0.1.schema.json",
        "WEB_SECURITY_EVENT_SCHEMA_VERSION",
    ),
    Contract(
        "ModelAssessment",
        ROOT / "crates/aisoc-contracts/src/lib.rs",
        "model-assessment-v0.1.schema.json",
        "MODEL_ASSESSMENT_SCHEMA_VERSION",
    ),
)


def fail(message: str) -> None:
    raise SystemExit(f"V4 contract schema check failed: {message}")


def rust_struct_body(source: str, struct_name: str) -> str:
    match = re.search(
        rf"pub struct {re.escape(struct_name)}\s*\{{(?P<body>.*?)\n\}}",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        fail(f"Rust struct {struct_name} not found")
    return match.group("body")


def rust_struct_fields(source: str, struct_name: str) -> set[str]:
    return set(
        re.findall(
            r"^\s*pub\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:",
            rust_struct_body(source, struct_name),
            re.MULTILINE,
        )
    )


def rust_struct_is_closed(source: str, struct_name: str) -> bool:
    marker = re.search(
        rf"#\[serde\(deny_unknown_fields\)\]\s*pub struct {re.escape(struct_name)}\s*\{{",
        source,
    )
    return marker is not None


def rust_version(source: str, constant: str) -> str:
    match = re.search(
        rf'pub const {re.escape(constant)}:\s*&str\s*=\s*"([^"]+)";',
        source,
    )
    if match is None:
        fail(f"Rust version constant {constant} not found")
    return match.group(1)


def require_bound(properties: dict[str, object], field: str, key: str, expected: object) -> None:
    node = properties.get(field)
    if not isinstance(node, dict) or node.get(key) != expected:
        fail(f"{field}.{key} must be {expected!r}")


def main() -> None:
    cache: dict[Path, str] = {}
    for contract in CONTRACTS:
        source = cache.setdefault(contract.source, contract.source.read_text(encoding="utf-8"))
        schema_path = SCHEMA_DIR / contract.schema
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            fail(f"{contract.schema} must be a closed object schema")
        if not rust_struct_is_closed(source, contract.rust_name):
            fail(f"Rust {contract.rust_name} must use serde deny_unknown_fields")

        properties = schema.get("properties")
        if not isinstance(properties, dict):
            fail(f"{contract.schema} has no properties object")
        rust_fields = rust_struct_fields(source, contract.rust_name)
        schema_fields = set(properties)
        if rust_fields != schema_fields:
            fail(
                f"{contract.rust_name} fields drifted: Rust-only={sorted(rust_fields - schema_fields)}, "
                f"Schema-only={sorted(schema_fields - rust_fields)}"
            )

        if contract.version_field:
            if contract.version_constant is None:
                fail(f"{contract.rust_name} has no configured version constant")
            version = rust_version(source, contract.version_constant)
            version_node = properties.get("schema_version")
            if not isinstance(version_node, dict) or version_node.get("const") != version:
                fail(
                    f"{contract.schema} schema_version does not match Rust constant {version!r}"
                )

    model = json.loads((SCHEMA_DIR / "model-assessment-v0.1.schema.json").read_text(encoding="utf-8"))
    model_properties = model["properties"]
    require_bound(model_properties, "risk_score", "maximum", 100)
    require_bound(model_properties, "confidence", "minimum", 0)
    require_bound(model_properties, "confidence", "maximum", 1)
    require_bound(model_properties, "attack_types", "maxItems", 32)
    require_bound(model_properties, "target_fields", "maxItems", 64)
    require_bound(model_properties, "evidence_refs", "maxItems", 128)
    require_bound(model_properties, "reason_codes", "maxItems", 64)

    batch = json.loads((SCHEMA_DIR / "event-batch-v0.1.schema.json").read_text(encoding="utf-8"))
    require_bound(batch["properties"], "events", "maxItems", 1000)
    if batch["properties"]["batch_id"].get("pattern") != r"^batch_[a-f0-9]{32}$":
        fail("event-batch batch_id pattern drifted")

    security = json.loads((SCHEMA_DIR / "security-event-v0.1.schema.json").read_text(encoding="utf-8"))
    require_bound(security["properties"], "labels", "maxProperties", 64)
    require_bound(security["properties"], "extensions", "maxProperties", 32)

    incident = json.loads(
        (SCHEMA_DIR / "incident-candidate-v0.1.schema.json").read_text(encoding="utf-8")
    )
    require_bound(incident["properties"], "risk_score", "maximum", 100)
    require_bound(incident["properties"], "evidence_index", "maxItems", 4096)
    require_bound(incident["properties"], "timeline", "maxItems", 10_000)
    require_bound(incident["properties"], "claims", "maxItems", 10_000)
    require_bound(incident["properties"], "edges", "maxItems", 8192)

    for contract in CONTRACTS:
        schema = json.loads((SCHEMA_DIR / contract.schema).read_text(encoding="utf-8"))
        defs = schema.get("$defs", {})
        for def_name, definition in defs.items():
            if isinstance(definition, dict) and definition.get("type") == "object":
                # Maps such as aggregate_metrics and extensions intentionally allow dynamic keys.
                if "additionalProperties" not in definition:
                    continue
                additional = definition.get("additionalProperties")
                if additional is True:
                    continue
                if additional is not False and not isinstance(additional, dict):
                    fail(f"{contract.schema} $defs.{def_name} has invalid additionalProperties")

    print(f"V4 Rust contract schemas: OK ({len(CONTRACTS)} authoritative DTOs checked)")


if __name__ == "__main__":
    main()
