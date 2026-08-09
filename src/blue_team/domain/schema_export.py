"""Export canonical Pydantic contracts as deterministic JSON Schema artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from blue_team.agent_core.contracts import AgentEnvelope, AgentHeartbeat, BatchAck, EventBatch
from blue_team.domain.ai_review import (
    AdjudicationReport,
    AnalyzerReport,
    BlindVerifierInput,
    EvidencePackage,
    ReviewOutcome,
    VerifierReport,
)
from blue_team.domain.console import (
    ConsoleAttackTraceInvestigation,
    ConsoleIncidentEvidenceDetail,
    ConsoleIncidentInvestigation,
    ConsoleMalwareInvestigation,
    ConsoleModelOperations,
    ConsoleRuleIntelligenceOperations,
    ConsoleSnapshot,
    ConsoleSystemOperations,
)
from blue_team.domain.detection import DetectionRead
from blue_team.domain.incident import (
    IncidentCandidate,
    IncidentClaimBundle,
    IncidentEvidenceBundle,
    IncidentGraphBundle,
    IncidentTimelineBundle,
)
from blue_team.domain.malware import MalwareAnalysisReport, SignedSandboxReportEnvelope
from blue_team.domain.response import (
    ResponseActionDetail,
    ResponseApprovalCreate,
    ResponsePlanCreate,
)
from blue_team.domain.rule_lifecycle import (
    RuleLifecycleStateRead,
    SignedRuleLifecycleManifest,
)
from blue_team.domain.security_event import SecurityEvent
from blue_team.domain.trace import (
    AttackTraceReport,
    InvestigationExportPackage,
    TraceGraphQuery,
    TraceGraphQueryResult,
)

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "agent-envelope-v0.1.schema.json": AgentEnvelope,
    "agent-heartbeat-v0.1.schema.json": AgentHeartbeat,
    "ai-analyzer-report-v0.1.schema.json": AnalyzerReport,
    "ai-adjudication-report-v0.1.schema.json": AdjudicationReport,
    "ai-blind-verifier-input-v0.1.schema.json": BlindVerifierInput,
    "ai-evidence-package-v0.1.schema.json": EvidencePackage,
    "ai-review-outcome-v0.1.schema.json": ReviewOutcome,
    "ai-verifier-report-v0.1.schema.json": VerifierReport,
    "batch-ack-v0.1.schema.json": BatchAck,
    "event-batch-v0.1.schema.json": EventBatch,
    "security-event-v0.1.schema.json": SecurityEvent,
    "detection-v0.1.schema.json": DetectionRead,
    "incident-candidate-v0.1.schema.json": IncidentCandidate,
    "incident-claims-v0.1.schema.json": IncidentClaimBundle,
    "incident-evidence-v0.1.schema.json": IncidentEvidenceBundle,
    "incident-graph-v0.1.schema.json": IncidentGraphBundle,
    "incident-timeline-v0.1.schema.json": IncidentTimelineBundle,
    "malware-analysis-v0.1.schema.json": MalwareAnalysisReport,
    "signed-sandbox-report-v0.1.schema.json": SignedSandboxReportEnvelope,
    "attack-trace-report-v0.1.schema.json": AttackTraceReport,
    "attack-trace-graph-query-v0.1.schema.json": TraceGraphQuery,
    "attack-trace-graph-result-v0.1.schema.json": TraceGraphQueryResult,
    "investigation-export-v0.1.schema.json": InvestigationExportPackage,
    "response-action-v0.1.schema.json": ResponseActionDetail,
    "response-plan-input-v0.1.schema.json": ResponsePlanCreate,
    "response-approval-input-v0.1.schema.json": ResponseApprovalCreate,
    "rule-lifecycle-state-v0.1.schema.json": RuleLifecycleStateRead,
    "signed-rule-lifecycle-manifest-v0.1.schema.json": SignedRuleLifecycleManifest,
    "console-attack-trace-investigation-v0.1.schema.json": ConsoleAttackTraceInvestigation,
    "console-incident-evidence-v0.1.schema.json": ConsoleIncidentEvidenceDetail,
    "console-incident-investigation-v0.1.schema.json": ConsoleIncidentInvestigation,
    "console-malware-investigation-v0.1.schema.json": ConsoleMalwareInvestigation,
    "console-model-operations-v0.1.schema.json": ConsoleModelOperations,
    "console-rule-intelligence-v0.1.schema.json": ConsoleRuleIntelligenceOperations,
    "console-snapshot-v0.1.schema.json": ConsoleSnapshot,
    "console-system-operations-v0.1.schema.json": ConsoleSystemOperations,
}


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def render_security_event_schema() -> str:
    return render_model_schema(SecurityEvent)


def render_model_schema(model: type[BaseModel]) -> str:
    schema = model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    ordered = {"$schema": schema.pop("$schema"), **schema}
    return json.dumps(ordered, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def export_security_event_schema(path: Path | None = None) -> Path:
    destination = path or repository_root() / "schemas" / "security-event-v0.1.schema.json"
    destination.write_text(render_security_event_schema(), encoding="utf-8", newline="\n")
    return destination


def export_all_schemas(directory: Path | None = None) -> tuple[Path, ...]:
    destination = directory or repository_root() / "schemas"
    destination.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for filename, model in SCHEMA_MODELS.items():
        path = destination / filename
        path.write_text(render_model_schema(model), encoding="utf-8", newline="\n")
        paths.append(path)
    return tuple(paths)


def stale_schemas(directory: Path | None = None) -> tuple[Path, ...]:
    destination = directory or repository_root() / "schemas"
    stale: list[Path] = []
    for filename, model in SCHEMA_MODELS.items():
        path = destination / filename
        if not path.is_file() or path.read_text(encoding="utf-8") != render_model_schema(model):
            stale.append(path)
    return tuple(stale)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blue-team-export-schemas",
        description="Export or verify deterministic JSON Schema contracts.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when a checked-in Schema is missing or differs from its model",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.check:
        stale = stale_schemas()
        for path in stale:
            print(f"stale schema: {path}", file=sys.stderr)
        return 1 if stale else 0
    for destination in export_all_schemas():
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
