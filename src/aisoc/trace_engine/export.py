"""Canonical evidence-index-only P10 investigation export."""

from __future__ import annotations

import json

from aisoc._rustcore import sha256_hex
from aisoc.domain.trace import (
    AttackTraceReport,
    InvestigationExportPackage,
    TraceExportManifest,
)


def build_investigation_export(
    report: AttackTraceReport, *, export_id: str
) -> InvestigationExportPackage:
    canonical = json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return InvestigationExportPackage(
        manifest=TraceExportManifest(
            export_id=export_id,
            tenant_id=report.tenant_id,
            trace_id=report.trace_id,
            trace_revision=report.revision,
            content_sha256=sha256_hex(canonical),
            evidence_count=len(report.evidence_index),
        ),
        trace=report,
    )
