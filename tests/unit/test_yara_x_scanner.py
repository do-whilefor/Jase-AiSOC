"""Tests for the real YARA-X scanner adapter.

These tests require the ``yara-x`` package; they are skipped when it is not
installed so the rest of the suite still runs in minimal environments.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from blue_team.domain.malware import EngineKind, EngineStatus, StaticFileProfile, ThreatSignal
from blue_team.malware_engine.orchestrator import MalwareOrchestrator

yara_x = pytest.importorskip("yara_x")

from blue_team.malware_engine.static import StaticAnalyzer  # noqa: E402
from blue_team.malware_engine.yara_x_scanner import YaraXAdapter, compile_rules  # noqa: E402

TENANT_ID = "ten_yara_test"
SAMPLE_ID = "smp_yara_test"
TASK_ID = "scan_yara_test"


def _profile(data: bytes) -> StaticFileProfile:
    return StaticAnalyzer().analyze(
        data, declared_media_type="application/octet-stream", filename=None
    )


def _write_rules(tmp_path: Path, rules: str, *, name: str = "test.yara") -> Path:
    path = tmp_path / name
    path.write_text(rules, encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_yara_x_adapter_clean_when_no_match(tmp_path: Path) -> None:
    rules = _write_rules(
        tmp_path,
        'rule demo_evil { strings: $a = "evilpayload" condition: $a }',
    )
    adapter = YaraXAdapter(rules)
    data = b"this is a benign sample with no marker"
    result = await adapter.scan(data, _profile(data))
    assert result.source_id == "yara-x"
    assert result.kind is EngineKind.YARA_X
    assert result.status is EngineStatus.COMPLETED
    assert result.signal is ThreatSignal.CLEAN
    assert result.matched_rules == ()
    assert "no_yara_matches" in result.observations


@pytest.mark.asyncio
async def test_yara_x_adapter_suspicious_on_match(tmp_path: Path) -> None:
    rules = _write_rules(
        tmp_path,
        """
        rule demo_evil {
            meta:
                family = "demo_family"
                malware_type = "trojan"
            strings:
                $a = "evilpayload"
            condition:
                $a
        }
        """,
    )
    adapter = YaraXAdapter(rules)
    data = b"contains the evilpayload marker"
    result = await adapter.scan(data, _profile(data))
    assert result.status is EngineStatus.COMPLETED
    # single YARA match is suspicious, not malicious (plan §9.2)
    assert result.signal is ThreatSignal.SUSPICIOUS
    assert result.matched_rules == ("demo_evil",)
    assert "demo_family" in result.family_candidates
    assert "trojan" in result.malware_type_candidates
    assert "yara_match:demo_evil" in result.observations


@pytest.mark.asyncio
async def test_yara_x_adapter_loads_directory_of_rules(tmp_path: Path) -> Path:
    (tmp_path / "a.yara").write_text(
        'rule rule_a { strings: $a = "alpha" condition: $a }', encoding="utf-8"
    )
    (tmp_path / "b.yar").write_text(
        'rule rule_b { strings: $a = "beta" condition: $a }', encoding="utf-8"
    )
    adapter = YaraXAdapter(tmp_path)
    data = b"alpha and beta both present"
    result = await adapter.scan(data, _profile(data))
    assert result.matched_rules == ("rule_a", "rule_b")
    return tmp_path


def test_compile_rules_rejects_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        compile_rules(tmp_path)


def test_yara_x_adapter_fails_fast_on_missing_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        YaraXAdapter(tmp_path / "does-not-exist.yara")


@pytest.mark.asyncio
async def test_orchestrator_with_yara_x_adapter_emits_real_match_not_unavailable(
    tmp_path: Path,
) -> None:
    rules = _write_rules(
        tmp_path,
        'rule demo_evil { strings: $a = "evilpayload" condition: $a }',
    )
    adapter = YaraXAdapter(rules)
    orchestrator = MalwareOrchestrator(scanners=(adapter,))
    data = b"evilpayload sample"
    report = await orchestrator.analyze(
        tenant_id=TENANT_ID,
        sample_id=SAMPLE_ID,
        scan_task_id=TASK_ID,
        data=data,
        declared_media_type="application/octet-stream",
        original_filename="demo.bin",
    )
    yara_result = next(r for r in report.engine_results if r.source_id == "yara-x")
    assert yara_result.status is EngineStatus.COMPLETED
    assert yara_result.matched_rules == ("demo_evil",)
    # builtin-yara-x must NOT be separately reported as unavailable now
    builtin_yara = [r for r in report.engine_results if r.source_id == "builtin-yara-x"]
    assert builtin_yara == []
    # builtin-clamav remains unavailable because it was not configured
    clamav = next(r for r in report.engine_results if r.source_id == "builtin-clamav")
    assert clamav.status is EngineStatus.UNAVAILABLE
    # sha256 is computed by the static profile and surfaced for reputation
    assert report.profile.sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.asyncio
async def test_orchestrator_without_yara_x_adapter_marks_yara_unavailable() -> None:
    orchestrator = MalwareOrchestrator()
    report = await orchestrator.analyze(
        tenant_id=TENANT_ID,
        sample_id=SAMPLE_ID,
        scan_task_id=TASK_ID,
        data=b"clean",
        declared_media_type="application/octet-stream",
        original_filename=None,
    )
    yara_result = next(r for r in report.engine_results if r.source_id == "builtin-yara-x")
    assert yara_result.status is EngineStatus.UNAVAILABLE
    assert "engine_unavailable:builtin-yara-x" in report.warnings
