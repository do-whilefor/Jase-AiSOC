#!/usr/bin/env python3
"""Replay a detection dataset: normalize EVE JSONL -> detect -> print a report.

Usage:
    uv run python scripts/replay_detection.py tests/replay/web_scan/

Reads ``events.jsonl`` (one Suricata EVE JSON object per line) and
``manifest.json`` from the dataset directory, normalizes each record into a
canonical :class:`SecurityEvent` via the Suricata normalizer, runs the P4
DetectionEngine, and prints which detections fired versus the manifest's
``expected_detections``. Exit code is 0 when expectations match, 1 otherwise.

This is the replay runner referenced by plan §8.4 ("高危规则修改必须支持历史回放")
and the P4 exit-condition verification.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from blue_team.config import get_settings
from blue_team.detection_engine import Detection, DetectionEngine
from blue_team.domain.security_event import SecurityEvent, SourceKind
from blue_team.normalize import RawInput, get_normalizer

TENANT = "ten_replay_dataset"
HOST = "host_replay_dataset"


def _load_dataset(directory: Path) -> tuple[list[bytes], dict[str, object]]:
    events_path = directory / "events.jsonl"
    manifest_path = directory / "manifest.json"
    if not events_path.is_file():
        raise SystemExit(f"events.jsonl not found in {directory}")
    if not manifest_path.is_file():
        raise SystemExit(f"manifest.json not found in {directory}")
    raw_records = [
        line.encode("utf-8") for line in events_path.read_text().splitlines() if line.strip()
    ]
    manifest = json.loads(manifest_path.read_text())
    return raw_records, manifest


def _normalize(raw_records: list[bytes]) -> list[SecurityEvent]:
    normalizer = get_normalizer(SourceKind.SURICATA)
    if normalizer is None:
        raise SystemExit("suricata normalizer not registered")
    received_at = datetime.now(UTC)
    events: list[SecurityEvent] = []
    for seq, raw_payload in enumerate(raw_records):
        raw = RawInput(
            source_kind=SourceKind.SURICATA,
            raw_payload=raw_payload,
            raw_ref=f"replay://{seq}",
            tenant_id=TENANT,
            host_id=HOST,
            agent_id=None,
            boot_id=None,
            received_at=received_at,
            envelope=None,
        )
        result = normalizer.normalize(raw)
        if result.event is not None:
            events.append(result.event)
        elif result.dlq is not None:
            print(f"  DLQ: {result.dlq.reason}: {result.dlq.detail}", file=sys.stderr)
    return events


def _evaluate(events: list[SecurityEvent]) -> list[Detection]:
    engine = DetectionEngine(settings=get_settings())
    return engine.evaluate(events)


def _report(directory: Path, manifest: dict[str, object], detections: list[Detection]) -> bool:
    name = manifest.get("name", directory.name)
    expected_raw = manifest.get("expected_detections", [])
    expected: list[dict[str, object]] = expected_raw if isinstance(expected_raw, list) else []
    print(f"dataset: {name}")
    print(f"  detections fired: {len(detections)}")
    for det in detections:
        print(
            f"    - {det.category} [{det.attack_state}] "
            f"entity={det.entity_key} summary={det.summary}"
        )

    ok = True
    for exp in expected:
        category = exp.get("category")
        min_count_raw = exp.get("min_count", 1)
        min_count = int(min_count_raw) if isinstance(min_count_raw, int | float) else 1
        actual = sum(1 for d in detections if d.category == category)
        if actual < min_count:
            print(f"  MISS: expected >={min_count} {category}, got {actual}")
            ok = False
        else:
            print(f"  OK:   {category} fired {actual} (expected >={min_count})")

    if not expected and detections:
        print(f"  MISS: expected 0 detections on a normal baseline, got {len(detections)}")
        ok = False
    elif not expected:
        print("  OK:   no detections on normal baseline (false-positive control)")
    return ok


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: replay_detection.py <dataset_dir>", file=sys.stderr)
        return 2
    directory = Path(argv[1])
    raw_records, manifest = _load_dataset(directory)
    events = _normalize(raw_records)
    detections = _evaluate(events)
    ok = _report(directory, manifest, detections)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
