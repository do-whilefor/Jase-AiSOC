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

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from blue_team.config import Settings
from blue_team.detection_engine import Detection, DetectionEngine
from blue_team.domain.security_event import SecurityEvent, SourceKind
from blue_team.normalize import RawInput, get_normalizer

TENANT = "ten_replay_dataset"
HOST = "host_replay_dataset"
BOOT = "boot_replay_dataset_0001"


def _load_dataset(directory: Path) -> tuple[list[bytes], dict[str, object]]:
    events_path = directory / "events.jsonl"
    manifest_path = directory / "manifest.json"
    if not events_path.is_file():
        raise SystemExit(f"events.jsonl not found in {directory}")
    if not manifest_path.is_file():
        raise SystemExit(f"manifest.json not found in {directory}")
    events_bytes = events_path.read_bytes()
    raw_records = [line for line in events_bytes.splitlines() if line.strip()]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hash = manifest.get("events_sha256")
    actual_hash = hashlib.sha256(events_bytes).hexdigest()
    if expected_hash != actual_hash:
        raise SystemExit(
            f"events.jsonl hash mismatch in {directory}: "
            f"expected {expected_hash}, got {actual_hash}"
        )
    return raw_records, manifest


def _normalize(
    raw_records: list[bytes], source_kind: SourceKind, boot_id: str
) -> tuple[list[SecurityEvent], int]:
    normalizer = get_normalizer(source_kind)
    if normalizer is None:
        raise SystemExit(f"{source_kind.value} normalizer not registered")
    received_at = datetime.now(UTC)
    events: list[SecurityEvent] = []
    dlq_count = 0
    for seq, raw_payload in enumerate(raw_records):
        raw = RawInput(
            source_kind=source_kind,
            raw_payload=raw_payload,
            raw_ref=f"replay://{seq}",
            tenant_id=TENANT,
            host_id=HOST,
            agent_id=None,
            boot_id=boot_id,
            received_at=received_at,
            envelope=None,
        )
        result = normalizer.normalize(raw)
        if result.event is not None:
            events.append(result.event)
        elif result.dlq is not None:
            dlq_count += 1
            print(f"  DLQ: {result.dlq.reason}: {result.dlq.detail}", file=sys.stderr)
    return events, dlq_count


def _evaluate(events: list[SecurityEvent]) -> list[Detection]:
    # Replays are pinned to repository defaults and must not inherit a developer
    # machine's .env thresholds.
    engine = DetectionEngine(settings=Settings())
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
    expected_categories: set[object] = set()
    for exp in expected:
        category = exp.get("category")
        expected_categories.add(category)
        attack_state = exp.get("attack_state")
        min_count_raw = exp.get("min_count", 1)
        min_count = int(min_count_raw) if isinstance(min_count_raw, int | float) else 1
        max_count_raw = exp.get("max_count")
        max_count = int(max_count_raw) if isinstance(max_count_raw, int | float) else None
        actual = sum(
            1
            for detection in detections
            if detection.category == category
            and (attack_state is None or detection.attack_state == attack_state)
        )
        if actual < min_count:
            print(f"  MISS: expected >={min_count} {category}/{attack_state or '*'}, got {actual}")
            ok = False
        elif max_count is not None and actual > max_count:
            print(f"  MISS: expected <={max_count} {category}/{attack_state or '*'}, got {actual}")
            ok = False
        else:
            print(
                f"  OK:   {category}/{attack_state or '*'} fired {actual} "
                f"(expected {min_count}..{max_count or '*'})"
            )

    unexpected = [d for d in detections if d.category not in expected_categories]
    if unexpected:
        print(f"  MISS: {len(unexpected)} unexpected detections fired")
        ok = False

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
    try:
        source_kind = SourceKind(str(manifest.get("source_kind", "suricata")))
    except ValueError as error:
        raise SystemExit(f"invalid source_kind in {directory}: {error}") from error
    boot_id_value = manifest.get("boot_id", BOOT)
    if not isinstance(boot_id_value, str) or not boot_id_value:
        raise SystemExit(f"invalid boot_id in {directory}")
    events, dlq_count = _normalize(raw_records, source_kind, boot_id_value)
    if dlq_count:
        print(f"dataset normalization failed: {dlq_count} record(s) entered DLQ", file=sys.stderr)
        return 1
    detections = _evaluate(events)
    ok = _report(directory, manifest, detections)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
