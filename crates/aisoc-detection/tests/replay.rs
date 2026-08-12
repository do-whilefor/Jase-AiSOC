#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use aisoc_contracts::{AttackState, SecurityEvent};
use aisoc_core::sha256_hex;
use aisoc_detection::{DetectionConfig, DetectionEngine};
use serde_json::Value;

const DATASETS: &[&str] = &[
    "host_clock_skew",
    "host_failed_attacks",
    "host_missing_source",
    "host_normal_baseline",
    "host_success_chains",
    "normal_baseline",
    "ssh_bruteforce",
    "web_injection",
    "web_scan",
];

#[test]
fn canonical_replay_datasets_match_detection_expectations() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/replay");
    for dataset in DATASETS {
        replay_dataset(&root.join(dataset));
    }
}

fn replay_dataset(directory: &Path) {
    let manifest_bytes = fs::read(directory.join("manifest.json"))
        .unwrap_or_else(|error| panic!("{}: manifest read failed: {error}", directory.display()));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("{}: invalid manifest: {error}", directory.display()));
    let canonical = fs::read(directory.join("canonical-events.jsonl")).unwrap_or_else(|error| {
        panic!(
            "{}: canonical replay input missing: {error}",
            directory.display()
        )
    });
    let expected_hash = manifest
        .get("canonical_events_sha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{}: canonical_events_sha256 missing", directory.display()));
    assert_eq!(
        sha256_hex(&canonical),
        expected_hash,
        "{}: canonical replay hash mismatch",
        directory.display()
    );

    let events = String::from_utf8(canonical)
        .unwrap_or_else(|error| {
            panic!(
                "{}: canonical replay is not UTF-8: {error}",
                directory.display()
            )
        })
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let event: SecurityEvent = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("{}: invalid canonical event: {error}", directory.display())
            });
            assert!(event.is_valid(), "{}: invalid SecurityEvent", directory.display());
            event
        })
        .collect::<Vec<_>>();

    let detections = DetectionEngine::new(DetectionConfig::default()).evaluate(&events);
    for detection in &detections {
        assert!(
            detection.is_valid(),
            "{}: invalid detection {}",
            directory.display(),
            detection.id
        );
    }

    let expected = manifest
        .get("expected_detections")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{}: expected_detections missing", directory.display()));
    let expected_categories = expected
        .iter()
        .filter_map(|item| item.get("category").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    for item in expected {
        let category = item
            .get("category")
            .and_then(Value::as_str)
            .expect("replay category must be a string");
        let attack_state = item.get("attack_state").and_then(Value::as_str);
        let min_count = item.get("min_count").and_then(Value::as_u64).unwrap_or(1) as usize;
        let max_count = item.get("max_count").and_then(Value::as_u64).map(|value| value as usize);
        let actual = detections
            .iter()
            .filter(|detection| {
                detection.category == category
                    && attack_state.map_or(true, |expected_state| {
                        attack_state_name(detection.attack_state) == expected_state
                    })
            })
            .count();
        assert!(
            actual >= min_count,
            "{}: expected at least {min_count} {category}/{attack_state:?}, got {actual}",
            directory.display()
        );
        if let Some(max_count) = max_count {
            assert!(
                actual <= max_count,
                "{}: expected at most {max_count} {category}/{attack_state:?}, got {actual}",
                directory.display()
            );
        }
    }

    let unexpected = detections
        .iter()
        .filter(|detection| !expected_categories.contains(detection.category.as_str()))
        .map(|detection| detection.category.as_str())
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "{}: unexpected detections: {unexpected:?}",
        directory.display()
    );
}

fn attack_state_name(state: AttackState) -> &'static str {
    match state {
        AttackState::AttackAttempt => "attack_attempt",
        AttackState::Blocked => "blocked",
        AttackState::SuspectedSuccess => "suspected_success",
        AttackState::ConfirmedCompromise => "confirmed_compromise",
        AttackState::Unknown => "unknown",
    }
}
