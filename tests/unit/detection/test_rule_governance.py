"""Version-bound governance metadata for every bundled detection rule."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from blue_team.detection_engine import get_rules, register_all
from blue_team.detection_engine.base import Rule
from blue_team.detection_engine.governance import (
    RuleLifecycleStage,
    validate_rule_governance,
)


def test_governance_catalog_covers_runtime_registry_without_claiming_release() -> None:
    register_all()
    rules = get_rules()
    governance = validate_rule_governance(rules)

    assert len(rules) == len(governance) == 9
    assert {item.rule_id for item in governance} == {item.rule_id for item in rules}
    for item in governance:
        assert item.lifecycle_stage is RuleLifecycleStage.DRAFT
        assert item.owner
        assert item.data_sources
        assert item.test_datasets
        assert item.expected_false_positives
        assert item.technique_ids
        assert item.suppression_conditions
        assert "signed rollback manifest" in item.rollback_plan
        assert "verified signed lifecycle manifest" in item.runtime_note
        assert "disabled" in item.runtime_note


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        ({"version": "9.9.9"}, "version drift"),
        ({"applicable_event_types": ("unexpected.event",)}, "data-source drift"),
    ),
)
def test_governance_validation_rejects_runtime_metadata_drift(
    replacement: dict[str, object],
    message: str,
) -> None:
    register_all()
    rules = get_rules()
    original = rules[0]
    values: dict[str, object] = {
        "rule_id": original.rule_id,
        "version": original.version,
        "applicable_event_types": original.applicable_event_types,
    }
    values.update(replacement)
    rules[0] = cast(Rule, SimpleNamespace(**values))

    with pytest.raises(RuntimeError, match=message):
        validate_rule_governance(rules)


def test_governance_validation_rejects_missing_catalog_entry() -> None:
    register_all()
    with pytest.raises(RuntimeError, match="rule governance drift"):
        validate_rule_governance(get_rules()[:-1])
