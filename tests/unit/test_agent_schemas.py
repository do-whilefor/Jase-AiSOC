from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel

from aisoc.domain.schema_export import (
    SCHEMA_MODELS,
    export_all_schemas,
    render_model_schema,
    stale_schemas,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(("filename", "model"), SCHEMA_MODELS.items())
def test_checked_in_contract_schema_matches_canonical_model(
    filename: str,
    model: type[BaseModel],
) -> None:
    path = ROOT / "schemas" / filename

    assert path.read_text(encoding="utf-8") == render_model_schema(model)
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_schema_staleness_check_detects_a_modified_artifact(tmp_path: Path) -> None:
    exported = export_all_schemas(tmp_path)
    assert stale_schemas(tmp_path) == ()

    exported[0].write_text("{}\n", encoding="utf-8")
    assert stale_schemas(tmp_path) == (exported[0],)
