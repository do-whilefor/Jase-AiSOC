from __future__ import annotations

import json

from pytest import CaptureFixture

from aisoc.platform.__main__ import main


def test_platform_probe_cli_emits_versioned_json(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "0.1.0"
    assert {collector["name"] for collector in payload["collectors"]} == {
        "journald",
        "auditd",
        "ebpf",
    }
