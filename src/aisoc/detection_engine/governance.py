"""Governance metadata for the bundled detection rules.

The source catalog is deliberately explicit and version-bound.  It does not
pretend that local unit/replay coverage closes the plan's Shadow, Canary, or
Released gates; every current rule remains Draft until real quality, rollout,
signature, and rollback evidence exists.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from aisoc.detection_engine.base import Rule
from aisoc.domain.rule_lifecycle import RuleLifecycleStage


@dataclass(frozen=True, slots=True)
class RuleGovernance:
    rule_id: str
    version: str
    title: str
    owner: str
    lifecycle_stage: RuleLifecycleStage
    data_sources: tuple[str, ...]
    test_datasets: tuple[str, ...]
    expected_false_positives: tuple[str, ...]
    technique_ids: tuple[str, ...]
    suppression_conditions: tuple[str, ...]
    rollback_plan: str
    runtime_note: str

    def __post_init__(self) -> None:
        if not self.rule_id or len(self.rule_id) > 128:
            raise ValueError("rule governance rule_id is invalid")
        if not self.version or len(self.version) > 32:
            raise ValueError("rule governance version is invalid")
        if not self.title or len(self.title) > 160:
            raise ValueError("rule governance title is invalid")
        if not self.owner or len(self.owner) > 128:
            raise ValueError("rule governance owner is invalid")
        for name, values, maximum in (
            ("data_sources", self.data_sources, 128),
            ("test_datasets", self.test_datasets, 256),
            ("expected_false_positives", self.expected_false_positives, 512),
            ("technique_ids", self.technique_ids, 32),
            ("suppression_conditions", self.suppression_conditions, 512),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"rule governance {name} must be sorted and unique")
            if any(not item or len(item) > maximum for item in values):
                raise ValueError(f"rule governance {name} contains an invalid value")
        if not self.rollback_plan or len(self.rollback_plan) > 1024:
            raise ValueError("rule governance rollback_plan is invalid")
        if not self.runtime_note or len(self.runtime_note) > 1024:
            raise ValueError("rule governance runtime_note is invalid")


_DRAFT_RUNTIME_NOTE = (
    "DetectionWorker emits only under the tenant's verified signed lifecycle manifest; "
    "without a current matching manifest this registered version is disabled."
)
_ROLLBACK = (
    "Import a higher-sequence signed rollback manifest bound to the current manifest hash; "
    "released rules return to exact canary scope and canaries return to shadow-only mode."
)


def _draft(
    rule_id: str,
    title: str,
    *,
    data_sources: tuple[str, ...],
    test_datasets: tuple[str, ...],
    expected_false_positives: tuple[str, ...],
    technique_ids: tuple[str, ...],
    suppression_conditions: tuple[str, ...],
) -> RuleGovernance:
    return RuleGovernance(
        rule_id=rule_id,
        version="0.1.0",
        title=title,
        owner="detection-research",
        lifecycle_stage=RuleLifecycleStage.DRAFT,
        data_sources=data_sources,
        test_datasets=test_datasets,
        expected_false_positives=expected_false_positives,
        technique_ids=technique_ids,
        suppression_conditions=suppression_conditions,
        rollback_plan=_ROLLBACK,
        runtime_note=_DRAFT_RUNTIME_NOTE,
    )


_CATALOG = {
    item.rule_id: item
    for item in (
        _draft(
            "auth.ssh.bruteforce",
            "SSH authentication failure burst",
            data_sources=("network.ssh",),
            test_datasets=("tests/replay/ssh_bruteforce",),
            expected_false_positives=(
                "authorized password rotation or vulnerability scanning from a known source",
            ),
            technique_ids=("T1110",),
            suppression_conditions=(
                "known scanner and maintenance identities require an external allowlist "
                "not yet implemented",
            ),
        ),
        _draft(
            "host.download.execute",
            "Downloaded file execution chain",
            data_sources=(
                "file.chmod",
                "file.creat",
                "file.open",
                "file.openat",
                "file.rename",
                "file.write",
                "process.exec",
            ),
            test_datasets=("tests/replay/host_success_chains",),
            expected_false_positives=("package installation and deployment automation",),
            technique_ids=("T1105",),
            suppression_conditions=(
                "signed package managers and approved deployment paths require asset "
                "policy context",
            ),
        ),
        _draft(
            "host.lateral.scan",
            "Internal lateral service scan",
            data_sources=("network.connect", "process.exec"),
            test_datasets=(
                "tests/replay/host_failed_attacks",
                "tests/replay/host_normal_baseline",
            ),
            expected_false_positives=("inventory, monitoring, and approved discovery tools",),
            technique_ids=("T1046",),
            suppression_conditions=(
                "approved scanner identity and target scope require an external allowlist",
            ),
        ),
        _draft(
            "host.persistence.change",
            "Suspicious persistence configuration change",
            data_sources=(
                "file.chmod",
                "file.creat",
                "file.open",
                "file.openat",
                "file.rename",
                "file.write",
            ),
            test_datasets=(
                "tests/replay/host_normal_baseline",
                "tests/replay/host_success_chains",
            ),
            expected_false_positives=("configuration management and administrator key rotation",),
            technique_ids=("T1053.003", "T1098.004", "T1543.002"),
            suppression_conditions=(
                "approved configuration-management actors and change windows require asset "
                "policy context",
            ),
        ),
        _draft(
            "host.web_process.shell",
            "Web process spawning a shell",
            data_sources=("process.exec",),
            test_datasets=(
                "tests/replay/host_normal_baseline",
                "tests/replay/host_success_chains",
            ),
            expected_false_positives=("administrative CGI and controlled diagnostic handlers",),
            technique_ids=("T1059.004",),
            suppression_conditions=(
                "approved handler path and parent identity require an external allowlist",
            ),
        ),
        _draft(
            "host.web_shell.outbound",
            "Web-spawned shell outbound connection",
            data_sources=("network.connect", "process.exec"),
            test_datasets=("tests/replay/host_success_chains",),
            expected_false_positives=("controlled health checks executed through a web handler",),
            technique_ids=("T1505.003",),
            suppression_conditions=(
                "approved handler, executable hash, and destination require policy context",
            ),
        ),
        _draft(
            "ioc.exact_match",
            "Pinned IOC exact match",
            data_sources=(
                "file.chmod",
                "file.creat",
                "file.open",
                "file.openat",
                "file.rename",
                "file.write",
                "network.connect",
                "network.http",
                "network.ssh",
                "process.exec",
            ),
            test_datasets=("tests/unit/detection/test_ioc_match.py",),
            expected_false_positives=(
                "stale or overly broad indicators supplied by an otherwise trusted local feed",
            ),
            technique_ids=("T1588.001",),
            suppression_conditions=(
                "feed curation and tenant-specific allowlisting remain deployment policy",
            ),
        ),
        _draft(
            "web.attack.injection",
            "Web request injection signature",
            data_sources=("network.http",),
            test_datasets=(
                "tests/replay/normal_baseline",
                "tests/replay/web_injection",
            ),
            expected_false_positives=("security testing and encoded application payloads",),
            technique_ids=("T1190",),
            suppression_conditions=(
                "approved scanner source and application route require tenant policy context",
            ),
        ),
        _draft(
            "web.recon.scanning",
            "High-volume web reconnaissance",
            data_sources=("network.http",),
            test_datasets=(
                "tests/replay/normal_baseline",
                "tests/replay/web_scan",
            ),
            expected_false_positives=("authorized scanners and high-cardinality crawler traffic",),
            technique_ids=("T1595",),
            suppression_conditions=(
                "approved scanner source and maintenance window require tenant policy context",
            ),
        ),
        _draft(
            "web.request.abnormal_method",
            "Uncommon HTTP method",
            data_sources=("network.http",),
            test_datasets=(
                "tests/replay/normal_baseline",
                "tests/replay/web_injection",
            ),
            expected_false_positives=("legitimate WebDAV, proxy, and debugging workflows",),
            technique_ids=("T1190",),
            suppression_conditions=(
                "approved method and route combinations require application policy context",
            ),
        ),
    )
}


def get_rule_governance(rule_id: str) -> RuleGovernance | None:
    return _CATALOG.get(rule_id)


def list_rule_governance() -> tuple[RuleGovernance, ...]:
    return tuple(_CATALOG[key] for key in sorted(_CATALOG))


def validate_rule_governance(rules: Sequence[Rule]) -> tuple[RuleGovernance, ...]:
    by_id = {rule.rule_id: rule for rule in rules}
    if len(by_id) != len(rules):
        raise RuntimeError("registered rule IDs are not unique")
    if set(by_id) != set(_CATALOG):
        missing = sorted(set(by_id) - set(_CATALOG))
        stale = sorted(set(_CATALOG) - set(by_id))
        raise RuntimeError(f"rule governance drift: missing={missing}, stale={stale}")
    for rule_id, rule in by_id.items():
        governance = _CATALOG[rule_id]
        if governance.version != rule.version:
            raise RuntimeError(f"rule governance version drift for {rule_id}")
        if governance.data_sources != tuple(sorted(rule.applicable_event_types)):
            raise RuntimeError(f"rule governance data-source drift for {rule_id}")
    return list_rule_governance()


__all__ = [
    "RuleGovernance",
    "RuleLifecycleStage",
    "get_rule_governance",
    "list_rule_governance",
    "validate_rule_governance",
]
