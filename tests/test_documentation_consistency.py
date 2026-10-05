"""Deterministic drift checks for checked-in assessment documentation."""

import re
from collections import Counter
from pathlib import Path

from amazon_connect_assessment.checks.control_registry import (
    ExecutionSource,
    get_atomic_control_registry,
)
from amazon_connect_assessment.models import FindingDisposition, Pillar

REPO_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPO_ROOT / "README.md"
CATALOG_PATH = REPO_ROOT / "docs" / "check-catalog.md"
CURRENT_DOC_PATHS = (
    README_PATH,
    CATALOG_PATH,
    REPO_ROOT / "docs" / "report-formats.md",
    REPO_ROOT / "docs" / "configuration.md",
    REPO_ROOT / "docs" / "user-guide.md",
    REPO_ROOT / "docs" / "development-guide.md",
    REPO_ROOT / "docs" / "README.md",
)
CATALOG_CONTROL_ROW = re.compile(
    r"^\| `([a-z][a-z0-9-]*-\d{3})` \| .*? \| "
    r"(Control|Manual Review|Informational) \| (BaseCheck|Journey) \|$",
    re.MULTILINE,
)
LEGACY_ALIASES = {"journey-sec-001", "journey-cost-001"}
EXPECTED_IDS_BY_PILLAR = {
    Pillar.SECURITY: {
        "security-iam-001",
        "security-data-001",
        "sec-iam-deep-001",
        "sec-storage-001",
        "sec-origins-001",
        "sec-cloudtrail-001",
        "sec-federation-001",
        "sec-profile-audit-001",
        "ai-ops-guardrail-001",
        "ai-ops-encryption-001",
        "sec-lex-convlogs-001",
        "sec-prompt-inject-001",
        "sec-lambda-validation-001",
        "sec-toll-fraud-001",
        "sec-sensitive-data-001",
        "sec-pii-prompts-001",
        "sec-excessive-agency-001",
        "sec-flow-auth-001",
        "cx-personalization-001",
    },
    Pillar.RESILIENCE: {
        "ai-ops-cross-region-001",
        "res-quota-config-001",
        "res-quota-headroom-001",
        "res-quota-growth-001",
        "res-acgr-config-001",
        "res-acgr-identity-001",
        "res-acgr-tdg-status-001",
        "res-acgr-traffic-dist-001",
        "res-acgr-failover-test-001",
        "res-acgr-numbers-001",
        "res-cloudwatch-001",
        "res-carrier-diversity-001",
        "res-hardcoded-routing-001",
        "res-lambda-dependency-001",
        "res-acxd-error-routing-001",
        "res-flow-errors-001",
        "res-flow-loops-001",
        "journey-res-001",
    },
    Pillar.COST_OPTIMIZATION: {
        "cost-unused-001",
        "cost-inefficient-001",
        "cost-oversized-001",
        "cost-usage-metrics-001",
        "cost-unused-numbers-001",
        "cost-premium-features-001",
        "cost-hours-mismatch-001",
        "ai-ops-model-cost-001",
        "cost-containment-001",
        "cost-wait-time-001",
        "cost-occupancy-001",
        "cost-fcr-001",
        "cost-acw-001",
        "cost-data-continuity-001",
        "cost-self-service-tier-001",
        "journey-scope-001",
    },
    Pillar.OPERATIONAL_EXCELLENCE: {
        "ops-logging-001",
        "ops-early-media-001",
        "ops-auto-resolve-001",
        "ai-ops-kb-sync-001",
        "ai-ops-bedrock-logging-001",
        "ops-acxd-handoff-001",
        "ops-acxd-escalation-001",
        "ops-unreachable-blocks-001",
    },
    Pillar.PERFORMANCE_EFFICIENCY: {
        "perf-lambda-count-001",
        "perf-sequential-lambda-001",
        "perf-flow-complexity-001",
    },
}
EXPECTED_DISPOSITIONS = {
    FindingDisposition.CONTROL: 23,
    FindingDisposition.MANUAL_REVIEW: 25,
    FindingDisposition.INFORMATIONAL: 16,
}
EXPECTED_EXECUTORS = {ExecutionSource.BASE_CHECK: 60, ExecutionSource.JOURNEY: 4}
PILLAR_HEADINGS = {
    Pillar.SECURITY: "Security",
    Pillar.RESILIENCE: "Resilience",
    Pillar.COST_OPTIMIZATION: "Cost Optimization",
    Pillar.OPERATIONAL_EXCELLENCE: "Operational Excellence",
    Pillar.PERFORMANCE_EFFICIENCY: "Performance Efficiency",
}


def test_documentation_catalog_lists_exact_canonical_control_inventory():
    # Arrange
    catalog_registry = get_atomic_control_registry()
    expected_ids = set().union(*EXPECTED_IDS_BY_PILLAR.values())

    # Act
    catalog = CATALOG_PATH.read_text(encoding="utf-8")
    documented_rows = CATALOG_CONTROL_ROW.findall(catalog)
    documented_ids = [control_id for control_id, _, _ in documented_rows]
    runtime_ids = [control.control_id for control in catalog_registry]

    # Assert
    assert len(expected_ids) == 64
    assert Counter(runtime_ids) == Counter(expected_ids)
    assert Counter(documented_ids) == Counter(expected_ids)
    assert LEGACY_ALIASES.isdisjoint(documented_ids)


def test_documentation_catalog_matches_pillar_disposition_and_executor_totals():
    # Arrange
    catalog_registry = get_atomic_control_registry()
    expected_pillar_counts = {
        pillar: len(control_ids) for pillar, control_ids in EXPECTED_IDS_BY_PILLAR.items()
    }

    # Act
    runtime_pillar_ids = {
        pillar: {control.control_id for control in catalog_registry if control.pillar == pillar}
        for pillar in Pillar
    }
    runtime_dispositions = Counter(control.disposition for control in catalog_registry)
    runtime_executors = Counter(control.execution_source for control in catalog_registry)
    catalog = CATALOG_PATH.read_text(encoding="utf-8")
    documented_rows = CATALOG_CONTROL_ROW.findall(catalog)
    documented_dispositions = Counter(row[1].lower().replace(" ", "_") for row in documented_rows)
    documented_executors = Counter(row[2] for row in documented_rows)

    # Assert
    assert runtime_pillar_ids == EXPECTED_IDS_BY_PILLAR
    assert runtime_dispositions == EXPECTED_DISPOSITIONS
    assert runtime_executors == EXPECTED_EXECUTORS
    assert documented_dispositions == {
        "control": 23,
        "manual_review": 25,
        "informational": 16,
    }
    assert documented_executors == {"BaseCheck": 60, "Journey": 4}
    for pillar, count in expected_pillar_counts.items():
        assert f"### {PILLAR_HEADINGS[pillar]} — {count} controls" in catalog


def test_current_methodology_docs_describe_unified_scoring_and_output_contracts():
    # Arrange
    required_phrases = {
        "64 canonical controls",
        "60 BaseCheck",
        "4 Journey",
        "scored-control denominator",
        "MANUAL_REVIEW",
        "INFORMATIONAL",
        "failed `CONTROL` records only",
        "journey-sec-001",
        "journey-cost-001",
    }
    obsolete_phrases = {
        "59 registered checks",
        "59 assessment checks",
        "plus 4 separately scored",
        "not returned by `--list-checks`",
        "will not appear in `--list-checks`",
    }

    # Act
    documentation = "\n".join(path.read_text(encoding="utf-8") for path in CURRENT_DOC_PATHS)

    # Assert
    for phrase in required_phrases:
        assert phrase in documentation
    for phrase in obsolete_phrases:
        assert phrase not in documentation
    assert "`journey-res-001` | Dead-End Caller Path | High | Control | Journey" in (
        CATALOG_PATH.read_text(encoding="utf-8")
    )
    assert "`journey-scope-001` | Dormant Flows Detected | Low | Manual Review | Journey" in (
        CATALOG_PATH.read_text(encoding="utf-8")
    )


def test_documentation_iam_guidance_uses_canonical_artifacts():
    # Arrange
    expected_json = "docs/iam-policy-template.json"
    expected_cloudformation = "cloudformation/AmazonConnectSelfAssessmentPolicy.yaml"
    stale_cloudformation = "cloudformation/RescoConnectSelfAssessmentPolicy.yaml"

    # Act
    documentation = "\n".join(
        [
            README_PATH.read_text(encoding="utf-8"),
            CATALOG_PATH.read_text(encoding="utf-8"),
        ]
    )

    # Assert
    assert expected_json in documentation
    assert expected_cloudformation in documentation
    assert stale_cloudformation not in documentation
    assert "qconnect:" not in documentation


def test_readme_offline_report_does_not_claim_cdn_dependencies():
    # Arrange
    readme = README_PATH.read_text(encoding="utf-8")

    # Act
    report_section = readme.split("### 5. Open the report", 1)[1].split("---", 1)[0]

    # Assert
    assert "self-contained" in report_section
    assert "React/Cloudscape" in report_section
    assert "without a CDN" in report_section
    assert "Chart.js" not in report_section
    assert "Font Awesome" not in report_section
