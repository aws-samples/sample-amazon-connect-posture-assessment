"""
Tests for posture roadmap (Task 15), docs generator (Task 16).
"""

from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.docs_generator import DocsGenerator
from amazon_connect_assessment.models import (
    CheckStatus,
    Finding,
    FindingDisposition,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report.posture_roadmap import (
    generate_posture_roadmap,
)


def _make_finding(
    pillar,
    severity,
    status,
    disposition=FindingDisposition.CONTROL,
):
    return Finding(
        check_id=f"test-{pillar.value}-{status.value}",
        check_name="Test",
        pillar=pillar,
        severity=severity,
        status=status,
        resource_id="r1",
        resource_type="ConnectInstance",
        description="desc",
        remediation="fix it",
        disposition=disposition,
    )


# --- Posture roadmap (Task 15) ---


class TestPostureRoadmap:
    def test_all_pass_is_advanced(self):
        findings = [
            _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.PASS) for _ in range(5)
        ]
        roadmap = generate_posture_roadmap(findings)
        assert roadmap["security"].maturity_level == "Advanced"
        assert roadmap["security"].pass_rate == 100.0
        assert roadmap["security"].improvement_actions == []

    def test_half_pass_is_intermediate(self):
        findings = [
            _make_finding(Pillar.RESILIENCE, Severity.HIGH, CheckStatus.PASS),
            _make_finding(Pillar.RESILIENCE, Severity.HIGH, CheckStatus.FAIL),
        ]
        roadmap = generate_posture_roadmap(findings)
        assert roadmap["resilience"].maturity_level == "Intermediate"
        assert roadmap["resilience"].pass_rate == 50.0

    def test_mostly_fail_is_basic(self):
        findings = [
            _make_finding(Pillar.COST_OPTIMIZATION, Severity.MEDIUM, CheckStatus.FAIL)
            for _ in range(4)
        ] + [_make_finding(Pillar.COST_OPTIMIZATION, Severity.LOW, CheckStatus.PASS)]
        roadmap = generate_posture_roadmap(findings)
        assert roadmap["cost_optimization"].maturity_level == "Basic"

    def test_improvement_actions_ordered_by_severity(self):
        findings = [
            _make_finding(Pillar.SECURITY, Severity.LOW, CheckStatus.FAIL),
            _make_finding(Pillar.SECURITY, Severity.CRITICAL, CheckStatus.FAIL),
            _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.FAIL),
        ]
        roadmap = generate_posture_roadmap(findings)
        actions = roadmap["security"].improvement_actions
        assert actions[0]["severity"] == "critical"
        assert actions[1]["severity"] == "high"
        assert actions[2]["severity"] == "low"

    def test_empty_pillar_not_in_roadmap(self):
        findings = [
            _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.PASS),
        ]
        roadmap = generate_posture_roadmap(findings)
        assert "resilience" not in roadmap

    def test_not_applicable_excluded_from_maturity(self):
        # An N/A finding must not drag the score down or inflate it —
        # otherwise the ACGR audit checks (five NOT_APPLICABLE for ~95%
        # of instances) would collectively swamp the resilience score.
        findings = [
            _make_finding(Pillar.RESILIENCE, Severity.HIGH, CheckStatus.PASS),
            _make_finding(Pillar.RESILIENCE, Severity.HIGH, CheckStatus.NOT_APPLICABLE),
            _make_finding(Pillar.RESILIENCE, Severity.HIGH, CheckStatus.NOT_APPLICABLE),
        ]
        roadmap = generate_posture_roadmap(findings)
        # 1 PASS out of 1 evaluated (N/A excluded) → 100% pass rate.
        assert roadmap["resilience"].pass_rate == 100.0
        assert roadmap["resilience"].maturity_level == "Advanced"

    def test_skipped_excluded_from_maturity(self):
        # Same principle for SKIPPED: a check we couldn't evaluate must
        # not skew the maturity assessment.
        findings = [
            _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.PASS),
            _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.SKIPPED),
        ]
        roadmap = generate_posture_roadmap(findings)
        assert roadmap["security"].pass_rate == 100.0


# --- Docs generator (Task 16) ---


class TestDocsGenerator:
    def test_generated_catalog_includes_all_unified_selected_controls(self, tmp_path):
        # Arrange
        registry = CheckRegistry()
        register_all_checks(registry)
        output = str(tmp_path / "check-catalog.md")

        # Act
        DocsGenerator().generate_catalog(registry, output)
        content = open(output, encoding="utf-8").read()

        # Assert
        assert "| Control ID |" in content
        assert len(registry.get_selected_controls()) == 64
        for control in registry.get_selected_controls():
            assert control.control_id in content
        assert "sec-flow-auth-001" in content
        assert "cost-containment-001" in content
        assert "| `journey-sec-001` |" not in content
        assert "| `journey-cost-001` |" not in content

    def test_generated_catalog_includes_disposition_executor_and_methodology(self, tmp_path):
        # Arrange
        registry = CheckRegistry()
        register_all_checks(registry, check_ids={"sec-flow-auth-001", "security-iam-001"})
        output = str(tmp_path / "check-catalog.md")

        # Act
        DocsGenerator().generate_catalog(registry, output)
        content = open(output, encoding="utf-8").read()

        # Assert
        assert "Manual Review" in content
        assert "Journey" in content
        assert "Base Check" in content
        assert "Root condition" in content
        assert "Why this is assessed" in content
        assert "What the evidence cannot prove" in content
        assert "Verification and closure" in content

    def test_generated_catalog_has_all_pillars(self, tmp_path):
        # Arrange
        registry = CheckRegistry()
        register_all_checks(registry)
        output = str(tmp_path / "check-catalog.md")

        # Act
        DocsGenerator().generate_catalog(registry, output)
        content = open(output, encoding="utf-8").read()

        # Assert
        assert "## Security" in content
        assert "## Resilience" in content
        assert "## Cost Optimization" in content
        assert "## Operational Excellence" in content
        assert "## Performance Efficiency" in content


def test_roadmap_mixed_dispositions_counts_only_scored_controls_and_failed_actions():
    # Arrange
    findings = [
        _make_finding(Pillar.SECURITY, Severity.HIGH, CheckStatus.PASS),
        _make_finding(Pillar.SECURITY, Severity.CRITICAL, CheckStatus.FAIL),
        _make_finding(
            Pillar.SECURITY,
            Severity.CRITICAL,
            CheckStatus.FAIL,
            FindingDisposition.MANUAL_REVIEW,
        ),
        _make_finding(
            Pillar.SECURITY,
            Severity.CRITICAL,
            CheckStatus.FAIL,
            FindingDisposition.INFORMATIONAL,
        ),
    ]

    # Act
    posture = generate_posture_roadmap(findings)["security"]

    # Assert
    assert posture.total_checks == 4
    assert posture.passed_checks == 1
    assert posture.scored_control_denominator == 2
    assert posture.pass_rate == 50.0
    assert len(posture.improvement_actions) == 1
