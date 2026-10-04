"""Focused regression tests for the Increment 1 methodology foundation."""

from dataclasses import FrozenInstanceError

import pytest

from amazon_connect_assessment.checks.base import BaseCheck, CheckContext
from amazon_connect_assessment.models import (
    AssessmentSummary,
    CheckStatus,
    Finding,
    FindingDisposition,
    FindingMethodology,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report.posture_roadmap import generate_posture_roadmap
from amazon_connect_assessment.score_policy import (
    FindingScoreClassification,
    classify_finding,
    compute_scored_control_counts,
    compute_scored_control_pass_rate,
)


def _finding(
    status: CheckStatus,
    disposition: FindingDisposition = FindingDisposition.CONTROL,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=f"methodology-{disposition.value}-{status.value}",
        check_name="Methodology test finding",
        pillar=Pillar.SECURITY,
        severity=severity,
        status=status,
        resource_id="resource-1",
        resource_type="ConnectInstance",
        description="Test finding",
        remediation="Test remediation",
        disposition=disposition,
    )


def _methodology() -> FindingMethodology:
    return FindingMethodology(
        reason="Explains why the check exists",
        evidence_source="Amazon Connect API",
        proof_limitations="API evidence does not prove operating practice",
        developer_admin_meaning="Review the configured control",
        verification_criteria="The configured value matches the approved standard",
        primary_lens_reference="SEC-1",
        responsible_function="Security",
    )


class _MethodologyCheck(BaseCheck):
    def execute(self, context: CheckContext) -> Finding:
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
        )


def test_models_legacy_constructors_preserve_methodology_defaults():
    # Arrange
    finding = _finding(CheckStatus.PASS)
    summary = AssessmentSummary(1, 1, 0, 0, 0, 0, 0, 0, 0)

    # Act
    defaults = (
        finding.disposition,
        finding.methodology,
        finding.instance_id,
        summary.scored_control_denominator,
        summary.manual_review_findings,
    )

    # Assert
    assert defaults == (FindingDisposition.CONTROL, None, None, 0, 0)
    assert FindingDisposition.CONTROL.value == "control"
    assert FindingDisposition.MANUAL_REVIEW.value == "manual_review"
    assert FindingDisposition.INFORMATIONAL.value == "informational"


def test_models_frozen_methodology_rejects_mutation():
    # Arrange
    methodology = _methodology()

    # Act
    new_reason = "Changed"

    # Assert
    with pytest.raises(FrozenInstanceError):
        methodology.reason = new_reason  # type: ignore[misc]


def test_base_check_declared_metadata_propagates_to_finding(check_context):
    # Arrange
    methodology = _methodology()
    check = _MethodologyCheck(
        check_id="manual-review-check",
        name="Manual review check",
        pillar=Pillar.SECURITY,
        severity=Severity.MEDIUM,
        disposition=FindingDisposition.MANUAL_REVIEW,
        methodology=methodology,
    )

    # Act
    finding = check.safe_execute(check_context)

    # Assert
    assert finding.disposition == FindingDisposition.MANUAL_REVIEW
    assert finding.methodology is methodology
    assert finding.instance_id == check_context.instance.instance_id


@pytest.mark.parametrize(
    ("status", "disposition", "expected"),
    [
        (CheckStatus.PASS, FindingDisposition.CONTROL, FindingScoreClassification.SCORED_PASS),
        (CheckStatus.FAIL, FindingDisposition.CONTROL, FindingScoreClassification.SCORED_FAIL),
        (
            CheckStatus.SKIPPED,
            FindingDisposition.CONTROL,
            FindingScoreClassification.UNEVALUATED_CONTROL,
        ),
        (
            CheckStatus.ERROR,
            FindingDisposition.CONTROL,
            FindingScoreClassification.UNEVALUATED_CONTROL,
        ),
        (
            CheckStatus.NOT_APPLICABLE,
            FindingDisposition.CONTROL,
            FindingScoreClassification.NOT_APPLICABLE,
        ),
        (
            CheckStatus.PASS,
            FindingDisposition.MANUAL_REVIEW,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.FAIL,
            FindingDisposition.MANUAL_REVIEW,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.SKIPPED,
            FindingDisposition.MANUAL_REVIEW,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.ERROR,
            FindingDisposition.MANUAL_REVIEW,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.NOT_APPLICABLE,
            FindingDisposition.MANUAL_REVIEW,
            FindingScoreClassification.NOT_APPLICABLE,
        ),
        (
            CheckStatus.PASS,
            FindingDisposition.INFORMATIONAL,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.FAIL,
            FindingDisposition.INFORMATIONAL,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.SKIPPED,
            FindingDisposition.INFORMATIONAL,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.ERROR,
            FindingDisposition.INFORMATIONAL,
            FindingScoreClassification.NON_SCORING,
        ),
        (
            CheckStatus.NOT_APPLICABLE,
            FindingDisposition.INFORMATIONAL,
            FindingScoreClassification.NOT_APPLICABLE,
        ),
    ],
)
def test_score_policy_status_disposition_matrix_returns_expected_classification(
    status, disposition, expected
):
    # Arrange
    finding = _finding(status, disposition)

    # Act
    classification = classify_finding(finding)

    # Assert
    assert classification == expected


def test_score_policy_mixed_findings_counts_only_control_pass_fail():
    # Arrange
    findings = [
        _finding(CheckStatus.PASS),
        _finding(CheckStatus.FAIL),
        _finding(CheckStatus.SKIPPED),
        _finding(CheckStatus.ERROR),
        _finding(CheckStatus.NOT_APPLICABLE),
        _finding(CheckStatus.PASS, FindingDisposition.MANUAL_REVIEW),
        _finding(CheckStatus.FAIL, FindingDisposition.INFORMATIONAL),
    ]

    # Act
    numerator, denominator = compute_scored_control_counts(findings)

    # Assert
    assert (numerator, denominator) == (1, 2)


def test_engine_mixed_dispositions_reports_disposition_aware_counts(assessment_engine):
    # Arrange
    findings = [
        _finding(CheckStatus.PASS),
        _finding(CheckStatus.FAIL, severity=Severity.CRITICAL),
        _finding(CheckStatus.ERROR),
        _finding(CheckStatus.SKIPPED),
        _finding(CheckStatus.NOT_APPLICABLE),
        _finding(CheckStatus.FAIL, FindingDisposition.MANUAL_REVIEW, Severity.CRITICAL),
        _finding(CheckStatus.FAIL, FindingDisposition.INFORMATIONAL, Severity.HIGH),
    ]

    # Act
    summary = assessment_engine._generate_summary(findings)

    # Assert
    assert summary.control_findings == 5
    assert summary.manual_review_findings == 1
    assert summary.informational_findings == 1
    assert summary.scored_control_passes == 1
    assert summary.scored_control_failures == 1
    assert summary.unevaluated_controls == 2
    assert summary.not_applicable_controls == 1
    assert summary.scored_control_numerator == 1
    assert summary.scored_control_denominator == 2
    assert summary.critical_findings == 1
    assert summary.high_findings == 0


def test_roadmap_non_control_failures_excludes_actions_and_score_impact():
    # Arrange
    findings = [
        _finding(CheckStatus.PASS),
        _finding(CheckStatus.FAIL, FindingDisposition.MANUAL_REVIEW, Severity.CRITICAL),
        _finding(CheckStatus.FAIL, FindingDisposition.INFORMATIONAL, Severity.HIGH),
    ]

    # Act
    posture = generate_posture_roadmap(findings)[Pillar.SECURITY.value]

    # Assert
    assert posture.passed_checks == 1
    assert posture.pass_rate == 100.0
    assert posture.maturity_level == "Advanced"
    assert posture.improvement_actions == []


def test_score_policy_zero_denominator_returns_none_pass_rate():
    # Arrange
    findings = [
        _finding(CheckStatus.SKIPPED),
        _finding(CheckStatus.ERROR),
        _finding(CheckStatus.NOT_APPLICABLE),
        _finding(CheckStatus.PASS, FindingDisposition.MANUAL_REVIEW),
    ]

    # Act
    pass_rate = compute_scored_control_pass_rate(findings)

    # Assert
    assert pass_rate is None


def test_roadmap_zero_scored_controls_returns_not_assessed():
    # Arrange
    findings = [
        _finding(CheckStatus.SKIPPED),
        _finding(CheckStatus.ERROR),
        _finding(CheckStatus.NOT_APPLICABLE),
    ]

    # Act
    posture = generate_posture_roadmap(findings)[Pillar.SECURITY.value]

    # Assert
    assert posture.pass_rate is None
    assert posture.maturity_level == "Not assessed"
    assert posture.improvement_actions == []
