"""
Tests for the ASFF (AWS Security Finding Format) export module.

Regression coverage for two schema-validity bugs that would have caused
Security Hub's BatchImportFindings to reject every finding this exporter
produces:

1. Resources[].Type was built as f"AwsConnect{resource_type}" (e.g.
   "AwsConnectContactFlow", "AwsConnectInstance"). ASFF only recognizes a
   fixed enum of resource types (AwsEc2Instance, AwsS3Bucket, etc) plus
   the literal fallback "Other" — there is no "AwsConnect*" family in the
   spec for any resource_type value, so every finding would fail schema
   validation. Fixed to use "Other" with the specific Connect resource
   type preserved in Resources[].Tags.

2. Description/Title/Remediation.Recommendation.Text had no length cap,
   but ASFF enforces field length limits (BatchImportFindings rejects
   the whole finding if exceeded). Since finding descriptions in this
   tool are markdown-authored and can run well past 1024 characters,
   uncapped export would reject findings outright. Fixed with
   _truncate().
"""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from amazon_connect_assessment.models import (
    CheckStatus,
    Finding,
    FindingDisposition,
    FindingMethodology,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report.asff_export import (
    _MAX_DESCRIPTION_LENGTH,
    _MAX_REMEDIATION_TEXT_LENGTH,
    _MAX_TITLE_LENGTH,
    _truncate,
    export_asff,
    finding_to_asff,
)


def _finding(**overrides) -> Finding:
    defaults = dict(
        check_id="sec-toll-fraud-001",
        check_name="Toll Fraud Vector",
        pillar=Pillar.SECURITY,
        severity=Severity.CRITICAL,
        status=CheckStatus.FAIL,
        resource_id="flow-123",
        resource_type="ContactFlow",
        description="A short description.",
        remediation="A short remediation.",
        evidence={},
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestResourceTypeIsValidASFFEnum:
    def test_resource_type_is_other_not_aws_connect_prefixed(self):
        finding = _finding(resource_type="ContactFlow")
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        resource = asff["Resources"][0]
        assert resource["Type"] == "Other"
        assert resource["Type"] != "AwsConnectContactFlow"

    def test_specific_connect_resource_type_preserved_in_tags(self):
        finding = _finding(resource_type="ConnectInstance")
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        resource = asff["Resources"][0]
        assert resource["Tags"]["ConnectResourceType"] == "ConnectInstance"

    def test_resource_id_and_region_still_populated(self):
        finding = _finding(resource_id="abc-def", resource_type="Queue")
        asff = finding_to_asff(finding, account_id="123456789012", region="eu-west-1")
        resource = asff["Resources"][0]
        assert resource["Id"] == "abc-def"
        assert resource["Region"] == "eu-west-1"


class TestFieldLengthTruncation:
    def test_short_fields_are_not_truncated(self):
        finding = _finding(description="short", remediation="also short")
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert asff["Description"] == "short"
        assert asff["Remediation"]["Recommendation"]["Text"] == "also short"

    def test_long_description_is_truncated_to_asff_limit(self):
        long_desc = "x" * 5000
        finding = _finding(description=long_desc)
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert len(asff["Description"]) <= _MAX_DESCRIPTION_LENGTH
        assert asff["Description"].endswith("[truncated]")

    def test_long_remediation_text_is_truncated(self):
        long_remediation = "y" * 5000
        finding = _finding(remediation=long_remediation)
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        text = asff["Remediation"]["Recommendation"]["Text"]
        assert len(text) <= _MAX_REMEDIATION_TEXT_LENGTH

    def test_long_title_is_truncated(self):
        finding = _finding(check_name="z" * 1000)
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert len(asff["Title"]) <= _MAX_TITLE_LENGTH

    def test_truncate_helper_handles_empty_and_none(self):
        assert _truncate("", 10) == ""
        assert _truncate(None, 10) is None

    def test_truncate_helper_never_exceeds_max_length(self):
        result = _truncate("a" * 2000, 100)
        assert len(result) <= 100
        assert result.endswith("[truncated]")


class TestFindingToAsffBasicShape:
    def test_severity_mapping(self):
        finding = _finding(severity=Severity.HIGH)
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert asff["Severity"]["Label"] == "HIGH"

    def test_compliance_status_mapping(self):
        finding = _finding(status=CheckStatus.FAIL)
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert asff["Compliance"]["Status"] == "FAILED"

    def test_schema_version_present(self):
        finding = _finding()
        asff = finding_to_asff(finding, account_id="123456789012", region="us-east-1")
        assert asff["SchemaVersion"] == "2018-10-08"

    def test_export_uses_filename_template(self, tmp_path):
        result = SimpleNamespace(
            findings=[_finding()],
            account_id="123456789012",
            region="us-east-1",
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            assessment_id="assessment-123",
        )

        path = export_asff(
            result,
            str(tmp_path),
            filename_template="assessment_{assessment_id}_{region}",
        )

        assert path == str(tmp_path / "assessment_assessment-123_us-east-1.json")

    def test_export_rejects_path_template(self, tmp_path):
        result = SimpleNamespace(
            findings=[_finding()],
            account_id="123456789012",
            region="us-east-1",
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            assessment_id="assessment-123",
        )

        with pytest.raises(ValueError, match="filename, not a path"):
            export_asff(result, str(tmp_path), filename_template="../outside/report")


@pytest.mark.parametrize(
    ("status", "disposition", "expected_count"),
    [
        (CheckStatus.PASS, FindingDisposition.CONTROL, 0),
        (CheckStatus.FAIL, FindingDisposition.CONTROL, 1),
        (CheckStatus.ERROR, FindingDisposition.CONTROL, 0),
        (CheckStatus.SKIPPED, FindingDisposition.CONTROL, 0),
        (CheckStatus.NOT_APPLICABLE, FindingDisposition.CONTROL, 0),
        (CheckStatus.PASS, FindingDisposition.MANUAL_REVIEW, 0),
        (CheckStatus.FAIL, FindingDisposition.MANUAL_REVIEW, 0),
        (CheckStatus.ERROR, FindingDisposition.MANUAL_REVIEW, 0),
        (CheckStatus.SKIPPED, FindingDisposition.MANUAL_REVIEW, 0),
        (CheckStatus.NOT_APPLICABLE, FindingDisposition.MANUAL_REVIEW, 0),
        (CheckStatus.PASS, FindingDisposition.INFORMATIONAL, 0),
        (CheckStatus.FAIL, FindingDisposition.INFORMATIONAL, 0),
        (CheckStatus.ERROR, FindingDisposition.INFORMATIONAL, 0),
        (CheckStatus.SKIPPED, FindingDisposition.INFORMATIONAL, 0),
        (CheckStatus.NOT_APPLICABLE, FindingDisposition.INFORMATIONAL, 0),
    ],
)
def test_asff_disposition_status_matrix_exports_only_failed_controls(
    status, disposition, expected_count, tmp_path
):
    # Arrange
    result = SimpleNamespace(
        findings=[_finding(status=status, disposition=disposition)],
        account_id="123456789012",
        region="us-east-1",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        assessment_id="assessment-123",
    )

    # Act
    path = export_asff(result, str(tmp_path))
    with open(path, encoding="utf-8") as report_file:
        payload = json.load(report_file)

    # Assert
    assert len(payload["Findings"]) == expected_count
    if expected_count:
        assert payload["Findings"][0]["Compliance"]["Status"] == "FAILED"


def test_asff_methodology_content_is_bounded_and_preserved(tmp_path):
    # Arrange
    methodology = FindingMethodology(
        reason="r" * 2000,
        evidence_source="Connect API",
        proof_limitations="Does not prove operations",
        developer_admin_meaning="Review this control",
        verification_criteria="Capture approved evidence",
        responsible_function="Security",
        primary_lens_reference="SEC-1",
    )
    result = SimpleNamespace(
        findings=[
            _finding(
                disposition=FindingDisposition.CONTROL,
                methodology=methodology,
                instance_id="instance-123",
            )
        ],
        account_id="123456789012",
        region="us-east-1",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        assessment_id="assessment-123",
    )

    # Act
    path = export_asff(result, str(tmp_path))
    with open(path, encoding="utf-8") as report_file:
        finding = json.load(report_file)["Findings"][0]

    # Assert
    fields = finding["ProductFields"]
    assert fields["amazon-connect-assessment/disposition"] == "control"
    assert fields["amazon-connect-assessment/instance-id"] == "instance-123"
    assert len(fields["amazon-connect-assessment/reason"]) <= 512
    assert fields["amazon-connect-assessment/verification-criteria"] == (
        "Capture approved evidence"
    )


def test_asff_top_level_identity_preserves_legacy_resource_shape_with_instance_id():
    # Arrange
    finding = _finding(instance_id="instance-123", resource_id="flow-123")

    # Act
    payload = finding_to_asff(
        finding,
        account_id="123456789012",
        region="us-east-1",
    )

    # Assert
    assert payload["Id"] == "amazon-connect-assessment/sec-toll-fraud-001/flow-123"


@pytest.mark.parametrize(
    ("canonical_id", "legacy_provider_id"),
    [
        ("sec-flow-auth-001", "journey-sec-001"),
        ("cost-containment-001", "journey-cost-001"),
    ],
)
def test_asff_renamed_journey_identity_uses_legacy_alias_and_canonical_field(
    canonical_id, legacy_provider_id
):
    # Arrange
    finding = _finding(
        check_id=canonical_id,
        instance_id="instance-123",
        resource_id="flow-123",
    )

    # Act
    payload = finding_to_asff(
        finding,
        account_id="123456789012",
        region="us-east-1",
    )

    # Assert
    assert payload["Id"] == (f"amazon-connect-assessment/{legacy_provider_id}/flow-123")
    assert payload["ProductFields"]["amazon-connect-assessment/check-id"] == canonical_id


@pytest.mark.parametrize(
    ("canonical_id", "legacy_id"),
    [
        ("sec-flow-auth-001", "journey-sec-001"),
        ("cost-containment-001", "journey-cost-001"),
    ],
)
def test_asff_legacy_and_canonical_journey_ids_resolve_to_same_golden_identity(
    canonical_id, legacy_id
):
    # Arrange
    canonical = _finding(check_id=canonical_id, resource_id="flow-123")
    legacy = _finding(check_id=legacy_id, resource_id="flow-123")

    # Act
    canonical_payload = finding_to_asff(
        canonical,
        account_id="123456789012",
        region="us-east-1",
    )
    legacy_payload = finding_to_asff(
        legacy,
        account_id="123456789012",
        region="us-east-1",
    )

    # Assert
    assert canonical_payload["Id"] == legacy_payload["Id"]
    assert (
        canonical_payload["ProductFields"]["amazon-connect-assessment/check-id"]
        == (legacy_payload["ProductFields"]["amazon-connect-assessment/check-id"])
    )
