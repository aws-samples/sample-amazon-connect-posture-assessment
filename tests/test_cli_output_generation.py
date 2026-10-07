from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

from amazon_connect_assessment.cli import run_assessment
from amazon_connect_assessment.models import (
    CheckStatus,
    Finding,
    FindingDisposition,
    Pillar,
    Severity,
)


class _FakeEngine:
    def __init__(self, result):
        self.result = result

    def run_assessment(self):
        return self.result


def _sample_result():
    return SimpleNamespace(
        assessment_id="assessment-123",
        account_id="123456789012",
        region="us-east-1",
        summary=SimpleNamespace(
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            critical_findings=0,
            high_findings=0,
        ),
    )


def test_run_assessment_passes_filename_template_to_report_generators(tmp_path):
    result = _sample_result()
    filename_template = "assessment_{account_id}_{region}"
    report_generator = Mock()
    report_generator._generate_filename.return_value = "assessment_123456789012_us-east-1.html"
    report_generator.generate_json_report.return_value = str(tmp_path / "reports" / "report.json")
    report_generator.generate_csv_report.return_value = str(tmp_path / "reports" / "report.csv")

    config = {
        "output": {
            "format": ["html", "json", "csv"],
            "directory": str(tmp_path / "custom-reports"),
            "filename_template": filename_template,
        },
        "cli": {},
    }

    with patch("amazon_connect_assessment.cli.ReportGenerator", return_value=report_generator):
        assert run_assessment(_FakeEngine(result), config) is True

    report_generator.generate_html_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports" / "assessment_123456789012_us-east-1.html"),
    )
    report_generator.generate_json_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports"),
        filename_template=filename_template,
    )
    report_generator.generate_csv_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports"),
        filename_template=filename_template,
    )
    assert (tmp_path / "custom-reports").is_dir()


def _cli_finding(status, disposition=FindingDisposition.CONTROL):
    return Finding(
        check_id=f"cli-{disposition.value}-{status.value}",
        check_name="CLI finding",
        pillar=Pillar.SECURITY,
        severity=Severity.HIGH,
        status=status,
        resource_id="resource-1",
        resource_type="ConnectInstance",
        description="Observed result",
        remediation="Action",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        disposition=disposition,
        instance_id="instance-1",
    )


def test_cli_mixed_dispositions_prints_distinct_posture_and_record_totals(tmp_path, capsys):
    # Arrange
    result = _sample_result()
    result.findings = [
        _cli_finding(CheckStatus.PASS),
        _cli_finding(CheckStatus.FAIL),
        _cli_finding(CheckStatus.SKIPPED),
        _cli_finding(CheckStatus.ERROR),
        _cli_finding(CheckStatus.NOT_APPLICABLE),
        _cli_finding(CheckStatus.FAIL, FindingDisposition.MANUAL_REVIEW),
        _cli_finding(CheckStatus.PASS, FindingDisposition.INFORMATIONAL),
    ]
    result.summary.total_checks = 7
    config = {"output": {"format": [], "directory": str(tmp_path)}, "cli": {}}

    # Act
    with patch("amazon_connect_assessment.cli.ReportGenerator", return_value=Mock()):
        succeeded = run_assessment(_FakeEngine(result), config)
    output = capsys.readouterr().out

    # Assert
    assert succeeded is True
    assert "Total records: 7" in output
    assert "Control posture: 1/2 (50.0%)" in output
    assert "Failed controls: 1" in output
    assert "Manual reviews: 1" in output
    assert "Manual-review candidates: 1" in output
    assert "Informational records: 1" in output
    assert "Unevaluated controls: 2" in output
    assert "Not applicable records: 1" in output
    assert "Execution errors: 1" in output
    assert "Passed:" not in output


def test_cli_zero_scored_controls_prints_not_scored(tmp_path, capsys):
    # Arrange
    result = _sample_result()
    result.findings = [
        _cli_finding(CheckStatus.SKIPPED),
        _cli_finding(CheckStatus.ERROR),
        _cli_finding(CheckStatus.NOT_APPLICABLE),
    ]
    result.summary.total_checks = 3
    config = {"output": {"format": [], "directory": str(tmp_path)}, "cli": {}}

    # Act
    with patch("amazon_connect_assessment.cli.ReportGenerator", return_value=Mock()):
        succeeded = run_assessment(_FakeEngine(result), config)
    output = capsys.readouterr().out

    # Assert
    assert succeeded is True
    assert "Control posture: 0/0 (Not scored)" in output
    assert "Unevaluated controls: 2" in output
    assert "Not applicable records: 1" in output
