"""Timestamps are recorded and rendered in UTC, whatever the host timezone."""

import csv
import json
from datetime import datetime, timedelta, timezone

import pytest

from amazon_connect_assessment.models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    Finding,
    Pillar,
    Severity,
    to_utc,
)
from amazon_connect_assessment.report.asff_export import finding_to_asff
from amazon_connect_assessment.report_generator import ReportGenerator

# 07:00 in UTC-05:00 is 12:00 UTC.
EST = timezone(timedelta(hours=-5))
LOCAL = datetime(2026, 1, 1, 7, 0, 0, tzinfo=EST)
NAIVE_UTC = datetime(2026, 1, 1, 12, 0, 0)
EXPECTED_ISO_UTC = "2026-01-01T12:00:00+00:00"


def _finding(timestamp: datetime) -> Finding:
    return Finding(
        check_id="sec-001",
        check_name="Check",
        pillar=Pillar.SECURITY,
        severity=Severity.HIGH,
        status=CheckStatus.FAIL,
        resource_id="r",
        resource_type="Instance",
        description="d",
        remediation="r",
        timestamp=timestamp,
    )


def test_default_finding_timestamp_is_aware_utc():
    finding = Finding(
        check_id="c",
        check_name="c",
        pillar=Pillar.SECURITY,
        severity=Severity.LOW,
        status=CheckStatus.PASS,
        resource_id="r",
        resource_type="t",
        description="d",
        remediation="r",
    )
    assert finding.timestamp.utcoffset() == timedelta(0)


def test_to_utc_converts_aware_and_assumes_naive_is_utc():
    assert to_utc(LOCAL) == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert to_utc(datetime(2026, 1, 1, 12, 0, 0)).tzinfo is timezone.utc


def test_asff_created_at_is_true_utc():
    asff = finding_to_asff(_finding(LOCAL), account_id="111122223333", region="us-east-1")
    assert asff["CreatedAt"] == "2026-01-01T12:00:00.000000Z"


def test_html_display_time_is_true_utc():
    assert ReportGenerator()._format_datetime(LOCAL) == "2026-01-01 12:00:00 UTC"


def _assessment(timestamp: datetime) -> AssessmentResult:
    finding = _finding(timestamp)
    return AssessmentResult(
        assessment_id="assessment-utc",
        timestamp=timestamp,
        account_id="111122223333",
        region="us-east-1",
        instances=[],
        findings=[finding],
        summary=AssessmentSummary(1, 0, 1, 0, 0, 0, 1, 0, 0),
        metadata=AssessmentMetadata("1.0.0", 1.0, "111122223333", "us-east-1", "test", "3.12"),
    )


@pytest.mark.parametrize("timestamp", [LOCAL, NAIVE_UTC])
def test_json_timestamps_convert_aware_non_utc_and_naive_values_to_utc(timestamp, tmp_path):
    # Arrange
    result = _assessment(timestamp)

    # Act
    path = ReportGenerator().generate_json_report(result, str(tmp_path))
    with open(path, encoding="utf-8") as report_file:
        payload = json.load(report_file)

    # Assert
    assert payload["timestamp"] == EXPECTED_ISO_UTC
    assert payload["findings"][0]["timestamp"] == EXPECTED_ISO_UTC


@pytest.mark.parametrize("timestamp", [LOCAL, NAIVE_UTC])
def test_csv_finding_timestamp_converts_aware_non_utc_and_naive_values_to_utc(timestamp, tmp_path):
    # Arrange
    result = _assessment(timestamp)

    # Act
    path = ReportGenerator().generate_csv_report(result, str(tmp_path))
    with open(path, newline="", encoding="utf-8") as report_file:
        rows = list(csv.DictReader(report_file))

    # Assert
    assert rows[0]["Timestamp"] == EXPECTED_ISO_UTC


@pytest.mark.parametrize("timestamp", [LOCAL, NAIVE_UTC])
def test_report_filename_timestamp_converts_aware_non_utc_and_naive_values_to_utc(
    timestamp,
):
    # Arrange
    result = _assessment(timestamp)

    # Act
    filename = ReportGenerator()._generate_filename("assessment_{timestamp}", result, "json")

    # Assert
    assert filename == "assessment_20260101_120000.json"


@pytest.mark.parametrize("timestamp", [LOCAL, NAIVE_UTC])
def test_cloudscape_finding_timestamp_matches_assessment_utc_display(timestamp):
    # Arrange
    finding = _finding(timestamp)
    generator = ReportGenerator()

    # Act
    view = generator._finding_view(0, finding, {}, [])

    # Assert
    assert view["timestamp"] == "2026-01-01 12:00:00 UTC"
