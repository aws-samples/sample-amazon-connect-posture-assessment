"""Timestamps are recorded and rendered in UTC, whatever the host timezone."""

from datetime import datetime, timedelta, timezone

from amazon_connect_assessment.models import CheckStatus, Finding, Pillar, Severity, to_utc
from amazon_connect_assessment.report.asff_export import finding_to_asff
from amazon_connect_assessment.report_generator import ReportGenerator

# 07:00 in UTC-05:00 is 12:00 UTC.
EST = timezone(timedelta(hours=-5))
LOCAL = datetime(2026, 1, 1, 7, 0, 0, tzinfo=EST)


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
