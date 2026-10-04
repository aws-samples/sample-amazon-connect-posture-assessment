"""Regression coverage for the deterministic canonical sample report."""

import importlib.util
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from amazon_connect_assessment.checks.control_registry import get_atomic_control_registry
from amazon_connect_assessment.models import CheckStatus, FindingDisposition
from amazon_connect_assessment.report_generator import ReportGenerator
from amazon_connect_assessment.score_policy import compute_scored_control_counts

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_sample_report.py"
CHECKED_IN_SAMPLE = REPO_ROOT / "examples" / "sample_assessment_report.html"


def _load_sample_module():
    spec = importlib.util.spec_from_file_location("canonical_sample_report", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    scripts_path = str(SCRIPT_PATH.parent)
    sys.path.insert(0, scripts_path)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(scripts_path)
    return module


SAMPLE_REPORT = _load_sample_module()


def test_sample_result_contains_each_canonical_control_once_per_instance():
    # Arrange
    catalog = get_atomic_control_registry()
    canonical_ids = {control.control_id for control in catalog}

    # Act
    result = SAMPLE_REPORT.build_sample_result(SAMPLE_REPORT.SAMPLE_SEED)
    ids_by_instance = defaultdict(list)
    for finding in result.findings:
        ids_by_instance[finding.instance_id].append(finding.check_id)

    # Assert
    assert len(canonical_ids) == 64
    assert set(ids_by_instance) == {instance.instance_id for instance in result.instances}
    for instance_ids in ids_by_instance.values():
        assert Counter(instance_ids) == Counter(canonical_ids)
    assert len(result.findings) == 64 * len(result.instances)
    assert "journey-sec-001" not in {finding.check_id for finding in result.findings}
    assert "journey-cost-001" not in {finding.check_id for finding in result.findings}
    structure_findings = [
        finding for finding in result.findings if finding.check_id == "perf-flow-complexity-001"
    ]
    assert len(structure_findings) == len(result.instances)
    for finding in structure_findings:
        records = finding.evidence["flow_structural_metrics"]
        assert len(records) == 2
        assert len(records[0]) == 11


def test_sample_result_preserves_catalog_metadata_and_representative_outcomes():
    # Arrange
    catalog = get_atomic_control_registry()

    # Act
    result = SAMPLE_REPORT.build_sample_result(SAMPLE_REPORT.SAMPLE_SEED)
    statuses = {finding.status for finding in result.findings}
    dispositions = {finding.disposition for finding in result.findings}

    # Assert
    assert statuses == set(CheckStatus)
    assert dispositions == set(FindingDisposition)
    for finding in result.findings:
        control = catalog.get(finding.check_id)
        assert finding.check_name == control.name
        assert finding.pillar == control.pillar
        assert finding.severity == control.default_severity
        assert finding.disposition == control.disposition
        assert finding.methodology is control.methodology
        assert finding.instance_id is not None


def test_sample_summary_matches_shared_scored_control_policy():
    # Arrange
    result = SAMPLE_REPORT.build_sample_result(SAMPLE_REPORT.SAMPLE_SEED)

    # Act
    numerator, denominator = compute_scored_control_counts(result.findings)
    status_counts = Counter(finding.status for finding in result.findings)
    disposition_counts = Counter(finding.disposition for finding in result.findings)

    # Assert
    assert result.summary.total_checks == len(result.findings)
    assert result.summary.scored_control_numerator == numerator
    assert result.summary.scored_control_denominator == denominator
    assert result.summary.passed_checks == status_counts[CheckStatus.PASS]
    assert result.summary.failed_checks == status_counts[CheckStatus.FAIL]
    assert result.summary.skipped_checks == status_counts[CheckStatus.SKIPPED]
    assert result.summary.error_checks == status_counts[CheckStatus.ERROR]
    assert result.summary.not_applicable_checks == status_counts[CheckStatus.NOT_APPLICABLE]
    assert result.summary.control_findings == disposition_counts[FindingDisposition.CONTROL]
    assert (
        result.summary.manual_review_findings
        == disposition_counts[FindingDisposition.MANUAL_REVIEW]
    )
    assert (
        result.summary.informational_findings
        == disposition_counts[FindingDisposition.INFORMATIONAL]
    )


def test_sample_html_exposes_disposition_methodology_and_canonical_ids():
    # Arrange
    result = SAMPLE_REPORT.build_sample_result(SAMPLE_REPORT.SAMPLE_SEED)

    # Act
    html = ReportGenerator().generate_html_report(
        result,
        include_raw_data=False,
        generated_at=SAMPLE_REPORT.SAMPLE_TIMESTAMP,
    )

    # Assert
    marker = '<script id="report-data" type="application/json">'
    start = html.index(marker) + len(marker)
    report_data = json.loads(html[start : html.index("</script>", start)])
    dispositions = {finding["disposition"] for finding in report_data["findings"]}
    ids = {finding["check_id"] for finding in report_data["findings"]}
    assert dispositions == {"control", "manual_review", "informational"}
    assert all(finding["methodology"] for finding in report_data["findings"])
    assert {
        "sec-flow-auth-001",
        "cost-containment-001",
        "journey-res-001",
        "journey-scope-001",
    } <= ids
    assert "journey-sec-001" not in ids
    assert "journey-cost-001" not in ids
    assert "ACXD_CONTEXT_VALUE_MARKER_DO_NOT_RENDER" not in html
    assert "workspace-example-001" in html
    assert "application-example-001" in html
    assert "accountToken" in html
    assert (
        report_data["stats"]["scored_control_numerator"] == result.summary.scored_control_numerator
    )
    assert (
        report_data["stats"]["scored_control_denominator"]
        == result.summary.scored_control_denominator
    )
    assert "Assessment methodology" in html


def test_checked_in_sample_matches_canonical_script_output(tmp_path):
    # Arrange
    generated_sample = tmp_path / "sample_assessment_report.html"

    # Act
    subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--output", str(generated_sample)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    # Assert
    assert generated_sample.read_bytes() == CHECKED_IN_SAMPLE.read_bytes()
