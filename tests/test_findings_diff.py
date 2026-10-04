"""Regression tests for assessment finding diff behavior."""

from amazon_connect_assessment.report.findings_diff import compute_diff, print_diff


def _finding(
    check_id: str,
    resource_id: str,
    suffix: str,
    *,
    instance_id: str | None = None,
    disposition: str | None = None,
    remediation: str | None = None,
    verification: str | None = None,
) -> dict:
    finding = {
        "check_id": check_id,
        "resource_id": resource_id,
        "status": "FAIL",
        "evidence": suffix,
    }
    if instance_id is not None:
        finding["instance_id"] = instance_id
    if disposition is not None:
        finding["disposition"] = disposition
    if remediation is not None:
        finding["remediation"] = remediation
    if verification is not None:
        finding["methodology"] = {"verification_criteria": verification}
    return finding


def test_duplicate_findings_are_counted_and_preserved():
    baseline = [
        _finding("check-a", "resource-1", "baseline-1"),
        _finding("check-a", "resource-1", "baseline-2"),
    ]
    current = [
        _finding("check-a", "resource-1", "current-1"),
        _finding("check-a", "resource-1", "current-2"),
        _finding("check-b", "resource-2", "new"),
    ]

    diff = compute_diff(baseline, current)

    assert diff.baseline_total == 2
    assert diff.current_total == 3
    assert len(diff.persistent) == 2
    assert len(diff.resolved) == 0
    assert len(diff.new) == 1
    assert diff.new[0]["check_id"] == "check-b"


def test_duplicate_count_decrease_marks_excess_records_resolved():
    baseline = [
        _finding("check-a", "resource-1", "baseline-1"),
        _finding("check-a", "resource-1", "baseline-2"),
    ]
    current = [_finding("check-a", "resource-1", "current-1")]

    diff = compute_diff(baseline, current)

    assert diff.baseline_total == 2
    assert diff.current_total == 1
    assert len(diff.persistent) == 1
    assert len(diff.resolved) == 1
    assert diff.resolved[0]["evidence"] == "baseline-2"


def test_findings_diff_legacy_aliases_match_canonical_control_ids():
    # Arrange
    baseline = [
        _finding("journey-sec-001", "flow-1", "old", instance_id="instance-1"),
        _finding("journey-cost-001", "flow-2", "old", instance_id="instance-1"),
    ]
    current = [
        _finding("sec-flow-auth-001", "flow-new", "new", instance_id="instance-1"),
        _finding("cost-containment-001", "flow-new", "new", instance_id="instance-1"),
    ]

    # Act
    diff = compute_diff(baseline, current)

    # Assert
    assert len(diff.persistent) == 2
    assert diff.resolved == []
    assert diff.new == []


def test_findings_diff_instance_identity_separates_same_control_across_instances():
    # Arrange
    baseline = [_finding("check-a", "flow-1", "old", instance_id="instance-1")]
    current = [_finding("check-a", "flow-1", "new", instance_id="instance-2")]

    # Act
    diff = compute_diff(baseline, current)

    # Assert
    assert len(diff.resolved) == 1
    assert len(diff.new) == 1
    assert diff.persistent == []


def test_findings_diff_dispositions_ignore_information_and_separate_review_candidates():
    # Arrange
    baseline = [
        _finding("legacy-control", "resource-1", "legacy"),
        _finding("review-a", "resource-2", "old", disposition="manual_review"),
        _finding("info-a", "resource-3", "old", disposition="informational"),
    ]
    current = [
        _finding("legacy-control", "resource-1", "current"),
        _finding("review-b", "resource-4", "new", disposition="manual_review"),
        _finding("info-b", "resource-5", "new", disposition="informational"),
    ]

    # Act
    diff = compute_diff(baseline, current)

    # Assert
    assert len(diff.persistent) == 1
    assert diff.baseline_total == 1
    assert diff.current_total == 1
    assert diff.baseline_manual_review_total == 1
    assert diff.current_manual_review_total == 1
    assert len(diff.manual_review_resolved) == 1
    assert len(diff.manual_review_new) == 1
    assert all("info" not in finding["check_id"] for finding in diff.resolved + diff.new)


def test_findings_diff_printed_items_include_action_and_verification(capsys):
    # Arrange
    current = [
        _finding(
            "check-a",
            "resource-1",
            "new",
            remediation="Update the setting",
            verification="Confirm the approved value",
        )
    ]
    diff = compute_diff([], current)

    # Act
    print_diff(diff)
    output = capsys.readouterr().out

    # Assert
    assert "Action: Update the setting" in output
    assert "Verification: Confirm the approved value" in output


def test_baseline_without_instance_id_matches_current_by_resource_identity():
    baseline = [_finding("ops-logging-001", "res-1", "old")]
    current = [_finding("ops-logging-001", "res-1", "new", instance_id="inst-1")]

    diff = compute_diff(baseline, current)

    assert (len(diff.resolved), len(diff.new), len(diff.persistent)) == (0, 0, 1)


def test_baseline_without_disposition_defaults_to_control():
    baseline = [_finding("ops-logging-001", "res-1", "old")]
    baseline[0]["disposition"] = None
    current = [_finding("ops-logging-001", "res-1", "new", disposition="control")]

    diff = compute_diff(baseline, current)

    assert (len(diff.resolved), len(diff.new), len(diff.persistent)) == (0, 0, 1)


def test_load_findings_skips_non_dict_entries(tmp_path, caplog):
    import json

    from amazon_connect_assessment.report.findings_diff import load_findings_from_json

    path = tmp_path / "report.json"
    good = _finding("ops-logging-001", "res-1", "x")
    path.write_text(json.dumps({"findings": [good, "oops", None, 3]}))

    with caplog.at_level("WARNING"):
        loaded = load_findings_from_json(str(path))

    assert loaded == [good]
    assert "skipped 3 non-object" in caplog.text


def test_load_findings_rejects_non_list_container(tmp_path):
    import json

    import pytest

    from amazon_connect_assessment.report.findings_diff import load_findings_from_json

    path = tmp_path / "report.json"
    path.write_text(json.dumps({"findings": {"a": 1}}))

    with pytest.raises(ValueError):
        load_findings_from_json(str(path))
