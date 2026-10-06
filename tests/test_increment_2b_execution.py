"""Focused Increment 2B selection and canonical Journey execution tests."""

from unittest.mock import MagicMock, patch

import pytest

from amazon_connect_assessment.checks.contact_flow_behavior_checks import (
    AuthenticationPatternCheck,
)
from amazon_connect_assessment.checks.control_registry import get_atomic_control_registry
from amazon_connect_assessment.checks.cost_containment_checks import (
    SelfServiceContainmentCheck,
)
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.cli import list_available_checks, validate_run_inputs
from amazon_connect_assessment.engine import AssessmentEngine
from amazon_connect_assessment.journey import JourneyMappingOutput
from amazon_connect_assessment.journey.journey_scorer import (
    _score_single_path,
    generate_journey_findings,
)
from amazon_connect_assessment.journey.models import (
    JourneyMapResult,
    JourneyNode,
    JourneyPath,
    PhoneNumberEntry,
    SuperGraph,
    TierAssignment,
)
from amazon_connect_assessment.journey.path_enumerator import (
    enumerate_journeys_with_completeness,
)
from amazon_connect_assessment.models import (
    CheckStatus,
    ConnectInstance,
    ContactFlow,
    Finding,
    FindingDisposition,
    Pillar,
    Severity,
)
from amazon_connect_assessment.parallel_engine import ParallelAssessmentEngine


def _path(number: str, action_types: list[str], terminal_type: str = "agent_queue") -> JourneyPath:
    nodes = [
        JourneyNode(
            flow_id="flow-1",
            flow_name="Main IVR",
            action_id=f"action-{index}",
            action_type=action_type,
        )
        for index, action_type in enumerate(action_types)
    ]
    return JourneyPath(
        entry_number=number,
        entry_number_type="DID",
        nodes=nodes,
        terminal_type=terminal_type,
        terminal_details={"queue": "queue-1"} if terminal_type == "agent_queue" else {},
        flows_traversed=["flow-1"],
    )


def _result(paths: list[JourneyPath], *, complete: bool = True) -> JourneyMapResult:
    return JourneyMapResult(
        journeys=paths,
        scores={path.path_hash: _score_single_path(path) for path in paths},
        tier_assignments=[TierAssignment("flow-1", "Main IVR", "tier1_did", "phone")],
        enumeration_complete=complete,
        enumeration_limitations=[] if complete else ["per-entry path limit 1 reached"],
    )


def test_registry_combined_filters_use_and_semantics_expected_result():
    # Arrange
    registry = CheckRegistry()
    register_all_checks(registry)

    # Act
    checks = registry.get_filtered_checks(
        pillars=[Pillar.SECURITY],
        severities=[Severity.HIGH],
        check_ids=["security-iam-001", "sec-iam-deep-001"],
    )

    # Assert
    assert [check.check_id for check in checks] == ["sec-iam-deep-001"]


def test_registry_journey_only_alias_selection_keeps_canonical_plan_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry, check_ids={"journey-sec-001"})

    # Assert
    assert registry.list_check_ids() == []
    assert registry.list_control_ids() == ["sec-flow-auth-001"]
    assert registry.list_selected_journey_control_ids() == ["sec-flow-auth-001"]


def test_registry_alias_exclusion_removes_journey_selection_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(
        registry,
        check_ids={"sec-flow-auth-001", "journey-res-001"},
        exclude_check_ids={"journey-sec-001"},
    )

    # Assert
    assert registry.list_control_ids() == ["journey-res-001"]


def test_registry_alias_config_disable_removes_journey_selection_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(
        registry,
        check_ids={"sec-flow-auth-001"},
        checks_config={"journey-sec-001": {"enabled": False}},
    )

    # Assert
    assert registry.list_control_ids() == []
    assert registry.list_selected_journey_control_ids() == []


def test_cli_journey_only_selection_passes_validation_expected_result(tmp_path):
    # Arrange
    config = {
        "output": {"directory": str(tmp_path)},
        "cli": {
            "checks": ["journey-sec-001"],
            "exclude_checks": [],
            "skip_flow_analysis": False,
        },
    }

    # Act
    errors = validate_run_inputs(config)

    # Assert
    assert errors == []


def test_cli_canonical_list_omits_aliases_and_shows_disposition_expected_result(capsys):
    # Arrange
    registry = CheckRegistry()
    register_all_checks(registry, check_ids={"journey-sec-001", "journey-res-001"})

    # Act
    list_available_checks(registry)
    output = capsys.readouterr().out

    # Assert
    assert "sec-flow-auth-001" in output
    assert "journey-res-001" in output
    assert "journey-sec-001" not in output
    assert "MANUAL_REVIEW" in output
    assert "CONTROL" in output


def test_registration_overlapping_executors_are_retired_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry)
    executor_types = {type(check) for check in registry.get_all_checks()}

    # Assert
    assert AuthenticationPatternCheck not in executor_types
    assert SelfServiceContainmentCheck not in executor_types
    assert len(registry.list_check_ids()) == 60


def test_journey_prompt_only_path_is_not_self_service_expected_result():
    # Arrange
    path = _path("+18005550101", ["PlayPrompt", "MessageParticipant", "TransferToQueue"])

    # Act
    score = _score_single_path(path)

    # Assert
    assert score.has_self_service is False


def test_journey_multiple_affected_numbers_emit_one_aggregate_outcome_expected_result():
    # Arrange
    paths = [
        _path("+18005550101", ["PlayPrompt", "TransferToQueue"]),
        _path("+18005550202", ["MessageParticipant", "TransferToQueue"]),
    ]

    # Act
    findings = generate_journey_findings(
        _result(paths),
        instance_id="instance-1",
        selected_control_ids=["cost-containment-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.FAIL
    assert findings[0].evidence["affected_phone_numbers"] == [
        "***-***-0101",
        "***-***-0202",
    ]
    assert len(findings[0].evidence["representative_paths"]) == 2


def test_journey_complete_clean_resilience_emits_pass_expected_result():
    # Arrange
    path = _path("+18005550101", ["GetParticipantInput", "TransferToQueue"])

    # Act
    findings = generate_journey_findings(
        _result([path]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.PASS


def test_journey_no_phone_paths_emit_not_applicable_expected_result():
    # Arrange
    result = JourneyMapResult(
        tier_assignments=[TierAssignment("flow-1", "Main IVR", "tier3_dormant", "unreferenced")]
    )

    # Act
    findings = generate_journey_findings(
        result,
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.NOT_APPLICABLE


def test_journey_incomplete_clean_resilience_emits_skipped_expected_result():
    # Arrange
    path = _path("+18005550101", ["GetParticipantInput", "TransferToQueue"])

    # Act
    findings = generate_journey_findings(
        _result([path], complete=False),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.SKIPPED
    assert findings[0].evidence["enumeration_complete"] is False


def test_journey_direct_findings_use_canonical_catalog_metadata_expected_result():
    # Arrange
    catalog = get_atomic_control_registry()
    path = _path("+18005550101", ["PlayPrompt", "TransferToQueue"])

    # Act
    findings = generate_journey_findings(
        _result([path]),
        instance_id="instance-1",
        selected_control_ids=["journey-sec-001", "journey-cost-001"],
    )

    # Assert
    assert {finding.check_id for finding in findings} == {
        "sec-flow-auth-001",
        "cost-containment-001",
    }
    for finding in findings:
        control = catalog.get(finding.check_id)
        assert finding.check_name == control.name
        assert finding.pillar == control.pillar
        assert finding.severity == control.default_severity
        assert finding.disposition == control.disposition
        assert finding.methodology == control.methodology
        assert finding.instance_id == "instance-1"

    authentication_finding = next(
        finding for finding in findings if finding.check_id == "sec-flow-auth-001"
    )
    assert "This is called out because" in authentication_finding.description
    assert "unauthorized disclosure or account-change risk" in authentication_finding.description


def test_parallel_journey_only_selection_still_executes_journeys_expected_result():
    # Arrange
    engine = ParallelAssessmentEngine.__new__(ParallelAssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    engine.logger = MagicMock()
    engine._compute_journey_findings = MagicMock(return_value=[MagicMock()])
    instances = [MagicMock()]

    # Act
    findings = engine._execute_checks_parallel(instances)

    # Assert
    assert len(findings) == 1
    engine._compute_journey_findings.assert_called_once_with(instances)


def test_engine_sequential_execution_passes_selected_journey_controls_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.config = {}
    engine.logger = MagicMock()
    engine._execution_errors = []
    engine.aws_client_factory = MagicMock()
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-sec-001"})
    instance = ConnectInstance(
        instance_id="instance-1",
        instance_arn="arn:aws:connect:us-east-1:111111111111:instance/instance-1",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
    )
    instance.contact_flows = [
        ContactFlow(
            id="flow-1",
            arn="arn:aws:connect:us-east-1:111111111111:instance/instance-1/contact-flow/flow-1",
            name="Main IVR",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content={
                "Version": "2019-10-30",
                "StartAction": "a1",
                "Actions": [
                    {
                        "Identifier": "a1",
                        "Type": "TransferToQueue",
                        "Parameters": {"QueueId": "queue-1"},
                        "Transitions": {},
                    }
                ],
            },
        )
    ]

    # Act
    with patch(
        "amazon_connect_assessment.journey.run_journey_mapping",
        return_value=JourneyMappingOutput(result=JourneyMapResult(), findings=[]),
    ) as run_mapping:
        findings = engine._compute_journey_findings([instance])

    # Assert
    assert findings == []
    assert run_mapping.call_args.kwargs["selected_control_ids"] == ["sec-flow-auth-001"]


def test_journey_single_dormant_flow_emits_manual_review_candidate_expected_result():
    # Arrange
    result = JourneyMapResult(
        dormant_flows=["flow-dormant"],
        tier_assignments=[
            TierAssignment("flow-dormant", "Old Flow", "tier3_dormant", "not phone reachable")
        ],
    )

    # Act
    findings = generate_journey_findings(
        result,
        instance_id="instance-1",
        selected_control_ids=["journey-scope-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.FAIL
    assert findings[0].disposition.value == "manual_review"
    assert "zero traffic" not in findings[0].description.lower()
    assert "delete" not in findings[0].remediation.lower()


def test_engine_duplicate_control_instance_outcomes_fail_validation_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["GetParticipantInput", "TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]

    # Act / Assert
    with pytest.raises(ValueError, match="Duplicate control outcome"):
        engine._validate_emitted_findings([finding, finding])


def test_registry_effective_declared_severity_filters_after_override_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(
        registry,
        severities={"low"},
        check_ids={"security-iam-001"},
        checks_config={"security-iam-001": {"severity": "low"}},
    )

    # Assert
    assert registry.list_control_ids() == ["security-iam-001"]
    assert registry.get_check("security-iam-001").severity == Severity.LOW


def test_journey_evaluation_failure_emits_skipped_for_each_selected_control_expected_result():
    # Arrange
    selected_ids = ["sec-flow-auth-001", "journey-res-001"]

    # Act
    findings = generate_journey_findings(
        JourneyMapResult(),
        instance_id="instance-1",
        selected_control_ids=selected_ids,
        evaluation_limitation="flow parsing failed",
    )

    # Assert
    assert [finding.check_id for finding in findings] == selected_ids
    assert all(finding.status == CheckStatus.SKIPPED for finding in findings)


def test_path_enumerator_depth_cap_propagates_incomplete_signal_expected_result():
    # Arrange
    graph = SuperGraph(
        nodes={
            "flow-1::a1": JourneyNode("flow-1", "Main IVR", "a1", "MessageParticipant"),
            "flow-1::a2": JourneyNode("flow-1", "Main IVR", "a2", "MessageParticipant"),
        },
        adjacency={"flow-1::a1": ["flow-1::a2"]},
        entry_points={"flow-1": "flow-1::a1"},
    )
    entries = [PhoneNumberEntry("+18005550101", "DID", "US", "flow-1")]

    # Act
    journeys, complete, limitations = enumerate_journeys_with_completeness(
        graph,
        entries,
        max_depth=1,
    )

    # Assert
    assert journeys[0].terminal_type == "truncated"
    assert complete is False
    assert limitations == ["maximum depth 1 exceeded"]


def test_journey_containment_non_agent_self_service_does_not_hide_agent_candidate_expected_result():
    # Arrange
    number = "+18005550101"
    agent_path = _path(number, ["PlayPrompt", "TransferToQueue"])
    self_service_path = _path(number, ["GetParticipantInput"], terminal_type="disconnect")
    result = _result([agent_path, self_service_path])

    # Act
    findings = generate_journey_findings(
        result,
        instance_id="instance-1",
        selected_control_ids=["cost-containment-001"],
    )

    # Assert
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.FAIL
    assert findings[0].evidence["candidate_path_count"] == 1
    assert findings[0].evidence["representative_paths"][0]["terminal_type"] == "agent_queue"


def test_engine_missing_selected_outcome_backfills_error_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    engine.logger = MagicMock()
    engine._execution_errors = []
    instance = ConnectInstance(
        instance_id="instance-1",
        instance_arn="arn:aws:connect:us-east-1:111111111111:instance/instance-1",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
    )

    # Act
    findings = engine._finalize_findings([], [instance])

    # Assert
    assert len(findings) == 1
    assert findings[0].check_id == "journey-res-001"
    assert findings[0].instance_id == "instance-1"
    assert findings[0].status == CheckStatus.ERROR
    assert "synthesized ERROR outcome" in engine._execution_errors[0]


def test_engine_unknown_emitted_control_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]
    finding.check_id = "unknown-control-001"

    # Act / Assert
    with pytest.raises(ValueError, match="unknown control ID"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_legacy_alias_emission_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"sec-flow-auth-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["sec-flow-auth-001"],
    )[0]
    finding.check_id = "journey-sec-001"

    # Act / Assert
    with pytest.raises(ValueError, match="legacy alias"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_unselected_emitted_control_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["sec-flow-auth-001"],
    )[0]

    # Act / Assert
    with pytest.raises(ValueError, match="unselected control ID"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_unexpected_instance_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="other-instance",
        selected_control_ids=["journey-res-001"],
    )[0]

    # Act / Assert
    with pytest.raises(ValueError, match="unexpected instance_id"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_disposition_drift_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]
    finding.disposition = FindingDisposition.INFORMATIONAL

    # Act / Assert
    with pytest.raises(ValueError, match="non-canonical disposition"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def _quota_finding(control_id: str, severity: Severity) -> Finding:
    control = get_atomic_control_registry().get(control_id)
    return Finding(
        check_id=control.control_id,
        check_name=control.name,
        pillar=control.pillar,
        severity=severity,
        status=CheckStatus.FAIL,
        resource_id="instance-1",
        resource_type="ConnectInstance",
        description="quota nearly exhausted",
        remediation="request a quota increase",
        evidence={},
        disposition=control.disposition,
        methodology=control.methodology,
        instance_id="instance-1",
    )


@pytest.mark.parametrize(
    ("control_id", "escalated"),
    [
        ("res-quota-config-001", Severity.HIGH),
        ("res-quota-headroom-001", Severity.CRITICAL),
        ("res-quota-growth-001", Severity.HIGH),
    ],
)
def test_engine_dynamic_severity_escalation_passes_validation_expected_result(
    control_id, escalated
):
    # The quota checks raise severity as usage approaches the limit; the
    # escalated outcome must survive validation instead of aborting the run.
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={control_id})
    finding = _quota_finding(control_id, escalated)
    assert escalated != engine.check_registry.get_control_severity(control_id)

    # Act / Assert — must not raise
    engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_severity_drift_on_static_control_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]
    finding.severity = Severity.CRITICAL

    # Act / Assert
    with pytest.raises(ValueError, match="non-canonical severity"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_methodology_drift_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]
    finding.methodology = None

    # Act / Assert
    with pytest.raises(ValueError, match="non-canonical methodology"):
        engine._validate_emitted_findings([finding], {"instance-1"})


def test_engine_missing_instance_id_rejects_outcome_expected_result():
    # Arrange
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.check_registry = CheckRegistry()
    register_all_checks(engine.check_registry, check_ids={"journey-res-001"})
    finding = generate_journey_findings(
        _result([_path("+18005550101", ["TransferToQueue"])]),
        instance_id="instance-1",
        selected_control_ids=["journey-res-001"],
    )[0]
    finding.instance_id = None

    # Act / Assert
    with pytest.raises(ValueError, match="missing instance_id"):
        engine._validate_emitted_findings([finding], {"instance-1"})
