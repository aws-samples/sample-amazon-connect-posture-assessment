"""Focused Connect-side coverage for Agentic CX Designer records."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from amazon_connect_assessment.checks.acxd_checks import (
    ACXDErrorRoutingCheck,
    ACXDEscalationReviewCheck,
    ACXDHandoffInventoryCheck,
)
from amazon_connect_assessment.checks.contact_flow_behavior_checks import _ERROR_CAPABLE_TYPES
from amazon_connect_assessment.checks.cost_containment_checks import _INPUT_COLLECTION_ACTIONS
from amazon_connect_assessment.journey.path_enumerator import TERMINAL_ACTIONS
from amazon_connect_assessment.models import CheckStatus, ContactFlow, FindingDisposition
from tests.conftest import build_action, build_contact_flow

_CONTEXT_VALUE_MARKER = "ACXD_CONTEXT_VALUE_MARKER_DO_NOT_RENDER"


def _acxd_action(action_id: str = "agentic", *, complete: bool = True) -> dict:
    return build_action(
        action_id,
        "ConnectParticipantWithAgenticCX",
        {
            "AgentConfiguration": {
                "WorkspaceId": "workspace-example-001",
                "ApplicationId": "application-example-001",
                "Alias": "customer-service",
            },
            "ContextVariables": {
                "accountToken": _CONTEXT_VALUE_MARKER,
                "customerTier": "gold",
            },
            "SpeechRecognitionConfiguration": {"LanguageCode": "en-US"},
            "AudioFillerConfiguration": {"Enabled": True},
        },
        next_action="completed" if complete else None,
        conditions=(
            [
                {
                    "NextAction": "escalated",
                    "Condition": {"Operator": "Equals", "Operands": ["Escalation"]},
                }
            ]
            if complete
            else None
        ),
        errors=(
            [
                {"NextAction": "idle", "ErrorType": "InputTimeLimitExceeded"},
                {"NextAction": "other", "ErrorType": "NoMatchingCondition"},
                {"NextAction": "error", "ErrorType": "NoMatchingError"},
            ]
            if complete
            else None
        ),
    )


def _flow(flow_id: str, name: str, actions: list[dict], start_action: str) -> ContactFlow:
    return ContactFlow(
        id=flow_id,
        arn=f"arn:aws:connect:us-east-1:111122223333:instance/example/contact-flow/{flow_id}",
        name=name,
        type="CONTACT_FLOW",
        state="ACTIVE",
        content=build_contact_flow(actions, start_action=start_action),
    )


def _complete_flow() -> ContactFlow:
    return _flow(
        "flow-agentic",
        "Agentic Customer Service",
        [
            _acxd_action(),
            build_action("completed", "DisconnectParticipant"),
            build_action("escalated", "TransferContactToQueue", {"QueueId": "support"}),
            build_action("idle", "MessageParticipant", {"Text": "Are you still there?"}),
            build_action("other", "MessageParticipant", {"Text": "Try another option."}),
            build_action("error", "MessageParticipant", {"Text": "Please hold."}),
        ],
        "agentic",
    )


def test_acxd_handoff_complete_inventory_passes_with_redacted_evidence(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [_complete_flow()]

    # Act
    finding = ACXDHandoffInventoryCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.PASS
    assert finding.disposition is FindingDisposition.INFORMATIONAL
    handoff = finding.evidence["acxd_handoffs"][0]
    assert handoff["workspace_id"] == "workspace-example-001"
    assert handoff["application_id"] == "application-example-001"
    assert handoff["alias"] == "customer-service"
    assert handoff["context_variable_names"] == ["accountToken", "customerTier"]
    assert handoff["context_variable_count"] == 2
    assert _CONTEXT_VALUE_MARKER not in str(finding.evidence)


def test_acxd_handoff_incomplete_flow_skips_with_partial_inventory(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [
        _complete_flow(),
        ContactFlow(
            id="unavailable",
            arn="arn:aws:connect:us-east-1:111122223333:instance/example/contact-flow/unavailable",
            name="Unavailable",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=None,
        ),
    ]

    # Act
    finding = ACXDHandoffInventoryCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.SKIPPED
    assert finding.evidence["reachable_acxd_actions"] == 1
    assert finding.evidence["analysis_complete"] is False


def test_acxd_handoff_no_reachable_action_returns_not_applicable(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [
        _flow("plain", "Plain", [build_action("start", "DisconnectParticipant")], "start")
    ]

    # Act
    finding = ACXDHandoffInventoryCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.NOT_APPLICABLE
    assert finding.evidence["reachable_acxd_actions"] == 0


def test_acxd_error_routing_missing_required_routes_fails_without_requiring_other_outcome(
    make_check_context, sample_connect_instance
):
    # Arrange
    action = _acxd_action()
    action["Transitions"]["Errors"] = [{"NextAction": "other", "ErrorType": "NoMatchingCondition"}]
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [
        _flow(
            "missing-errors",
            "Missing errors",
            [
                action,
                build_action("completed", "DisconnectParticipant"),
                build_action("escalated", "TransferContactToQueue"),
                build_action("other", "DisconnectParticipant"),
            ],
            "agentic",
        )
    ]

    # Act
    finding = ACXDErrorRoutingCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.FAIL
    assert finding.evidence["defect_details"][0]["missing_requirements"] == [
        "InputTimeLimitExceeded",
        "NoMatchingError",
    ]
    assert finding.evidence["defect_details"][0]["other_outcome_configured"] is True


def test_acxd_error_routing_required_routes_present_passes(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [_complete_flow()]

    # Act
    finding = ACXDErrorRoutingCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.PASS
    assert finding.evidence["actions_with_missing_routes"] == 0


def test_acxd_error_routing_known_gap_with_incomplete_flow_stays_fail(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [
        _flow("gap", "Gap", [_acxd_action(complete=False)], "agentic"),
        ContactFlow(
            id="unavailable",
            arn="arn:aws:connect:us-east-1:111122223333:instance/example/contact-flow/unavailable",
            name="Unavailable",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=None,
        ),
    ]

    # Act
    finding = ACXDErrorRoutingCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.FAIL
    assert finding.evidence["analysis_complete"] is False
    assert "incomplete" in finding.description.lower()


def test_acxd_escalation_missing_condition_is_manual_review_candidate(
    make_check_context, sample_connect_instance
):
    # Arrange
    action = _acxd_action()
    action["Transitions"]["Conditions"] = []
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [_flow("no-escalation", "No escalation", [action], "agentic")]

    # Act
    finding = ACXDEscalationReviewCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.FAIL
    assert finding.disposition is FindingDisposition.MANUAL_REVIEW
    assert finding.evidence["escalation_review_candidates"] == 1
    assert "not proof" in finding.description.lower()


def test_acxd_escalation_explicit_condition_passes_review_screen(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [_complete_flow()]

    # Act
    finding = ACXDEscalationReviewCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.PASS
    assert finding.evidence["escalation_review_candidates"] == 0


def test_acxd_unreachable_and_default_sample_actions_are_excluded(
    make_check_context, sample_connect_instance
):
    # Arrange
    instance = deepcopy(sample_connect_instance)
    instance.contact_flows = [
        _flow(
            "customer",
            "Customer flow",
            [
                build_action("start", "DisconnectParticipant"),
                _acxd_action("orphan", complete=False),
            ],
            "start",
        ),
        _flow("sample", "Sample Agentic CX demo", [_acxd_action(complete=False)], "agentic"),
    ]

    # Act
    finding = ACXDErrorRoutingCheck().execute(make_check_context(instance=instance))

    # Assert
    assert finding.status is CheckStatus.NOT_APPLICABLE
    assert finding.evidence["unreachable_acxd_actions_ignored"] == 1
    assert finding.evidence["sample_flows_excluded"] == 1


def test_acxd_shared_inventory_check_keeps_parallel_instance_evidence_isolated(
    make_check_context, sample_connect_instance
):
    # Arrange
    check = ACXDHandoffInventoryCheck()
    first = deepcopy(sample_connect_instance)
    first.instance_id = "first-instance"
    first.contact_flows = [_complete_flow()]
    second = deepcopy(sample_connect_instance)
    second.instance_id = "second-instance"
    second.contact_flows = [
        _flow("plain", "Plain", [build_action("start", "DisconnectParticipant")], "start")
    ]

    # Act
    with ThreadPoolExecutor(max_workers=2) as executor:
        findings = list(
            executor.map(
                check.execute,
                [make_check_context(instance=first), make_check_context(instance=second)],
            )
        )

    # Assert
    by_instance = {finding.resource_id: finding for finding in findings}
    assert by_instance["first-instance"].status is CheckStatus.PASS
    assert by_instance["second-instance"].status is CheckStatus.NOT_APPLICABLE


def test_acxd_dedicated_controls_exclude_generic_error_input_and_terminal_sets():
    # Arrange
    action_type = "ConnectParticipantWithAgenticCX"

    # Act
    memberships = (
        action_type in _ERROR_CAPABLE_TYPES,
        action_type in _INPUT_COLLECTION_ACTIONS,
        action_type in TERMINAL_ACTIONS,
    )

    # Assert
    assert memberships == (False, False, False)
