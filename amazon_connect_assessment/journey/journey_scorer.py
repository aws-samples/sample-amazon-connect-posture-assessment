"""
Journey scoring — evaluates each caller path for security, containment,
resilience, and CX maturity gaps.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional

from ..models import CheckStatus, Finding, Remediation
from ..parsers.flow_patterns import (
    AUTHENTICATION_INDICATORS,
    PERSONALIZATION_INDICATORS,
    SELF_SERVICE_ACTION_TYPES,
)
from .models import JourneyMapResult, JourneyNode, JourneyPath, JourneyScore

logger = logging.getLogger("journey.scorer")

_CALLBACK_ACTIONS = {"CreateCallback", "SetCallbackNumber", "OfferCallback"}
_RETURNING_HINTS = ("returning", "previous", "history", "repeat", "last_call", "crm")


def _mask_number(number: str) -> str:
    """Mask a phone number for report evidence, preserving the last 4 digits.

    Evidence dicts are surfaced in the HTML/JSON report, so the full DID is
    reduced to a trailing fragment (e.g. ``***-***-1234``) — enough to identify
    which number triggered a finding without publishing the whole number.
    """
    if not number:
        return number
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 4:
        return "***"
    return f"***-***-{''.join(digits[-4:])}"


def score_journeys(journeys: List[JourneyPath], config: Dict[str, Any]) -> Dict[str, JourneyScore]:
    """Score each journey path; return results keyed by path_hash."""
    scores: Dict[str, JourneyScore] = {}
    for journey in journeys:
        scores[journey.path_hash] = _score_single_path(journey)
    return scores


def _score_single_path(path: JourneyPath) -> JourneyScore:
    """Score a single journey path across all dimensions."""
    score = JourneyScore()

    for i, node in enumerate(path.nodes):
        # Security: authentication
        if not score.has_authentication and _matches_indicators(node, AUTHENTICATION_INDICATORS):
            score.has_authentication = True
            score.auth_position = i

        # Self-service
        if node.action_type in SELF_SERVICE_ACTION_TYPES:
            score.has_self_service = True
            score.self_service_actions.append(node.action_id)

        # Callback
        if node.action_type in _CALLBACK_ACTIONS:
            score.has_callback_offering = True

        # Personalization
        if not score.has_personalization and _matches_indicators(node, PERSONALIZATION_INDICATORS):
            score.has_personalization = True

        # NLU / Bot
        if node.action_type in (
            "ConnectParticipantWithLexBot",
            "ConnectToLexBot",
            "ConnectParticipantWithAgenticCX",
        ):
            score.has_nlu_bot = True

        # Returning caller detection
        if not score.has_returning_caller_detection:
            if node.action_type in (
                "CheckContactAttributes",
                "CheckAttribute",
                "InvokeLambdaFunction",
            ):
                blob = str(node.parameters).lower()
                if any(h in blob for h in _RETURNING_HINTS):
                    score.has_returning_caller_detection = True

        # Dynamic prompt
        if not score.has_dynamic_prompt:
            if node.action_type in ("MessageParticipant", "PlayPrompt"):
                text = str(node.parameters.get("Text", ""))
                if "$." in text:
                    score.has_dynamic_prompt = True

    # CX maturity
    cx = score.cx_feature_count
    if cx >= 4:
        score.cx_maturity = "Advanced"
    elif cx >= 2:
        score.cx_maturity = "Intermediate"
    else:
        score.cx_maturity = "Basic"

    # Deficiencies
    if not score.has_authentication and path.terminal_type == "agent_queue":
        score.deficiencies.append("🔓 No authentication before agent queue")
    if not score.has_self_service:
        score.deficiencies.append("💰 No self-service automation")
    if not score.has_callback_offering and path.terminal_type == "agent_queue":
        score.deficiencies.append("📞 No callback offering before queue")
    if not score.has_personalization:
        score.deficiencies.append("👤 No personalization")
    if path.terminal_type == "disconnect" and path.terminal_details.get("reason") == "dead_end":
        score.deficiencies.append("⚠️ Dead-end disconnect")

    return score


def _matches_indicators(node: JourneyNode, indicators: Dict[str, List[str]]) -> bool:
    hints = indicators.get(node.action_type)
    if not hints:
        return False
    blob = (node.action_type + " " + str(node.parameters)).lower()
    return any(h in blob for h in hints)


_CANONICAL_JOURNEY_CONTROL_IDS = (
    "sec-flow-auth-001",
    "cost-containment-001",
    "journey-res-001",
    "journey-scope-001",
)


def _selected_journey_ids(selected_control_ids: Optional[Iterable[str]]) -> List[str]:
    from ..checks.control_registry import ExecutionSource, get_atomic_control_registry

    catalog = get_atomic_control_registry()
    requested = (
        _CANONICAL_JOURNEY_CONTROL_IDS if selected_control_ids is None else selected_control_ids
    )
    selected: List[str] = []
    for control in catalog.select(requested):
        if control.execution_source != ExecutionSource.JOURNEY:
            raise ValueError(f"Control {control.control_id} is not owned by Journey execution")
        selected.append(control.control_id)
    return selected


def _representative_path(path: JourneyPath) -> Dict[str, Any]:
    return {
        "phone_number": _mask_number(path.entry_number),
        "flows": path.flows_traversed,
        "terminal_type": path.terminal_type,
        "terminal_details": path.terminal_details,
    }


def _canonical_finding(
    control_id: str,
    instance_id: Optional[str],
    status: CheckStatus,
    description: str,
    remediation: str,
    evidence: Dict[str, Any],
    structured_remediation: Optional[Remediation] = None,
) -> Finding:
    from ..checks.control_registry import get_atomic_control_registry

    control = get_atomic_control_registry().get(control_id)
    canonical_instance_id = instance_id or "instance"
    return Finding(
        check_id=control.control_id,
        check_name=control.name,
        pillar=control.pillar,
        severity=control.default_severity,
        status=status,
        resource_id=canonical_instance_id,
        resource_type="ConnectInstance",
        description=description,
        remediation=remediation,
        evidence=evidence,
        structured_remediation=structured_remediation,
        disposition=control.disposition,
        methodology=control.methodology,
        instance_id=canonical_instance_id,
    )


def _no_candidate_status(result: JourneyMapResult) -> CheckStatus:
    return CheckStatus.PASS if result.enumeration_complete else CheckStatus.SKIPPED


def _coverage_evidence(result: JourneyMapResult) -> Dict[str, Any]:
    numbers = sorted({_mask_number(path.entry_number) for path in result.journeys})
    return {
        "evaluated_phone_numbers": numbers,
        "journey_count": len(result.journeys),
        "enumeration_complete": result.enumeration_complete,
        "enumeration_limitations": result.enumeration_limitations,
    }


def generate_journey_findings(
    result: JourneyMapResult,
    instance_id: Optional[str] = None,
    selected_control_ids: Optional[Iterable[str]] = None,
    evaluation_limitation: Optional[str] = None,
) -> List[Finding]:
    """Emit one canonical aggregate outcome per selected Journey control."""
    selected_ids = _selected_journey_ids(selected_control_ids)
    if evaluation_limitation:
        return [
            _canonical_finding(
                control_id,
                instance_id,
                CheckStatus.SKIPPED,
                "Journey evaluation could not be completed for this instance.",
                "Resolve the reported data or execution limitation and rerun the assessment.",
                {"evaluation_limitation": evaluation_limitation},
            )
            for control_id in selected_ids
        ]

    findings: List[Finding] = []
    paths_by_number: Dict[str, List[JourneyPath]] = {}
    for path in result.journeys:
        paths_by_number.setdefault(path.entry_number, []).append(path)

    for control_id in selected_ids:
        coverage = _coverage_evidence(result)

        if control_id == "journey-scope-001":
            if not result.tier_assignments and not result.dormant_flows:
                findings.append(
                    _canonical_finding(
                        control_id,
                        instance_id,
                        CheckStatus.NOT_APPLICABLE,
                        "No parsed flow inventory was available for a phone-reachability review.",
                        "Provide readable contact flow inventory and rerun the assessment.",
                        {"reason": "no_flow_inventory"},
                    )
                )
                continue
            dormant_flows = sorted(result.dormant_flows)
            status = CheckStatus.FAIL if dormant_flows else CheckStatus.PASS
            description = (
                f"{len(dormant_flows)} flow(s) are outside the discovered phone-anchored "
                "static closure and require an ownership and usage review."
                if dormant_flows
                else "All parsed flows are in the discovered phone-anchored static closure."
            )
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description,
                    "Review associations, dynamic references, other channels, ownership, and "
                    "observed usage before changing any flow.",
                    {
                        "dormant_flow_count": len(dormant_flows),
                        "dormant_flow_ids": dormant_flows,
                        "dynamic_reference_count": len(result.dynamic_edges),
                    },
                )
            )
            continue

        if not result.journeys:
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    CheckStatus.NOT_APPLICABLE,
                    "No phone-number journeys made this control applicable.",
                    "Associate an inbound phone number with a readable contact flow to evaluate it.",
                    {"reason": "no_phone_number_journeys"},
                )
            )
            continue

        if control_id == "sec-flow-auth-001":
            candidates = [
                path
                for path in result.journeys
                if path.terminal_type == "agent_queue"
                and not result.scores.get(path.path_hash, JourneyScore()).has_authentication
            ]
            affected_numbers = sorted({_mask_number(path.entry_number) for path in candidates})
            status = CheckStatus.FAIL if candidates else _no_candidate_status(result)
            evidence = {
                **coverage,
                "affected_phone_numbers": affected_numbers,
                "candidate_path_count": len(candidates),
                "representative_paths": [
                    _representative_path(paths[0])
                    for _, paths in sorted(
                        {
                            number: [path for path in candidates if path.entry_number == number]
                            for number in {path.entry_number for path in candidates}
                        }.items()
                    )
                ],
            }
            description = (
                (
                    f"{len(candidates)} agent-queue path(s) across {len(affected_numbers)} inbound "
                    "phone number(s) have no recognized authentication step. This is called out "
                    "because those routes may reach staff who can access or change "
                    "customer-specific information before caller identity is established. If a "
                    "destination handles sensitive requests, a missing verified gate can increase "
                    "unauthorized disclosure or account-change risk; queue sensitivity and "
                    "agent-side verification still require review."
                )
                if candidates
                else (
                    "No enumerated agent-queue path lacks a recognized authentication step. This "
                    "matters because sensitive queues should not be reachable before caller "
                    "identity is established where authentication is required; static recognition "
                    "still does not prove that authentication is effective."
                    if result.enumeration_complete
                    else "No candidate was found, but bounded path enumeration was incomplete. "
                    "Unexamined paths may still reach sensitive queues before caller identity is "
                    "established, so this result cannot close the authentication review."
                )
            )
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description,
                    "Classify queue sensitivity and add tested fail-closed authentication before "
                    "agent transfer where required.",
                    evidence,
                )
            )
            continue

        if control_id == "cost-containment-001":
            affected_paths_by_number: Dict[str, List[JourneyPath]] = {}
            for number, number_paths in paths_by_number.items():
                agent_paths = [path for path in number_paths if path.terminal_type == "agent_queue"]
                if agent_paths and all(
                    not result.scores.get(path.path_hash, JourneyScore()).has_self_service
                    for path in agent_paths
                ):
                    affected_paths_by_number[number] = agent_paths
            affected_paths = [
                path
                for number in sorted(affected_paths_by_number)
                for path in affected_paths_by_number[number]
            ]
            affected_numbers = sorted({_mask_number(number) for number in affected_paths_by_number})
            status = CheckStatus.FAIL if affected_paths else _no_candidate_status(result)
            evidence = {
                **coverage,
                "affected_phone_numbers": affected_numbers,
                "candidate_path_count": len(affected_paths),
                "representative_paths": [
                    _representative_path(affected_paths_by_number[number][0])
                    for number in sorted(affected_paths_by_number)
                ],
            }
            description = (
                f"{len(affected_numbers)} inbound phone number(s) have agent-bound journeys "
                "without recognized menu/input, Lambda lookup, or Lex self-service."
                if affected_paths
                else (
                    "Every evaluated agent-bound journey includes recognized self-service."
                    if result.enumeration_complete
                    else "No candidate was found, but bounded path enumeration was incomplete."
                )
            )
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description,
                    "Validate a suitable DTMF, Lambda, or Lex resolution opportunity with "
                    "production demand and fallback testing.",
                    evidence,
                )
            )
            continue

        if control_id == "journey-res-001":
            candidates = [
                path
                for path in result.journeys
                if path.terminal_type == "disconnect"
                and path.terminal_details.get("reason") == "dead_end"
            ]
            affected_numbers = sorted({_mask_number(path.entry_number) for path in candidates})
            status = CheckStatus.FAIL if candidates else _no_candidate_status(result)
            evidence = {
                **coverage,
                "affected_phone_numbers": affected_numbers,
                "dead_end_path_count": len(candidates),
                "representative_paths": [
                    _representative_path(paths[0])
                    for _, paths in sorted(
                        {
                            number: [path for path in candidates if path.entry_number == number]
                            for number in {path.entry_number for path in candidates}
                        }.items()
                    )
                ],
            }
            description = (
                f"{len(candidates)} structural dead-end path(s) affect "
                f"{len(affected_numbers)} inbound phone number(s)."
                if candidates
                else (
                    "No structural dead-end path was found in complete enumeration."
                    if result.enumeration_complete
                    else "No dead end was found, but bounded path enumeration was incomplete."
                )
            )
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description,
                    "Trace each recorded path and add a caller-safe terminal outcome or document "
                    "the intended behavior.",
                    evidence,
                )
            )

    return findings
