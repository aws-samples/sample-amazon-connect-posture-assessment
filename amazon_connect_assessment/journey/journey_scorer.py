"""
Journey scoring — evaluates each customer path for security, containment,
resilience, and CX maturity gaps, using the rules of the channel the path
entered on (see :mod:`journey.channels`).
"""

import logging
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import CheckStatus, Finding, Remediation
from ..parsers.flow_patterns import (
    AUTHENTICATION_INDICATORS,
    PERSONALIZATION_INDICATORS,
    SELF_SERVICE_ACTION_TYPES,
)
from .channels import rules_for
from .models import CHANNELS, JourneyMapResult, JourneyNode, JourneyPath, JourneyScore

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


_PHONE_ENTRY_TYPES = {"DID", "TOLL_FREE", "SMS", "WHATSAPP"}


def _mask_email(address: str) -> str:
    """``jane@example.com`` -> ``j***@example.com``."""
    local, _, domain = (address or "").partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}"


def _mask_entry(entry_type: str, identifier: str) -> str:
    """Mask an entry identifier for report evidence.

    Phone numbers keep their last 4 digits and email addresses their domain.
    Observed entry flows are labelled by flow name, and unresolved messaging
    or email entries by resource ID; neither is customer data.
    """
    if entry_type == "OBSERVED_FLOW":
        return identifier
    if (identifier or "").startswith(("sms:", "whatsapp:", "email:")):
        return identifier
    if entry_type == "EMAIL_ADDRESS":
        return _mask_email(identifier)
    return _mask_number(identifier)


def _entry_ref(path: JourneyPath) -> Dict[str, str]:
    return {
        "channel": path.entry_channel,
        "entry_type": path.entry_type,
        "entry": _mask_entry(path.entry_type, path.entry_identifier),
    }


def _channel_breakdown(channels: Iterable[str]) -> str:
    """``VOICE 2, CHAT 1`` in canonical channel order."""
    counts = Counter(channels)
    return ", ".join(f"{c} {counts[c]}" for c in CHANNELS if counts.get(c))


def score_journeys(journeys: List[JourneyPath], config: Dict[str, Any]) -> Dict[str, JourneyScore]:
    """Score each journey path; return results keyed by path_hash."""
    scores: Dict[str, JourneyScore] = {}
    for journey in journeys:
        scores[journey.path_hash] = _score_single_path(journey)
    return scores


def _score_single_path(path: JourneyPath) -> JourneyScore:
    """Score a single journey path with its channel's rules."""
    rules = rules_for(path.entry_channel)
    score = JourneyScore(channel=path.entry_channel)

    for i, node in enumerate(path.nodes):
        # Security: authentication. Besides the keyword indicators, any
        # dedicated authentication action counts — e.g. the chat
        # "Authenticate Customer" block (Cognito-backed customer auth).
        if not score.has_authentication and (
            _matches_indicators(node, AUTHENTICATION_INDICATORS)
            or "authenticat" in node.action_type.lower()
        ):
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

        # Returning customer detection
        if not score.has_returning_caller_detection:
            if node.action_type in (
                "CheckContactAttributes",
                "CheckAttribute",
                "InvokeLambdaFunction",
            ):
                blob = str(node.parameters).lower()
                if any(h in blob for h in _RETURNING_HINTS):
                    score.has_returning_caller_detection = True

        # Dynamic prompt / message
        if not score.has_dynamic_prompt:
            if node.action_type in ("MessageParticipant", "PlayPrompt"):
                text = str(node.parameters.get("Text", ""))
                if "$." in text:
                    score.has_dynamic_prompt = True

    # CX maturity, counted over the features meaningful on this channel.
    score.cx_maturity = rules.maturity(score.cx_feature_count)

    # Deficiencies — only for rules that apply on this channel.
    if (
        rules.authentication
        and not score.has_authentication
        and path.terminal_type == "agent_queue"
    ):
        score.deficiencies.append("🔓 No authentication before agent queue")
    if rules.self_service and not score.has_self_service:
        score.deficiencies.append("💰 No self-service automation")
    if rules.callback and not score.has_callback_offering and path.terminal_type == "agent_queue":
        score.deficiencies.append("📞 No callback offering before queue")
    if not score.has_personalization:
        score.deficiencies.append("👤 No personalization")
    if (
        rules.dead_end
        and path.terminal_type == "disconnect"
        and path.terminal_details.get("reason") == "dead_end"
    ):
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
    rep: Dict[str, Any] = {
        **_entry_ref(path),
        "flows": path.flows_traversed,
        "terminal_type": path.terminal_type,
        "terminal_details": path.terminal_details,
    }
    if path.entry_type in _PHONE_ENTRY_TYPES:
        rep["phone_number"] = rep["entry"]
    return rep


def _canonical_finding(
    control_id: str,
    instance_id: str,
    status: CheckStatus,
    description: str,
    remediation: str,
    evidence: Dict[str, Any],
    structured_remediation: Optional[Remediation] = None,
) -> Finding:
    from ..checks.control_registry import get_atomic_control_registry

    control = get_atomic_control_registry().get(control_id)
    if not instance_id or not instance_id.strip():
        raise ValueError("Journey finding generation requires a non-empty instance_id")
    return Finding(
        check_id=control.control_id,
        check_name=control.name,
        pillar=control.pillar,
        severity=control.default_severity,
        status=status,
        resource_id=instance_id,
        resource_type="ConnectInstance",
        description=description,
        remediation=remediation,
        evidence=evidence,
        structured_remediation=structured_remediation,
        disposition=control.disposition,
        methodology=control.methodology,
        instance_id=instance_id,
    )


def _no_candidate_status(result: JourneyMapResult) -> CheckStatus:
    return CheckStatus.PASS if result.enumeration_complete else CheckStatus.SKIPPED


def _coverage_evidence(result: JourneyMapResult) -> Dict[str, Any]:
    voice_numbers = sorted(
        {
            _mask_number(path.entry_identifier)
            for path in result.journeys
            if path.entry_type in ("DID", "TOLL_FREE")
        }
    )
    entries = sorted(
        {tuple(_entry_ref(path).values()) for path in result.journeys},
        key=lambda ref: (CHANNELS.index(ref[0]) if ref[0] in CHANNELS else 9, ref[1], ref[2]),
    )
    return {
        "evaluated_phone_numbers": voice_numbers,
        "evaluated_entry_points": [
            {"channel": c, "entry_type": t, "entry": i} for c, t, i in entries
        ],
        "journey_count": len(result.journeys),
        "journeys_by_channel": {
            c: n for c, n in Counter(p.entry_channel for p in result.journeys).items()
        },
        "enumeration_complete": result.enumeration_complete,
        "enumeration_limitations": result.enumeration_limitations,
        "channel_coverage": result.channel_coverage,
        "entry_discovery_limitations": result.entry_discovery_limitations,
    }


def _rule_scope(
    result: JourneyMapResult, rule: str
) -> Tuple[List[str], Dict[str, str], List[JourneyPath], bool]:
    """Channels a rule covers, channels it excludes (with why), its paths, completeness."""
    seen = {p.entry_channel for p in result.journeys} | set(result.channel_coverage)
    ordered = [c for c in CHANNELS if c in seen]
    in_scope = [c for c in ordered if rules_for(c).applies(rule)]
    excluded = {
        c: rules_for(c).not_applicable.get(rule, "")
        for c in ordered
        if not rules_for(c).applies(rule)
    }
    paths = [p for p in result.journeys if rules_for(p.entry_channel).applies(rule)]
    if in_scope:
        complete = all(result.channel_complete(c) for c in in_scope)
    else:
        complete = result.enumeration_complete
    return in_scope, excluded, paths, complete


def _excluded_note(excluded: Dict[str, str]) -> str:
    if not excluded:
        return ""
    parts = [f"{channel} ({reason})" if reason else channel for channel, reason in excluded.items()]
    return " Not evaluated for " + "; ".join(parts) + "."


def _affected_refs(paths: List[JourneyPath]) -> List[Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}
    for path in paths:
        seen.setdefault(path.entry_key, _entry_ref(path))
    return [seen[key] for key in sorted(seen)]


def _representatives(paths: List[JourneyPath]) -> List[Dict[str, Any]]:
    first: Dict[str, JourneyPath] = {}
    for path in paths:
        first.setdefault(path.entry_key, path)
    return [_representative_path(first[key]) for key in sorted(first)]


def _affected_phone_numbers(paths: List[JourneyPath]) -> List[str]:
    return sorted(
        {_mask_number(p.entry_identifier) for p in paths if p.entry_type in _PHONE_ENTRY_TYPES}
    )


# Which channel rule each path-based Journey control evaluates.
_CONTROL_RULE = {
    "sec-flow-auth-001": "authentication",
    "cost-containment-001": "self_service",
    "journey-res-001": "dead_end",
}


def generate_journey_findings(
    result: JourneyMapResult,
    instance_id: str,
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

    for control_id in selected_ids:
        coverage = _coverage_evidence(result)

        if control_id == "journey-scope-001":
            if not result.tier_assignments and not result.dormant_flows:
                status = (
                    CheckStatus.NOT_APPLICABLE
                    if result.enumeration_complete
                    else CheckStatus.SKIPPED
                )
                findings.append(
                    _canonical_finding(
                        control_id,
                        instance_id,
                        status,
                        (
                            "No parsed flow inventory was available for an entry-point "
                            "reachability review."
                            if result.enumeration_complete
                            else "Flow inventory coverage was incomplete, so entry-point "
                            "reachability could not be fully evaluated."
                        ),
                        "Provide readable contact flow inventory and rerun the assessment.",
                        {
                            **coverage,
                            "reason": (
                                "no_flow_inventory"
                                if result.enumeration_complete
                                else "incomplete_flow_inventory"
                            ),
                        },
                    )
                )
                continue
            dormant_flows = sorted(result.dormant_flows)
            traffic_flows = sorted(result.traffic_observed_flows)
            usage_known = result.usage_metrics_status == "complete"
            window = result.usage_window_days
            status = CheckStatus.FAIL if dormant_flows else _no_candidate_status(result)
            if dormant_flows and usage_known:
                description = (
                    f"{len(dormant_flows)} flow(s) are not reachable from any entry point "
                    "(phone, SMS, WhatsApp, email, or an observed entry flow) and started no "
                    f"contacts in the last {window} days, so they require an ownership and "
                    "usage review."
                )
            elif dormant_flows:
                description = (
                    f"{len(dormant_flows)} flow(s) are not reachable from any discovered entry "
                    "point and require an ownership and usage review. Usage metrics were "
                    "unavailable, so flows started only by web chat, tasks, or the API, and "
                    "queue or whisper flows, may be included."
                )
            elif traffic_flows:
                description = (
                    f"No dormant flows. {len(traffic_flows)} flow(s) are not reachable from any "
                    f"entry point but started contacts in the last {window} days, typically as "
                    "queue, hold, or whisper flows, or dynamically invoked sub-flows."
                )
            else:
                description = "Every parsed flow is reachable from a discovered entry point."
            if traffic_flows:
                description += (
                    f" The {len(traffic_flows)} in-use, unreachable flow(s) are not enumerated "
                    "as journeys, so journey controls do not cover them."
                    if dormant_flows
                    else " They are not enumerated as journeys, so journey controls do not "
                    "cover them."
                )
            channel_mix_by_flow = {
                t.flow_id: t.channel_mix
                for t in result.tier_assignments
                if t.flow_id in set(traffic_flows)
            }
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description,
                    "Review associations, dynamic references, other channels, ownership, and "
                    "observed usage before changing any flow.",
                    {
                        **coverage,
                        "dormant_flow_count": len(dormant_flows),
                        "dormant_flow_ids": dormant_flows,
                        "traffic_observed_flow_count": len(traffic_flows),
                        "traffic_observed_flow_ids": traffic_flows,
                        "traffic_observed_channel_mix": channel_mix_by_flow,
                        "usage_metrics_status": result.usage_metrics_status,
                        "usage_window_days": window if usage_known else None,
                        "dynamic_reference_count": len(result.dynamic_edges),
                    },
                )
            )
            continue

        rule = _CONTROL_RULE.get(control_id)
        if rule is None:
            continue
        in_scope, excluded, paths, complete = _rule_scope(result, rule)
        scope_evidence = {
            **coverage,
            "evaluated_channels": in_scope,
            "excluded_channels": excluded,
        }
        note = _excluded_note(excluded)
        pass_or_skip = CheckStatus.PASS if complete else CheckStatus.SKIPPED

        if not paths:
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    CheckStatus.NOT_APPLICABLE if complete else CheckStatus.SKIPPED,
                    (
                        "No entry-point journeys made this control applicable."
                        if complete
                        else "Journey coverage was incomplete, so this control could not be "
                        "fully evaluated."
                    )
                    + note,
                    "Associate a phone number, messaging number, or email address with a "
                    "readable contact flow to evaluate it."
                    if complete
                    else "Resolve traversal limitations and rerun the assessment.",
                    {
                        **scope_evidence,
                        "reason": (
                            "no_entry_point_journeys" if complete else "incomplete_journey_coverage"
                        ),
                    },
                )
            )
            continue

        if control_id == "sec-flow-auth-001":
            candidates = [
                path
                for path in paths
                if path.terminal_type == "agent_queue"
                and not result.scores.get(path.path_hash, JourneyScore()).has_authentication
            ]
            affected = _affected_refs(candidates)
            status = CheckStatus.FAIL if candidates else pass_or_skip
            if candidates:
                description = (
                    f"{len(candidates)} agent-queue path(s) across {len(affected)} entry "
                    f"point(s) ({_channel_breakdown(a['channel'] for a in affected)}) have no "
                    "recognized authentication step. This is called out because those routes "
                    "may reach staff who can access or change customer-specific information "
                    "before the customer's identity is established. If a destination handles "
                    "sensitive requests, a missing verified gate can increase unauthorized "
                    "disclosure or account-change risk; queue sensitivity and agent-side "
                    "verification still require review."
                )
            elif complete:
                description = (
                    "No enumerated agent-queue path lacks a recognized authentication step. This "
                    "matters because sensitive queues should not be reachable before customer "
                    "identity is established where authentication is required; static "
                    "recognition still does not prove that authentication is effective."
                )
            else:
                description = (
                    "No candidate was found, but bounded path enumeration was incomplete. "
                    "Unexamined paths may still reach sensitive queues before customer identity "
                    "is established, so this result cannot close the authentication review."
                )
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description + note,
                    "Classify queue sensitivity and add tested fail-closed authentication before "
                    "agent transfer where required.",
                    {
                        **scope_evidence,
                        "affected_phone_numbers": _affected_phone_numbers(candidates),
                        "affected_entry_points": affected,
                        "candidate_path_count": len(candidates),
                        "representative_paths": _representatives(candidates),
                    },
                )
            )
            continue

        if control_id == "cost-containment-001":
            by_entry: Dict[str, List[JourneyPath]] = {}
            for path in paths:
                by_entry.setdefault(path.entry_key, []).append(path)
            affected_paths = []
            for key in sorted(by_entry):
                agent_paths = [p for p in by_entry[key] if p.terminal_type == "agent_queue"]
                if agent_paths and all(
                    not result.scores.get(p.path_hash, JourneyScore()).has_self_service
                    for p in agent_paths
                ):
                    affected_paths.extend(agent_paths)
            affected = _affected_refs(affected_paths)
            status = CheckStatus.FAIL if affected_paths else pass_or_skip
            if affected_paths:
                description = (
                    f"{len(affected)} entry point(s) "
                    f"({_channel_breakdown(a['channel'] for a in affected)}) have agent-bound "
                    "journeys without recognized menu/input, Lambda lookup, or bot "
                    "self-service."
                )
            elif complete:
                description = (
                    "Every evaluated agent-bound journey includes recognized self-service."
                )
            else:
                description = "No candidate was found, but bounded path enumeration was incomplete."
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description + note,
                    "Validate a suitable DTMF, chat input, Lambda, or Lex resolution opportunity "
                    "with production demand and fallback testing.",
                    {
                        **scope_evidence,
                        "affected_phone_numbers": _affected_phone_numbers(affected_paths),
                        "affected_entry_points": affected,
                        "candidate_path_count": len(affected_paths),
                        "representative_paths": _representatives(affected_paths),
                    },
                )
            )
            continue

        if control_id == "journey-res-001":
            candidates = [
                path
                for path in paths
                if path.terminal_type == "disconnect"
                and path.terminal_details.get("reason") == "dead_end"
            ]
            affected = _affected_refs(candidates)
            status = CheckStatus.FAIL if candidates else pass_or_skip
            if candidates:
                description = (
                    f"{len(candidates)} structural dead-end path(s) affect {len(affected)} entry "
                    f"point(s) ({_channel_breakdown(a['channel'] for a in affected)})."
                )
            elif complete:
                description = "No structural dead-end path was found in complete enumeration."
            else:
                description = "No dead end was found, but bounded path enumeration was incomplete."
            findings.append(
                _canonical_finding(
                    control_id,
                    instance_id,
                    status,
                    description + note,
                    "Trace each recorded path and add a customer-safe terminal outcome or "
                    "document the intended behavior.",
                    {
                        **scope_evidence,
                        "affected_phone_numbers": _affected_phone_numbers(candidates),
                        "affected_entry_points": affected,
                        "dead_end_path_count": len(candidates),
                        "representative_paths": _representatives(candidates),
                    },
                )
            )

    return findings
