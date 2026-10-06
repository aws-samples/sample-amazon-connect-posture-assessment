"""Connect-side assessment of Agentic CX Designer flow handoffs.

These checks inspect only reachable ``ConnectParticipantWithAgenticCX`` actions
in customer-authored Amazon Connect flow exports. They do not call Agentic CX
Designer APIs or make claims about application internals, builds, deployments,
alias resolution, runtime containment, or guardrails.
"""

from __future__ import annotations

import ast
import threading
import weakref
from dataclasses import dataclass
from typing import Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FindingDisposition,
    FlowAction,
    Pillar,
    Remediation,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser, reachable_from_entry
from ..parsers.flow_patterns import is_default_sample_flow
from .base import BaseCheck, CheckContext

ACXD_ACTION_TYPE = "ConnectParticipantWithAgenticCX"
_REQUIRED_ERROR_ROUTES = ("InputTimeLimitExceeded", "NoMatchingError")


@dataclass(frozen=True)
class _ActionObservation:
    """One reachable ACXD action plus report-safe structural evidence."""

    flow: ContactFlow
    action: FlowAction
    evidence: dict[str, object]


@dataclass(frozen=True)
class _FlowInventory:
    """Immutable per-execution inventory shared by the ACXD checks."""

    observations: tuple[_ActionObservation, ...]
    common_evidence: dict[str, object]
    limitations: tuple[str, ...]


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return ContactFlowParser().parse(flow.content)
    except Exception:  # noqa: BLE001 - malformed customer content is incomplete evidence
        return None


def _transition_token(condition: object) -> str:
    """Extract one authored transition token without evaluating the predicate."""
    raw = str(condition or "").strip()
    if not raw:
        return ""
    try:
        parsed = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw
    if not isinstance(parsed, dict):
        return raw
    operands = parsed.get("Operands")
    if isinstance(operands, list):
        for operand in operands:
            if str(operand).casefold() == "escalation":
                return "Escalation"
        if len(operands) == 1:
            return str(operands[0])
    return raw


def _context_variable_names(value: object) -> list[str]:
    """Return deterministic variable names while discarding every value."""
    if isinstance(value, dict):
        return sorted({str(name) for name in value})
    if isinstance(value, list):
        names = {
            str(item["Name"])
            for item in value
            if isinstance(item, dict) and item.get("Name") not in (None, "")
        }
        return sorted(names)
    return []


def _safe_action_evidence(flow: ContactFlow, action: FlowAction) -> dict[str, object]:
    """Describe an ACXD handoff without retaining context-variable values."""
    params = action.parameters if isinstance(action.parameters, dict) else {}
    agent_config = params.get("AgentConfiguration")
    agent_config = agent_config if isinstance(agent_config, dict) else {}
    context_names = _context_variable_names(params.get("ContextVariables"))
    condition_tokens = sorted(
        {
            token
            for transition in action.transitions
            if transition.transition_type == "condition"
            and (token := _transition_token(transition.condition))
        }
    )
    error_tokens = sorted(
        {
            token
            for transition in action.error_transitions
            if (token := _transition_token(transition.condition))
        }
    )
    return {
        "flow": flow.name,
        "flow_id": flow.id,
        "action_id": action.action_id,
        "workspace_id": agent_config.get("WorkspaceId"),
        "application_id": agent_config.get("ApplicationId"),
        "alias": agent_config.get("Alias"),
        "context_variable_count": len(context_names),
        "context_variable_names": context_names,
        "context_values_redacted": True,
        "speech_recognition_configured": "SpeechRecognitionConfiguration" in params,
        "audio_filler_configured": "AudioFillerConfiguration" in params,
        "completed_route_configured": any(
            transition.transition_type == "default" for transition in action.transitions
        ),
        "condition_outcomes": condition_tokens,
        "error_outcomes": error_tokens,
        "other_outcome_configured": "NoMatchingCondition" in error_tokens,
    }


def _collect_inventory(context: CheckContext) -> _FlowInventory:
    """Collect all reachable ACXD handoffs for one instance."""
    instance = context.instance
    customer_flows = sorted(
        (flow for flow in instance.contact_flows if not is_default_sample_flow(flow)),
        key=lambda flow: ((flow.name or "").casefold(), flow.id),
    )
    observations: list[_ActionObservation] = []
    skipped_flows: list[dict[str, str]] = []
    flows_analyzed = 0
    unreachable_actions = 0

    for flow in customer_flows:
        graph = _parse_flow(flow)
        if graph is None:
            reason = (
                "flow content unavailable"
                if not flow.content or not isinstance(flow.content, dict)
                else "flow content parse failed"
            )
            skipped_flows.append({"flow": flow.name, "flow_id": flow.id, "reason": reason})
            continue
        if not graph.actions:
            skipped_flows.append(
                {"flow": flow.name, "flow_id": flow.id, "reason": "flow has no actions"}
            )
            continue
        if graph.entry_point_id not in graph.actions:
            skipped_flows.append(
                {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "reason": "entry action is missing or invalid",
                }
            )
            continue

        flows_analyzed += 1
        reachable_ids = reachable_from_entry(graph)
        actions = sorted(
            (action for action in graph.actions.values() if action.action_type == ACXD_ACTION_TYPE),
            key=lambda action: action.action_id,
        )
        unreachable_actions += sum(action.action_id not in reachable_ids for action in actions)
        observations.extend(
            _ActionObservation(flow, action, _safe_action_evidence(flow, action))
            for action in actions
            if action.action_id in reachable_ids
        )

    limitations = (f"{len(skipped_flows)} flow(s) could not be analyzed",) if skipped_flows else ()
    common_evidence: dict[str, object] = {
        "flows_discovered": len(instance.contact_flows),
        "customer_flows_discovered": len(customer_flows),
        "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
        "flows_analyzed": flows_analyzed,
        "flows_skipped": len(skipped_flows),
        "skipped_flow_details": skipped_flows,
        "reachable_acxd_actions": len(observations),
        "unreachable_acxd_actions_ignored": unreachable_actions,
        "analysis_complete": not limitations,
        "limitations": list(limitations),
        "evidence_boundary": (
            "The Connect flow proves the ACXD handoff and authored branches only; "
            "application content, builds, deployments, alias resolution, runtime "
            "containment, and guardrails were not inspected."
        ),
    }
    return _FlowInventory(tuple(observations), common_evidence, limitations)


# All three ACXD checks need the same parsed-flow inventory, so it is built
# once per ConnectInstance object instead of re-parsing every flow per check.
# Keyed on object identity (validated through the weakref) rather than
# instance_id so a rebuilt instance with changed flows never reads stale data.
# Entries evict themselves when the instance is garbage collected. A race
# between two workers computing the same inventory is benign: the build is
# pure CPU over already-fetched flow content and deterministic.
_inventory_cache: dict[int, tuple[weakref.ref, _FlowInventory]] = {}
_inventory_cache_lock = threading.Lock()


def _get_inventory(context: CheckContext) -> _FlowInventory:
    """Return the memoized flow inventory for this context's instance."""
    instance = context.instance
    key = id(instance)
    with _inventory_cache_lock:
        cached = _inventory_cache.get(key)
        if cached is not None and cached[0]() is instance:
            return cached[1]

    inventory = _collect_inventory(context)

    def _evict(reference: weakref.ref, cache_key: int = key) -> None:
        with _inventory_cache_lock:
            entry = _inventory_cache.get(cache_key)
            if entry is not None and entry[0] is reference:
                del _inventory_cache[cache_key]

    with _inventory_cache_lock:
        _inventory_cache[key] = (weakref.ref(instance, _evict), inventory)
    return inventory


def _not_applicable(check: BaseCheck, context: CheckContext, evidence: dict[str, object]):
    return check.not_applicable(
        context,
        "no reachable ConnectParticipantWithAgenticCX action was found in completely "
        "analyzed customer-authored flows",
        resource_type="ContactFlow",
        evidence=evidence,
    )


class ACXDHandoffInventoryCheck(BaseCheck):
    """Inventory Connect-to-ACXD handoffs without judging application internals."""

    def __init__(self):
        super().__init__(
            check_id="ops-acxd-handoff-001",
            name="Agentic CX Handoff Inventory",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.LOW,
            disposition=FindingDisposition.INFORMATIONAL,
            description=(
                "Inventories reachable Agentic CX handoffs and their Connect-side identifiers, "
                "optional feature presence, and redacted context-variable names."
            ),
            remediation_template=(
                "Confirm each handoff references the intended workspace, application, and alias; "
                "validate application content and deployment separately in Agentic CX Designer."
            ),
        )

    def execute(self, context: CheckContext):
        inventory = _get_inventory(context)
        evidence = {
            **inventory.common_evidence,
            "acxd_handoffs": [observation.evidence for observation in inventory.observations],
        }
        if inventory.limitations:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=context.instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    "Agentic CX handoff inventory is incomplete: "
                    + "; ".join(inventory.limitations)
                    + ". Partial redacted observations are retained."
                ),
                evidence=evidence,
            )
        if not inventory.observations:
            return _not_applicable(self, context, evidence)
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"Inventoried {len(inventory.observations)} reachable Agentic CX handoff(s). "
                "This confirms only the Connect-side handoff configuration."
            ),
            evidence=evidence,
        )


class ACXDErrorRoutingCheck(BaseCheck):
    """Require explicit idle-timeout and catch-all error routes."""

    def __init__(self):
        super().__init__(
            check_id="res-acxd-error-routing-001",
            name="Agentic CX Error and Idle-Timeout Routing",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "Checks every reachable Agentic CX handoff for InputTimeLimitExceeded and "
                "NoMatchingError transitions."
            ),
            remediation_template=(
                "Connect InputTimeLimitExceeded to an intentional idle-timeout experience and "
                "NoMatchingError to a caller-safe fallback, then test both outcomes."
            ),
        )

    def execute(self, context: CheckContext):
        inventory = _get_inventory(context)
        defects: list[dict[str, object]] = []
        for observation in inventory.observations:
            error_tokens = set(observation.evidence["error_outcomes"])
            missing = [token for token in _REQUIRED_ERROR_ROUTES if token not in error_tokens]
            if missing:
                defects.append({**observation.evidence, "missing_requirements": missing})
        evidence = {
            **inventory.common_evidence,
            "acxd_action_evidence": [item.evidence for item in inventory.observations],
            "actions_with_missing_routes": len(defects),
            "defect_details": defects[:20],
            "defect_rows_omitted": max(0, len(defects) - 20),
        }
        if defects:
            limitation = (
                " Other flow evidence is incomplete: " + "; ".join(inventory.limitations) + "."
                if inventory.limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=context.instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(defects)} reachable Agentic CX handoff(s) lack an explicit "
                    f"idle-timeout or error route.{limitation} NoMatchingCondition is reported "
                    "as another authored outcome but does not replace either required route."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Add the missing ACXD idle-timeout and error routes.",
                    target_resources=[
                        f"{row['flow_id']}:{row['action_id']}" for row in defects[:20]
                    ],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Connect InputTimeLimitExceeded to an intentional idle-timeout "
                                "experience and NoMatchingError to a caller-safe fallback."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Publish the flow and test both outcomes. Validate the internal "
                                "Agentic CX application separately."
                            ),
                        ),
                    ],
                ),
            )
        if inventory.limitations:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=context.instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    "Agentic CX error-routing analysis is incomplete and cannot report PASS: "
                    + "; ".join(inventory.limitations)
                    + "."
                ),
                evidence=evidence,
            )
        if not inventory.observations:
            return _not_applicable(self, context, evidence)
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"All {len(inventory.observations)} reachable Agentic CX handoff(s) have "
                "InputTimeLimitExceeded and NoMatchingError routes."
            ),
            evidence=evidence,
        )


class ACXDEscalationReviewCheck(BaseCheck):
    """Identify ACXD handoffs whose human-escalation intent needs review."""

    def __init__(self):
        super().__init__(
            check_id="ops-acxd-escalation-001",
            name="Agentic CX Escalation Path Review",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.MEDIUM,
            disposition=FindingDisposition.MANUAL_REVIEW,
            description=(
                "Identifies reachable Agentic CX handoffs without an explicit Escalation "
                "condition route for workload-specific experience review."
            ),
            remediation_template=(
                "Confirm whether the workload requires human escalation. If it does, connect and "
                "test an Escalation condition route; otherwise document the intentional design."
            ),
        )

    def execute(self, context: CheckContext):
        inventory = _get_inventory(context)
        candidates = [
            observation.evidence
            for observation in inventory.observations
            if "Escalation" not in observation.evidence["condition_outcomes"]
        ]
        evidence = {
            **inventory.common_evidence,
            "acxd_action_evidence": [item.evidence for item in inventory.observations],
            "escalation_review_candidates": len(candidates),
            "candidate_details": candidates[:20],
            "candidate_rows_omitted": max(0, len(candidates) - 20),
        }
        if candidates:
            limitation = (
                " Other flow evidence is incomplete: " + "; ".join(inventory.limitations) + "."
                if inventory.limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=context.instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(candidates)} reachable Agentic CX handoff(s) have no explicit "
                    f"Escalation condition route.{limitation} This is a review candidate, not "
                    "proof that human escalation is required."
                ),
                evidence=evidence,
            )
        if inventory.limitations:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=context.instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    "Agentic CX escalation-path review is incomplete and cannot report PASS: "
                    + "; ".join(inventory.limitations)
                    + "."
                ),
                evidence=evidence,
            )
        if not inventory.observations:
            return _not_applicable(self, context, evidence)
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"All {len(inventory.observations)} reachable Agentic CX handoff(s) include an "
                "explicit Escalation condition route. Workload intent still requires review."
            ),
            evidence=evidence,
        )


def register_acxd_checks(registry) -> None:
    """Register the three flow-dependent Connect-side ACXD records."""
    registry.register_check(ACXDHandoffInventoryCheck())
    registry.register_check(ACXDErrorRoutingCheck())
    registry.register_check(ACXDEscalationReviewCheck())
