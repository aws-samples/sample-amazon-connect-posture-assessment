"""
Bounded path enumeration for Customer Journey Mapping.

Traces all possible customer paths from each entry point — on any channel —
to terminal outcomes using iterative DFS with depth and path-count bounds.
"""

import logging
from typing import Any, Dict, List, Tuple

from .models import EntryPoint, JourneyNode, JourneyPath, PhoneNumberEntry, SuperGraph

logger = logging.getLogger("journey.path_enumerator")

# Terminal action types and their outcome classification.
TERMINAL_ACTIONS = {
    "TransferToQueue": "agent_queue",
    "TransferContactToQueue": "agent_queue",
    "DisconnectParticipant": "disconnect",
    "EndFlowExecution": "disconnect",
    "CreateCallback": "callback",
    "SetCallbackNumber": "callback",
    "TransferContactToPhoneNumber": "external_transfer",
    "TransferToPhoneNumber": "external_transfer",
}

# Cross-flow action types — kept in sync with super_graph.CROSS_FLOW_ACTIONS.
# A node of one of these types with no outgoing super-graph edge means the
# target flow reference couldn't be statically resolved (dynamic/attribute
# reference), not that the caller's journey actually dead-ends here.
_CROSS_FLOW_ACTION_TYPES = {
    "TransferToFlow",
    "TransferContactToFlow",
    "InvokeFlowModule",
}

MAX_PATHS_PER_ENTRY = 200
MAX_PATH_DEPTH = 50
MAX_TOTAL_PATHS = 5000
# Work cap per entry point: bounds DFS node expansions even when few paths complete
# (e.g. heavily branching graphs whose branches are pruned by loop detection).
MAX_STEPS_PER_ENTRY = 100_000


def enumerate_journeys(
    super_graph: SuperGraph,
    phone_entries: List[PhoneNumberEntry],
    max_paths: int = MAX_PATHS_PER_ENTRY,
    max_depth: int = MAX_PATH_DEPTH,
) -> List[JourneyPath]:
    """Enumerate bounded paths, preserving the original list-only API."""
    journeys, _, _ = enumerate_journeys_with_completeness(
        super_graph,
        phone_entries,
        max_paths=max_paths,
        max_depth=max_depth,
    )
    return journeys


def enumerate_journeys_with_completeness(
    super_graph: SuperGraph,
    phone_entries: List[PhoneNumberEntry],
    max_paths: int = MAX_PATHS_PER_ENTRY,
    max_depth: int = MAX_PATH_DEPTH,
) -> Tuple[List[JourneyPath], bool, List[str]]:
    """Voice-era API: enumerate from phone entries; report overall completeness."""
    entries = [
        EntryPoint(
            channel="VOICE",
            entry_type=entry.number_type,
            identifier=entry.phone_number,
            contact_flow_id=entry.contact_flow_id or "",
        )
        for entry in phone_entries
    ]
    journeys, per_entry = enumerate_entry_journeys(super_graph, entries, max_paths, max_depth)
    limitations = list(dict.fromkeys(item for items in per_entry.values() for item in items))
    return journeys, not _coverage_limitations(limitations), limitations


def enumerate_entry_journeys(
    super_graph: SuperGraph,
    entry_points: List[EntryPoint],
    max_paths: int = MAX_PATHS_PER_ENTRY,
    max_depth: int = MAX_PATH_DEPTH,
) -> Tuple[List[JourneyPath], Dict[str, List[str]]]:
    """Enumerate paths from every entry point.

    Returns the journeys and, per ``EntryPoint.key``, the limitations hit while
    enumerating it, so coverage can be judged per channel: a gap on a chat
    entry must not mark voice incomplete. Entries arrive sorted voice-first,
    so the global path cap is the last thing to starve voice.
    """
    all_journeys: List[JourneyPath] = []
    per_entry: Dict[str, List[str]] = {}

    for entry_index, entry in enumerate(entry_points):
        limitations = per_entry.setdefault(entry.key, [])
        if not entry.contact_flow_id:
            limitations.append("entry is missing an associated contact flow")
            continue
        entry_key = super_graph.entry_points.get(entry.contact_flow_id)
        if not entry_key:
            limitations.append(
                f"contact flow {entry.contact_flow_id} is missing a graph entry point"
            )
            continue

        paths, entry_limitations = _enumerate_from_entry(
            super_graph,
            entry_key,
            entry.identifier,
            entry.entry_type,
            max_paths,
            max_depth,
            entry_channel=entry.channel,
        )
        all_journeys.extend(paths)
        limitations.extend(entry_limitations)
        if len(all_journeys) >= MAX_TOTAL_PATHS:
            exceeded_limit = len(all_journeys) > MAX_TOTAL_PATHS
            all_journeys = all_journeys[:MAX_TOTAL_PATHS]
            unprocessed = entry_points[entry_index + 1 :]
            if exceeded_limit or unprocessed:
                note = f"global path limit {MAX_TOTAL_PATHS} reached"
                limitations.append(note)
                for skipped in unprocessed:
                    per_entry.setdefault(skipped.key, []).append(note)
                logger.warning(
                    f"Global path limit ({MAX_TOTAL_PATHS}) reached; stopping enumeration early"
                )
                break

    per_entry = {key: list(dict.fromkeys(items)) for key, items in per_entry.items()}
    logger.info(
        f"Enumerated {len(all_journeys)} journey paths across {len(entry_points)} entry points"
    )
    return all_journeys, per_entry


def _coverage_limitations(limitations: List[str]) -> List[str]:
    """Limitations that reduce coverage (loop-back pruning does not)."""
    return [item for item in limitations if not item.startswith("loop-back edges pruned")]


def _enumerate_from_entry(
    graph: SuperGraph,
    entry_key: str,
    entry_number: str,
    entry_type: str,
    max_paths: int,
    max_depth: int,
    max_steps: int = MAX_STEPS_PER_ENTRY,
    entry_channel: str = "VOICE",
) -> Tuple[List[JourneyPath], List[str]]:
    """Run bounded iterative DFS and report any cap that truncated coverage."""
    paths: List[JourneyPath] = []
    limitations: List[str] = []
    stack: List[tuple] = [(entry_key, [], frozenset([entry_key]))]

    steps = 0
    loop_backs_dropped = 0
    while stack and len(paths) < max_paths:
        if steps >= max_steps:
            limitations.append(f"per-entry step limit {max_steps} reached")
            break
        steps += 1
        current_key, path_nodes, visited = stack.pop()
        node = graph.get_node(current_key)

        if node is None:
            limitations.append(f"graph node {current_key} is missing")
            continue

        current_path = path_nodes + [node]

        # Depth bound. A path that hits this limit is a real journey the
        # caller can actually experience — it just happens to be long — so
        # record it as a truncated path rather than silently dropping it.
        # The prior behavior (`continue` with no recorded path) meant any
        # flow deep/branchy enough to need the depth cap produced ZERO
        # journeys for that branch, which is a false negative: security,
        # containment, and dead-end checks downstream never saw that path
        # at all, so a genuinely dead-ended or unauthenticated long path
        # was invisible to every journey-* finding.
        if len(current_path) > max_depth:
            limitations.append(f"maximum depth {max_depth} exceeded")
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))
            paths.append(
                JourneyPath(
                    entry_identifier=entry_number,
                    entry_type=entry_type,
                    entry_channel=entry_channel,
                    nodes=current_path,
                    terminal_type="truncated",
                    terminal_details={
                        "reason": "max_depth_exceeded",
                        "last_action": node.action_type,
                        "depth": len(current_path),
                    },
                    flows_traversed=flows_seen,
                )
            )
            continue

        # Check if terminal.
        terminal_type = TERMINAL_ACTIONS.get(node.action_type)
        if terminal_type:
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))
            paths.append(
                JourneyPath(
                    entry_identifier=entry_number,
                    entry_type=entry_type,
                    entry_channel=entry_channel,
                    nodes=current_path,
                    terminal_type=terminal_type,
                    terminal_details=_extract_terminal_details(node),
                    flows_traversed=flows_seen,
                )
            )
            continue

        # Expand successors.
        successors = graph.successors(current_key)
        if not successors:
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))

            # A cross-flow action (TransferToFlow/TransferContactToFlow/
            # InvokeFlowModule) with no outgoing edge is NOT necessarily a
            # dead end — super_graph.build_super_graph only adds an edge
            # when it could statically resolve the target flow. When the
            # target is a dynamic/attribute-based reference (e.g. "transfer
            # to the flow named in $.Attributes.NextFlow"), no edge exists
            # even though the call is actually being routed somewhere at
            # runtime; the graph just can't say where. Labeling that
            # "disconnect" / "dead_end" was fabricating a real defect
            # (journey-res-001 "Dead-End Caller Path", HIGH severity) for
            # what is often a perfectly normal dynamic-routing pattern.
            # Give it its own terminal_type so journey_scorer can decide
            # whether/how to surface it, rather than conflating it with an
            # actual dead end.
            if node.action_type in _CROSS_FLOW_ACTION_TYPES:
                limitations.append("unresolved dynamic transfer target")
                paths.append(
                    JourneyPath(
                        entry_identifier=entry_number,
                        entry_type=entry_type,
                        entry_channel=entry_channel,
                        nodes=current_path,
                        terminal_type="unresolved_transfer",
                        terminal_details={
                            "reason": "dynamic_transfer_target",
                            "last_action": node.action_type,
                        },
                        flows_traversed=flows_seen,
                    )
                )
                continue

            # Genuine dead-end: no successors, not a recognized terminal,
            # and not an unresolved dynamic transfer either.
            paths.append(
                JourneyPath(
                    entry_identifier=entry_number,
                    entry_type=entry_type,
                    entry_channel=entry_channel,
                    nodes=current_path,
                    terminal_type="disconnect",
                    terminal_details={
                        "reason": "dead_end",
                        "last_action": node.action_type,
                    },
                    flows_traversed=flows_seen,
                )
            )
            continue

        for succ_key in successors:
            if succ_key in visited:
                loop_backs_dropped += 1
            else:
                stack.append(
                    (
                        succ_key,
                        current_path,
                        visited | frozenset([succ_key]),
                    )
                )

    if loop_backs_dropped:
        limitations.append(
            f"loop-back edges pruned: {loop_backs_dropped}; cycles were present but ordinary "
            "node revisits were not enumerated"
        )
    if stack and not any(item.startswith("per-entry step limit") for item in limitations):
        limitations.append(f"per-entry path limit {max_paths} reached")
    return paths, limitations


def _extract_terminal_details(node: JourneyNode) -> Dict[str, Any]:
    """Extract relevant details from a terminal node."""
    details: Dict[str, Any] = {
        "action_type": node.action_type,
        "flow_name": node.flow_name,
    }
    params = node.parameters

    if node.action_type in ("TransferToQueue", "TransferContactToQueue"):
        details["queue"] = params.get("QueueId", params.get("Queue", "unknown"))

    elif node.action_type in ("TransferContactToPhoneNumber", "TransferToPhoneNumber"):
        details["phone_number"] = params.get("PhoneNumber", "unknown")

    return details
