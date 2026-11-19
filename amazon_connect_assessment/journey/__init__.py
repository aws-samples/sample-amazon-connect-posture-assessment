"""
Customer Journey Mapping and Scoring.

Discovers entry points on every channel (voice numbers, SMS and WhatsApp
numbers, email addresses, and traffic-observed entry flows for web chat and
tasks), stitches the flows they reach into an instance-wide super-graph,
enumerates every customer journey, and scores each one with its channel's
rules for security/containment/resilience/CX gaps. Produces the
``journey-*`` findings that surface in the assessment report.

Diagram rendering for the top-N flows lives in :mod:`journey.renderer`
(Mermaid ``flowchart TD``) and is invoked separately by the engine.

Usage:
    from amazon_connect_assessment.journey import run_journey_mapping
    output = run_journey_mapping(instance, parsed_flows, factory, config)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from ..aws_client_factory import AWSClientFactory
from ..models import ConnectInstance, ContactFlowGraph, Finding
from .models import JourneyMapResult


@dataclass
class JourneyMappingOutput:
    """Output container for journey mapping results + findings."""

    result: JourneyMapResult
    findings: List[Finding] = field(default_factory=list)


def run_journey_mapping(
    instance: ConnectInstance,
    parsed_flows: Dict[str, ContactFlowGraph],
    factory: AWSClientFactory,
    config: Dict[str, Any],
    selected_control_ids: Optional[Iterable[str]] = None,
) -> JourneyMappingOutput:
    """
    Execute the full journey mapping pipeline.

    Steps:
    1. Resolve topology (phone numbers → flows, tier classification)
    2. Build super-graph (stitch flows at transfer boundaries)
    3. Enumerate paths (bounded DFS from each entry point)
    4. Score journeys (security, containment, resilience, CX)
    5. Generate findings

    Returns:
        JourneyMappingOutput with findings and result data for reporting.
    """
    from .journey_scorer import generate_journey_findings, score_journeys
    from .path_enumerator import _coverage_limitations, enumerate_entry_journeys
    from .super_graph import build_super_graph
    from .topology import _compute_transitive_reachability, discover_entry_points

    # Step 1: Entry points on every channel, and flow tiers.
    discovery = discover_entry_points(
        instance_id=instance.instance_id,
        instance_arn=instance.instance_arn,
        factory=factory,
        parsed_flows=parsed_flows,
        config=config,
    )
    tier_assignments = discovery.tier_assignments
    channel_traffic = discovery.channel_traffic

    # Step 2: Build super-graph (tier 1 only — see build_super_graph)
    super_graph = build_super_graph(parsed_flows, tier_assignments)

    # Step 3: Enumerate paths from every entry point.
    max_paths = config.get("journey_map", {}).get("max_paths_per_did", 200)
    max_depth = config.get("journey_map", {}).get("max_depth", 50)
    journeys, per_entry = enumerate_entry_journeys(
        super_graph=super_graph,
        entry_points=discovery.entry_points,
        max_paths=max_paths,
        max_depth=max_depth,
    )

    # Step 4: Coverage per channel. A dynamic reference or cap only makes the
    # channels whose entries actually reach it incomplete.
    channel_coverage = _channel_coverage(
        discovery,
        journeys,
        per_entry,
        super_graph,
        parsed_flows,
        _coverage_limitations,
        _compute_transitive_reachability,
    )
    enumeration_limitations = list(
        dict.fromkeys(
            item for coverage in channel_coverage.values() for item in coverage["limitations"]
        )
    )
    enumeration_complete = all(c["complete"] for c in channel_coverage.values())

    # Step 5: Score journeys with their channel's rules.
    scores = score_journeys(journeys, config)

    # Step 6: Assemble result
    dormant_flows = [t.flow_id for t in tier_assignments if t.tier == "tier3_dormant"]
    traffic_observed_flows = [t.flow_id for t in tier_assignments if t.tier == "tier2_traffic"]

    result = JourneyMapResult(
        phone_entries=discovery.phone_entries,
        entry_points=discovery.entry_points,
        tier_assignments=tier_assignments,
        journeys=journeys,
        scores=scores,
        dormant_flows=dormant_flows,
        traffic_observed_flows=traffic_observed_flows,
        usage_metrics_status=channel_traffic.status,
        usage_window_days=channel_traffic.window_days,
        dynamic_edges=super_graph.dynamic_references,
        containment_scores=_compute_containment_scores(discovery.entry_points, journeys),
        enumeration_complete=enumeration_complete,
        enumeration_limitations=enumeration_limitations,
        channel_coverage=channel_coverage,
        entry_discovery_limitations=discovery.limitations,
    )

    # Step 7: Generate one canonical outcome per selected Journey control.
    findings = generate_journey_findings(
        result,
        instance_id=instance.instance_id,
        selected_control_ids=selected_control_ids,
    )

    return JourneyMappingOutput(result=result, findings=findings)


def _channel_coverage(
    discovery,
    journeys: List,
    per_entry: Dict[str, List[str]],
    super_graph,
    parsed_flows: Dict[str, ContactFlowGraph],
    coverage_filter,
    reachability,
) -> Dict[str, Dict[str, Any]]:
    """Per-channel completeness for channels with entries or discovery gaps."""
    from .models import CHANNELS

    channels = {e.channel for e in discovery.entry_points} | set(discovery.incomplete_channels)
    coverage: Dict[str, Dict[str, Any]] = {}
    for channel in CHANNELS:
        if channel not in channels:
            continue
        entries = [e for e in discovery.entry_points if e.channel == channel]
        limitations = [item for e in entries for item in coverage_filter(per_entry.get(e.key, []))]
        reached = reachability({e.contact_flow_id for e in entries}, parsed_flows)
        dynamic = [
            ref for ref in super_graph.dynamic_references if ref.get("source_flow") in reached
        ]
        if dynamic:
            limitations.append(f"{len(dynamic)} dynamic cross-flow reference(s) unresolved")
        if channel in discovery.incomplete_channels:
            limitations.append("entry-point discovery was incomplete for this channel")
        limitations = list(dict.fromkeys(limitations))
        coverage[channel] = {
            "complete": not limitations,
            "limitations": limitations,
            "entry_points": len(entries),
            "journeys": sum(1 for j in journeys if j.entry_channel == channel),
        }
    return coverage


def _compute_containment_scores(entry_points: List, journeys: List) -> Dict[str, float]:
    """Per entry point: % of its paths that resolve without an agent."""
    result: Dict[str, float] = {}
    for entry in entry_points:
        entry_journeys = [j for j in journeys if j.entry_key == entry.key]
        if not entry_journeys:
            result[entry.key] = 0.0
            continue
        non_agent = sum(1 for j in entry_journeys if j.terminal_type != "agent_queue")
        result[entry.key] = non_agent / len(entry_journeys) * 100
    return result
