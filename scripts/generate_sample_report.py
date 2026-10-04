#!/usr/bin/env python3
"""Regenerate the checked-in sample assessment report.

``examples/sample_assessment_report.html`` is the report a prospective user opens
before installing anything, and the source for the README screenshot. It is built
here from the *live* check registry rather than captured from a real run, so it
cannot go stale as checks are added, and so it never contains real customer data.

Findings are assigned deterministically from a seeded RNG, which keeps the output
byte-stable across runs — regenerating after a styling change produces a diff that
only reflects the styling change.

    python scripts/generate_sample_report.py
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sample_contact_flows import (  # noqa: E402
    BILLING_FLOW,
    BILLING_ID,
    MAIN_IVR_FLOW,
    MAIN_IVR_ID,
    OVERFLOW_FLOW,
    OVERFLOW_ID,
    dormant_flow_specs,
)

from amazon_connect_assessment.checks.base import BaseCheck  # noqa: E402
from amazon_connect_assessment.checks.control_registry import (  # noqa: E402
    AtomicControl,
    ExecutionSource,
)
from amazon_connect_assessment.checks.registration import register_all_checks  # noqa: E402
from amazon_connect_assessment.checks.registry import CheckRegistry  # noqa: E402
from amazon_connect_assessment.journey.journey_scorer import (  # noqa: E402
    generate_journey_findings,
    score_journeys,
)
from amazon_connect_assessment.journey.models import (  # noqa: E402
    JourneyMapResult,
    PhoneNumberEntry,
    TierAssignment,
)
from amazon_connect_assessment.journey.path_enumerator import enumerate_journeys  # noqa: E402
from amazon_connect_assessment.journey.renderer import flow_to_diagram_artifacts  # noqa: E402
from amazon_connect_assessment.journey.super_graph import build_super_graph  # noqa: E402
from amazon_connect_assessment.models import (  # noqa: E402
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    ContactFlow,
    Finding,
    FindingDisposition,
    Pillar,
    Severity,
)
from amazon_connect_assessment.parsers import ContactFlowParser  # noqa: E402
from amazon_connect_assessment.report_generator import ReportGenerator  # noqa: E402
from amazon_connect_assessment.score_policy import (  # noqa: E402
    FindingScoreClassification,
    classify_finding,
    compute_scored_control_counts,
    is_control_failure,
)

DEFAULT_OUTPUT = REPO_ROOT / "examples" / "sample_assessment_report.html"

# Documentation-only placeholders. 111122223333 is the account ID AWS reserves for
# examples, and the instance IDs are fixed so the sample diff stays readable.
SAMPLE_ACCOUNT_ID = "111122223333"
SAMPLE_REGION = "us-east-1"
SAMPLE_ASSESSMENT_ID = "00000000-0000-4000-8000-000000000001"
SAMPLE_TIMESTAMP = datetime(2026, 1, 15, 14, 30, 0)
SAMPLE_SEED = 20260115

# Weighted so the sample shows a realistic mix: mostly passing, a meaningful tail of
# failures to demonstrate the remediation guidance, and a few access-denied skips.
STATUS_WEIGHTS: list[tuple[CheckStatus, int]] = [
    (CheckStatus.PASS, 62),
    (CheckStatus.FAIL, 27),
    (CheckStatus.SKIPPED, 6),
    (CheckStatus.NOT_APPLICABLE, 4),
    (CheckStatus.ERROR, 1),
]

PRIMARY_INSTANCE_ID = "11111111-1111-4111-8111-111111111111"
OVERFLOW_INSTANCE_ID = "22222222-2222-4222-8222-222222222222"

# Reserved-for-documentation ranges: +1 800 555 01xx is the North American
# fictional-number block, and 206-555-01xx is its DID equivalent.
SAMPLE_PHONE_NUMBERS: dict[str, list[dict[str, str]]] = {
    PRIMARY_INSTANCE_ID: [
        {
            "PhoneNumber": "+18005550100",
            "PhoneNumberType": "TOLL_FREE",
            "PhoneNumberCountryCode": "US",
            "PhoneNumberDescription": "Main customer service line",
            "flow_id": MAIN_IVR_ID,
        },
        {
            "PhoneNumber": "+12065550142",
            "PhoneNumberType": "DID",
            "PhoneNumberCountryCode": "US",
            "PhoneNumberDescription": "Seattle local number",
            "flow_id": MAIN_IVR_ID,
        },
    ],
    OVERFLOW_INSTANCE_ID: [
        {
            "PhoneNumber": "+18005550199",
            "PhoneNumberType": "TOLL_FREE",
            "PhoneNumberCountryCode": "US",
            "PhoneNumberDescription": "Peak-season overflow line",
            "flow_id": OVERFLOW_ID,
        },
    ],
}


def _flow(instance_id: str, flow_id: str, name: str, flow_type: str, content: dict) -> ContactFlow:
    """Build a ContactFlow the way instance discovery would return it."""
    return ContactFlow(
        id=flow_id,
        arn=(
            f"arn:aws:connect:{SAMPLE_REGION}:{SAMPLE_ACCOUNT_ID}:instance/"
            f"{instance_id}/contact-flow/{flow_id}"
        ),
        name=name,
        type=flow_type,
        state="ACTIVE",
        content=content,
    )


def _build_instances() -> list[ConnectInstance]:
    """Build the two synthetic instances, including their contact flows."""
    primary_flows = [
        _flow(PRIMARY_INSTANCE_ID, MAIN_IVR_ID, "Main IVR", "CONTACT_FLOW", MAIN_IVR_FLOW),
        _flow(PRIMARY_INSTANCE_ID, BILLING_ID, "Billing Support", "CONTACT_FLOW", BILLING_FLOW),
    ]
    primary_flows.extend(
        _flow(PRIMARY_INSTANCE_ID, spec["id"], spec["name"], spec["type"], spec["content"])
        for spec in dormant_flow_specs(1)
    )

    return [
        ConnectInstance(
            instance_id=PRIMARY_INSTANCE_ID,
            instance_arn=(
                f"arn:aws:connect:{SAMPLE_REGION}:{SAMPLE_ACCOUNT_ID}:instance/"
                f"{PRIMARY_INSTANCE_ID}"
            ),
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            instance_alias="example-contact-center",
            service_role=(
                f"arn:aws:iam::{SAMPLE_ACCOUNT_ID}:role/aws-service-role/connect.amazonaws.com"
            ),
            status="ACTIVE",
            contact_flows=primary_flows,
        ),
        ConnectInstance(
            instance_id=OVERFLOW_INSTANCE_ID,
            instance_arn=(
                f"arn:aws:connect:{SAMPLE_REGION}:{SAMPLE_ACCOUNT_ID}:instance/"
                f"{OVERFLOW_INSTANCE_ID}"
            ),
            identity_management_type="CONNECT_MANAGED",
            inbound_calls_enabled=True,
            outbound_calls_enabled=False,
            instance_alias="example-overflow",
            status="ACTIVE",
            contact_flows=[
                _flow(
                    OVERFLOW_INSTANCE_ID,
                    OVERFLOW_ID,
                    "Overflow Routing",
                    "CONTACT_FLOW",
                    OVERFLOW_FLOW,
                )
            ],
        ),
    ]


SAMPLE_INSTANCES = _build_instances()


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the sample report build."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Destination HTML file (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=SAMPLE_SEED,
        help=f"RNG seed controlling the finding mix (default: {SAMPLE_SEED})",
    )
    return parser.parse_args()


def _selected_execution_plan() -> tuple[list[AtomicControl], dict[str, BaseCheck]]:
    """Return the unified selected controls and their BaseCheck executors."""
    registry = CheckRegistry()
    register_all_checks(registry)
    return registry.get_selected_controls(), {
        check.check_id: check for check in registry.get_all_checks()
    }


def _status_for(rng: random.Random, outcome_index: int) -> CheckStatus:
    """Pick a deterministic status while guaranteeing every status is represented."""
    required_statuses = tuple(CheckStatus)
    if outcome_index < len(required_statuses):
        return required_statuses[outcome_index]
    statuses = [status for status, _ in STATUS_WEIGHTS]
    weights = [weight for _, weight in STATUS_WEIGHTS]
    return rng.choices(statuses, weights=weights, k=1)[0]


def _describe(control: AtomicControl, check: BaseCheck, status: CheckStatus) -> str:
    """Build a status-appropriate description for a sample finding."""
    if status is CheckStatus.PASS:
        return f"{control.name} passed. {check.description}"
    if status is CheckStatus.SKIPPED:
        return (
            f"{control.name} was skipped because the assessing identity lacked a required "
            "read permission. Grant the permissions listed in the check catalog and re-run."
        )
    if status is CheckStatus.NOT_APPLICABLE:
        return f"{control.name} does not apply to this instance's configuration."
    if status is CheckStatus.ERROR:
        return f"{control.name} could not complete because an AWS API call was throttled."
    if control.disposition is FindingDisposition.MANUAL_REVIEW:
        return f"{control.name} found a review candidate. {check.description}"
    if control.disposition is FindingDisposition.INFORMATIONAL:
        return f"{control.name} recorded inventory context. {check.description}"
    return f"{control.name} found a measured control gap. {check.description}"


def _parse_flows(instance: ConnectInstance) -> dict:
    """Parse every flow on an instance, keyed by flow id.

    Mirrors ``AssessmentEngine._compute_journey_findings``, including the
    flow_id/flow_name backfill — ``Content`` never carries Identifier/Name, so
    without it every flow collapses onto the same super-graph key.
    """
    parser = ContactFlowParser()
    graphs = {}
    for flow in instance.contact_flows:
        graph = parser.parse(flow.content)
        graph.flow_id = flow.id
        graph.flow_name = flow.name
        graphs[flow.id] = graph
    return graphs


def _tier_assignments(instance: ConnectInstance, entry_flow_ids: set[str]) -> list[TierAssignment]:
    """Classify flows the way ``journey.topology.resolve_topology`` would.

    Flows a phone number terminates on are tier 1; flows reachable only via a
    transfer are tier 2; everything else is dormant. Assigned here rather than
    resolved from AWS because ``resolve_topology`` is the one step of the
    pipeline that needs live ``ListPhoneNumbersV2`` / ``ListFlowAssociations``
    calls. Every downstream step below is the production code.
    """
    transfer_targets = {BILLING_ID}
    assignments: list[TierAssignment] = []
    for flow in instance.contact_flows:
        if flow.id in entry_flow_ids:
            tier, rationale = "tier1_did", "Inbound phone number terminates on this flow"
        elif flow.id in transfer_targets:
            tier, rationale = "tier2_traffic", "Reached by a transfer from a tier 1 flow"
        else:
            tier, rationale = "tier3_dormant", "No phone number association and no inbound traffic"
        assignments.append(
            TierAssignment(flow_id=flow.id, flow_name=flow.name, tier=tier, rationale=rationale)
        )
    return assignments


def build_journey_data(
    instances: list[ConnectInstance],
) -> tuple[list[dict], list[Finding]]:
    """Run the journey pipeline over the sample flows.

    Returns ``(journey_map_entries, journey_findings)`` — the same two things
    ``AssessmentEngine`` produces, built by the same parser, super-graph, path
    enumerator, scorer and renderer.
    """
    entries: list[dict] = []
    findings: list[Finding] = []

    for instance in instances:
        numbers = SAMPLE_PHONE_NUMBERS[instance.instance_id]
        graphs = _parse_flows(instance)
        entry_flow_ids = {n["flow_id"] for n in numbers}

        # --- Caller Journey Map diagrams (one per number, deduped per flow) ---
        rendered: dict = {}
        for num in numbers:
            flow_id = num["flow_id"]
            flow = next(f for f in instance.contact_flows if f.id == flow_id)
            if flow_id not in rendered:
                rendered[flow_id] = flow_to_diagram_artifacts(graphs[flow_id])
            artifacts = rendered[flow_id]
            entries.append(
                {
                    "instance_id": instance.instance_id,
                    "instance_display_name": instance.display_name,
                    "phone_number": num["PhoneNumber"],
                    "phone_type": num["PhoneNumberType"],
                    "phone_country_code": num["PhoneNumberCountryCode"],
                    "phone_description": num["PhoneNumberDescription"],
                    "flow_id": flow_id,
                    "flow_name": flow.name,
                    "flow_type": flow.type,
                    "diagram_html": artifacts.diagram_html,
                    "diagram_model": artifacts.diagram_model,
                    "exports": artifacts.export_payload(),
                }
            )

        # --- journey-* findings ---
        assignments = _tier_assignments(instance, entry_flow_ids)
        super_graph = build_super_graph(graphs, assignments)
        phone_entries = [
            PhoneNumberEntry(
                phone_number=num["PhoneNumber"],
                number_type=num["PhoneNumberType"],
                country_code=num["PhoneNumberCountryCode"],
                contact_flow_id=num["flow_id"],
                contact_flow_name=next(
                    f.name for f in instance.contact_flows if f.id == num["flow_id"]
                ),
                target_arn=instance.instance_arn,
            )
            for num in numbers
        ]
        journeys = enumerate_journeys(super_graph=super_graph, phone_entries=phone_entries)
        scores = score_journeys(journeys, {})
        dormant = [a.flow_id for a in assignments if a.tier == "tier3_dormant"]
        containment = {
            e.phone_number: (
                sum(
                    1
                    for j in journeys
                    if j.entry_number == e.phone_number and j.terminal_type != "agent_queue"
                )
                / max(1, sum(1 for j in journeys if j.entry_number == e.phone_number))
                * 100
            )
            for e in phone_entries
        }
        result = JourneyMapResult(
            phone_entries=phone_entries,
            tier_assignments=assignments,
            journeys=journeys,
            scores=scores,
            dormant_flows=dormant,
            dynamic_edges=super_graph.dynamic_references,
            containment_scores=containment,
        )
        findings.extend(generate_journey_findings(result, instance_id=instance.instance_id))

    entries.sort(key=lambda e: (e["instance_display_name"], e["phone_number"]))
    return entries, findings


def _sample_evidence(control: AtomicControl, instance: ConnectInstance) -> dict:
    """Return deterministic evidence that exercises the report's generic renderers."""
    evidence = {
        "instance_alias": instance.instance_alias,
        "sample_data": True,
        "root_condition_key": control.root_condition_key,
    }
    if control.control_id == "perf-flow-complexity-001":
        evidence["flow_structural_metrics"] = [
            {
                "flow": "Main customer service IVR",
                "flow_id": "8f14e45f-ea6b-4f9d-93b3-9f8f477a2e17",
                "total_actions": 24,
                "reachable_actions": 22,
                "longest_route_transitions": 9,
                "route_analysis_capped": False,
                "integration_points": 3,
                "cycles": 1,
                "paths_enumerated": 18,
                "path_enumeration_capped": False,
                "module_invocations": 2,
            },
            {
                "flow": "Billing self-service",
                "flow_id": "45c48cce-2e2d-4c4f-9179-0f6a01c12345",
                "total_actions": 16,
                "reachable_actions": 16,
                "longest_route_transitions": 7,
                "route_analysis_capped": False,
                "integration_points": 2,
                "cycles": 0,
                "paths_enumerated": 12,
                "path_enumeration_capped": False,
                "module_invocations": 1,
            },
        ]
    return evidence


def build_sample_result(seed: int) -> AssessmentResult:
    """Construct one canonical outcome per control and synthetic instance."""
    rng = random.Random(seed)
    controls, base_checks = _selected_execution_plan()
    control_by_id = {control.control_id: control for control in controls}

    journey_map_entries, generated_journey_findings = build_journey_data(SAMPLE_INSTANCES)
    journey_by_instance_and_id = {
        (finding.instance_id, finding.check_id): finding for finding in generated_journey_findings
    }

    findings: list[Finding] = []
    for instance in SAMPLE_INSTANCES:
        for control in controls:
            if control.execution_source is ExecutionSource.JOURNEY:
                finding = journey_by_instance_and_id[(instance.instance_id, control.control_id)]
            else:
                check = base_checks[control.control_id]
                status = _status_for(rng, len(findings))
                finding = Finding(
                    check_id=control.control_id,
                    check_name=control.name,
                    pillar=control.pillar,
                    severity=control.default_severity,
                    status=status,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=_describe(control, check, status),
                    remediation=(
                        check.remediation_template
                        or "See the check catalog for remediation or review guidance."
                    ),
                    evidence=_sample_evidence(control, instance),
                    disposition=control.disposition,
                    methodology=control.methodology,
                    instance_id=instance.instance_id,
                )
            finding.timestamp = SAMPLE_TIMESTAMP + timedelta(seconds=len(findings))
            findings.append(finding)

    by_status = Counter(finding.status for finding in findings)
    by_disposition = Counter(finding.disposition for finding in findings)
    classifications = Counter(classify_finding(finding) for finding in findings)
    scored_numerator, scored_denominator = compute_scored_control_counts(findings)
    failed_controls = [finding for finding in findings if is_control_failure(finding)]
    by_severity = Counter(finding.severity for finding in failed_controls)
    journey_count = sum(
        control_by_id[finding.check_id].execution_source is ExecutionSource.JOURNEY
        for finding in findings
    )

    summary = AssessmentSummary(
        total_checks=len(findings),
        passed_checks=by_status[CheckStatus.PASS],
        failed_checks=by_status[CheckStatus.FAIL],
        error_checks=by_status[CheckStatus.ERROR],
        skipped_checks=by_status[CheckStatus.SKIPPED],
        not_applicable_checks=by_status[CheckStatus.NOT_APPLICABLE],
        critical_findings=by_severity[Severity.CRITICAL],
        high_findings=by_severity[Severity.HIGH],
        medium_findings=by_severity[Severity.MEDIUM],
        low_findings=by_severity[Severity.LOW],
        registered_checks=len(findings) - journey_count,
        journey_findings=journey_count,
        control_findings=by_disposition[FindingDisposition.CONTROL],
        manual_review_findings=by_disposition[FindingDisposition.MANUAL_REVIEW],
        informational_findings=by_disposition[FindingDisposition.INFORMATIONAL],
        scored_control_passes=classifications[FindingScoreClassification.SCORED_PASS],
        scored_control_failures=classifications[FindingScoreClassification.SCORED_FAIL],
        unevaluated_controls=classifications[FindingScoreClassification.UNEVALUATED_CONTROL],
        not_applicable_controls=sum(
            finding.disposition is FindingDisposition.CONTROL
            and finding.status is CheckStatus.NOT_APPLICABLE
            for finding in findings
        ),
        scored_control_numerator=scored_numerator,
        scored_control_denominator=scored_denominator,
    )

    metadata = AssessmentMetadata(
        tool_version="0.1.0",
        execution_time_seconds=42.7,
        aws_account_id=SAMPLE_ACCOUNT_ID,
        aws_region=SAMPLE_REGION,
        execution_environment="sample",
        python_version="3.12",
    )

    return AssessmentResult(
        assessment_id=SAMPLE_ASSESSMENT_ID,
        timestamp=SAMPLE_TIMESTAMP,
        account_id=SAMPLE_ACCOUNT_ID,
        region=SAMPLE_REGION,
        instances=SAMPLE_INSTANCES,
        findings=findings,
        summary=summary,
        metadata=metadata,
        execution_errors=[],
        journey_map_entries=journey_map_entries,
        journey_map_status=None,
    )


def main() -> int:
    """Render the sample report to disk."""
    args = parse_args()
    result = build_sample_result(args.seed)

    html = ReportGenerator().generate_html_report(
        assessment_result=result,
        include_raw_data=False,
        generated_at=SAMPLE_TIMESTAMP,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")

    pillar_counts = {pillar: 0 for pillar in Pillar}
    for finding in result.findings:
        pillar_counts[finding.pillar] += 1
    breakdown = ", ".join(
        f"{pillar.value}={count}" for pillar, count in pillar_counts.items() if count
    )

    print(f"Sample report written: {args.output} ({args.output.stat().st_size / 1024:.1f} KiB)")
    print(f"  {len(result.findings)} findings ({breakdown})")
    print(
        f"  pass={result.summary.passed_checks} fail={result.summary.failed_checks} "
        f"skipped={result.summary.skipped_checks} error={result.summary.error_checks} "
        f"not_applicable={result.summary.not_applicable_checks}"
    )
    print(
        f"  scored controls={result.summary.scored_control_numerator}/"
        f"{result.summary.scored_control_denominator}; "
        f"manual reviews={result.summary.manual_review_findings}; "
        f"informational={result.summary.informational_findings}"
    )
    print(
        f"  {result.summary.journey_findings} Journey-backed outcome(s), "
        f"{len(result.journey_map_entries)} journey map entr(ies)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
