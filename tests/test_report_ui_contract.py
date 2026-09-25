"""
Contract between ReportGenerator._build_report_data() and the Cloudscape report UI.

``frontend/test/fixtures/report-data.json`` is generated from the real Python
output for a representative assessment. This test fails when the generator's
output shape drifts from the committed fixture; the Node tests
(``frontend/test/report.test.mjs``) check that same fixture against the fields
the UI reads (``frontend/src/contract.js``). Together they catch a key renamed
or dropped on either side.

Regenerate after an intentional data-contract change:

    UPDATE_REPORT_FIXTURE=1 pytest tests/test_report_ui_contract.py
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from amazon_connect_assessment.journey.renderer import flow_to_diagram_artifacts
from amazon_connect_assessment.models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from amazon_connect_assessment.parsers import ContactFlowParser
from amazon_connect_assessment.report_generator import ReportGenerator

FIXTURE = (
    Path(__file__).resolve().parents[1] / "frontend" / "test" / "fixtures" / "report-data.json"
)


def _flow_entry(instance: ConnectInstance) -> dict:
    content = {
        "Version": "2019-10-30",
        "StartAction": "greet",
        "Actions": [
            {
                "Identifier": "greet",
                "Type": "MessageParticipant",
                "Parameters": {"Text": "Welcome"},
                "Transitions": {"NextAction": "menu"},
            },
            {
                "Identifier": "menu",
                "Type": "GetParticipantInput",
                "Parameters": {"Text": "Press 1 for sales"},
                "Transitions": {
                    "NextAction": "end",
                    "Conditions": [
                        {
                            "NextAction": "queue",
                            "Condition": {"Operator": "Equals", "Operands": ["1"]},
                        }
                    ],
                    "Errors": [{"NextAction": "end", "ErrorType": "InputTimeLimitExceeded"}],
                },
            },
            {
                "Identifier": "queue",
                "Type": "TransferContactToQueue",
                "Parameters": {},
                "Transitions": {"Errors": [{"NextAction": "end", "ErrorType": "QueueAtCapacity"}]},
            },
            {
                "Identifier": "end",
                "Type": "DisconnectParticipant",
                "Parameters": {},
                "Transitions": {},
            },
        ],
    }
    graph = ContactFlowParser().parse(content)
    graph.flow_id, graph.flow_name = "flow-main", "Main IVR"
    artifacts = flow_to_diagram_artifacts(graph)
    return {
        "instance_id": instance.instance_id,
        "instance_display_name": instance.display_name,
        "phone_number": "+18005550100",
        "phone_type": "TOLL_FREE",
        "phone_country_code": "US",
        "phone_description": "Main line",
        "flow_id": "flow-main",
        "flow_name": "Main IVR",
        "flow_type": "CONTACT_FLOW",
        "diagram_html": artifacts.diagram_html,
        "diagram_model": artifacts.diagram_model,
        "exports": artifacts.export_payload(),
    }


def _assessment() -> AssessmentResult:
    when = datetime(2026, 1, 15, 10, 0, 0)
    instance = ConnectInstance(
        instance_id="i-0001",
        instance_arn="arn:aws:connect:us-east-1:111122223333:instance/i-0001",
        identity_management_type="SAML",
        inbound_calls_enabled=True,
        outbound_calls_enabled=False,
        instance_alias="contact-center",
        status="ACTIVE",
    )
    findings = [
        Finding(
            check_id="SEC-001",
            check_name="Recordings use a customer-managed key",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Recordings use **SSE-S3**.",
            remediation="Use a KMS key.",
            evidence={
                "compliant": False,
                "buckets": [{"name": "recordings", "arn": "arn:aws:s3:::recordings"}],
                "limits": {"checked": 3},
                "queues": ["general"],
            },
            timestamp=when,
            structured_remediation=Remediation(
                summary="Use a customer-managed key",
                steps=[RemediationStep(1, "Create a key", command="aws kms create-key")],
                target_resources=["recordings"],
                references=[RemediationReference("Docs", "https://docs.aws.amazon.com/")],
                applies_if="Recordings are enabled",
            ),
        ),
        Finding(
            check_id="RES-001",
            check_name="Queues have overflow",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="All queues overflow.",
            remediation="None needed.",
            evidence={},
            timestamp=when,
        ),
    ]
    result = AssessmentResult(
        assessment_id="contract-fixture",
        timestamp=when,
        account_id="111122223333",
        region="us-east-1",
        instances=[instance],
        findings=findings,
        summary=AssessmentSummary(2, 1, 1, 0, 0, 1, 0, 0, 0),
        metadata=AssessmentMetadata("1.0.0", 12.5, "111122223333", "us-east-1", "CI", "3.12"),
        execution_errors=["Throttled calling ListQueues"],
    )
    result.journey_map_entries = [_flow_entry(instance)]
    return result


def _report_data() -> dict:
    data = ReportGenerator()._build_report_data(_assessment(), include_raw_data=False)
    data["generated_at"] = "2026-01-15 10:05:00 UTC"  # the only non-deterministic value
    return json.loads(json.dumps(data, default=str))


def _shape(value: Any) -> Any:
    """Structure only: dict keys, list element shapes, and scalar type names."""
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return type(value).__name__


def test_report_ui_fixture_matches_generator_output():
    data = _report_data()
    if os.environ.get("UPDATE_REPORT_FIXTURE"):
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    committed = json.loads(FIXTURE.read_text(encoding="utf-8"))

    assert _shape(data) == _shape(committed), (
        "ReportGenerator._build_report_data() output no longer matches "
        "frontend/test/fixtures/report-data.json. If the change is intentional, "
        "update frontend/src/contract.js and regenerate the fixture with "
        "UPDATE_REPORT_FIXTURE=1 pytest tests/test_report_ui_contract.py"
    )


def test_report_ui_fixture_exercises_optional_sections():
    # The fixture must keep covering the branches the UI renders conditionally.
    committed = json.loads(FIXTURE.read_text(encoding="utf-8"))
    failed = next(f for f in committed["findings"] if f["status"] == "fail")

    assert failed["structured_remediation"]["steps"]
    assert failed["evidence"]["tables"] and failed["evidence"]["sections"]
    assert committed["journey"]["entries"][0]["diagram_model"]["layout"]["connectors"]
    assert committed["execution_errors"]
    assert committed["filters"] == {"default_severity": "critical", "default_status": "fail"}
