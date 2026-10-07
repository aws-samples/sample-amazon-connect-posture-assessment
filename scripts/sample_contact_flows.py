"""Synthetic Amazon Connect contact flows for the checked-in sample report.

These are real contact-flow JSON documents in the ``2019-10-30`` schema, not
mock objects. ``generate_sample_report.py`` feeds them through the production
parser, super-graph builder, path enumerator and scorer, so the sample report's
Caller Journey Map and ``journey-*`` findings are produced by exactly the code
path a real run uses. If a change to that pipeline alters what it reports, the
sample diff shows it.

The flows are written to exercise the findings the journey pipeline can emit:

* ``main-ivr`` reaches a queue through the Agentic CX escalation/fallback routes
  with no authentication step on those paths (``journey-sec-001``), and has an
  attribute-tagging branch with no outgoing transition (``journey-res-001``).
* ``billing-support`` authenticates before its queue transfer, so that path is
  correctly *not* flagged — the sample shows both outcomes side by side.
* ``overflow-routing`` routes straight to a queue with no self-service action of
  any kind (``journey-cost-001``).
* Six unreferenced flows on the primary instance are classified dormant
  (``journey-scope-001``, which triggers above five).
"""

from __future__ import annotations

from typing import Any, Dict, List

# Flow identifiers are referenced by ContactFlowId in the transfer actions
# below, so the super-graph can statically resolve the cross-flow edges.
MAIN_IVR_ID = "aaaaaaaa-0000-4000-8000-000000000001"
BILLING_ID = "aaaaaaaa-0000-4000-8000-000000000002"
OVERFLOW_ID = "bbbbbbbb-0000-4000-8000-000000000001"

MAIN_IVR_FLOW: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "welcome",
    "Actions": [
        {
            "Identifier": "welcome",
            "Type": "MessageParticipant",
            "Parameters": {"Text": "Thank you for calling Example Corp."},
            "Transitions": {
                "NextAction": "main-menu",
                "Errors": [{"NextAction": "main-menu", "ErrorType": "NoMatchingError"}],
            },
        },
        {
            "Identifier": "main-menu",
            "Type": "GetParticipantInput",
            "Parameters": {
                "Text": "For billing, press 1. For technical support, press 2.",
                "InputTimeLimitSeconds": "5",
            },
            "Transitions": {
                "Conditions": [
                    {
                        "NextAction": "to-billing",
                        "Condition": {"Operator": "Equals", "Operands": ["1"]},
                    },
                    {
                        "NextAction": "tech-bot",
                        "Condition": {"Operator": "Equals", "Operands": ["2"]},
                    },
                ],
                "Errors": [
                    {"NextAction": "tag-abandoned", "ErrorType": "NoMatchingCondition"},
                    {"NextAction": "tag-abandoned", "ErrorType": "InputTimeLimitExceeded"},
                ],
            },
        },
        {
            "Identifier": "to-billing",
            "Type": "TransferToFlow",
            "Parameters": {"ContactFlowId": BILLING_ID},
            "Transitions": {},
        },
        {
            "Identifier": "tech-bot",
            "Type": "ConnectParticipantWithAgenticCX",
            "Parameters": {
                "AgentConfiguration": {
                    "WorkspaceId": "workspace-example-001",
                    "ApplicationId": "application-example-001",
                    "Alias": "technical-support",
                },
                "ContextVariables": {
                    "accountToken": "ACXD_CONTEXT_VALUE_MARKER_DO_NOT_RENDER",
                    "customerTier": "synthetic-gold",
                },
                "SpeechRecognitionConfiguration": {"LanguageCode": "en-US"},
                "AudioFillerConfiguration": {"Enabled": True},
            },
            "Transitions": {
                "NextAction": "bot-resolved",
                "Conditions": [
                    {
                        "NextAction": "tech-queue",
                        "Condition": {"Operator": "Equals", "Operands": ["Escalation"]},
                    },
                ],
                "Errors": [
                    {"NextAction": "tech-queue", "ErrorType": "InputTimeLimitExceeded"},
                    {"NextAction": "tech-queue", "ErrorType": "NoMatchingCondition"},
                    {"NextAction": "tech-queue", "ErrorType": "NoMatchingError"},
                ],
            },
        },
        {
            "Identifier": "bot-resolved",
            "Type": "DisconnectParticipant",
            "Parameters": {},
            "Transitions": {},
        },
        {
            "Identifier": "tech-queue",
            "Type": "TransferContactToQueue",
            "Parameters": {"QueueId": "Technical Support"},
            "Transitions": {},
        },
        {
            # No outgoing transition: the caller who makes no selection is
            # tagged and then nothing happens. This is the dead end
            # journey-res-001 exists to surface.
            "Identifier": "tag-abandoned",
            "Type": "UpdateContactAttributes",
            "Parameters": {"Attributes": {"ivr_outcome": "no_selection"}},
            "Transitions": {},
        },
    ],
}

BILLING_FLOW: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "collect-account",
    "Actions": [
        {
            "Identifier": "collect-account",
            "Type": "GetParticipantInput",
            "Parameters": {
                "Text": "Please enter your account number, followed by the pound key.",
                "InputTimeLimitSeconds": "10",
            },
            "Transitions": {
                "NextAction": "profile-lookup",
                "Errors": [{"NextAction": "billing-queue", "ErrorType": "NoMatchingError"}],
            },
        },
        {
            "Identifier": "profile-lookup",
            "Type": "InvokeLambdaFunction",
            "Parameters": {
                "FunctionArn": (
                    "arn:aws:lambda:us-east-1:111122223333:function:example-customer-lookup"
                ),
                "TimeLimit": "3",
            },
            "Transitions": {
                "NextAction": "billing-queue",
                "Errors": [{"NextAction": "billing-queue", "ErrorType": "NoMatchingError"}],
            },
        },
        {
            "Identifier": "billing-queue",
            "Type": "TransferContactToQueue",
            "Parameters": {"QueueId": "Billing"},
            "Transitions": {},
        },
    ],
}

OVERFLOW_FLOW: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "set-queue",
    "Actions": [
        {
            "Identifier": "set-queue",
            "Type": "UpdateContactTargetQueue",
            "Parameters": {"QueueId": "Overflow"},
            "Transitions": {
                "NextAction": "overflow-queue",
                "Errors": [{"NextAction": "overflow-queue", "ErrorType": "NoMatchingError"}],
            },
        },
        {
            "Identifier": "overflow-queue",
            "Type": "TransferContactToQueue",
            "Parameters": {"QueueId": "Overflow"},
            "Transitions": {},
        },
    ],
}

# Flows with no phone number association and no inbound traffic. Named the way
# real instances accumulate them — templates, whisper flows, and abandoned
# experiments nobody deleted.
DORMANT_FLOW_NAMES = [
    "After Hours Message",
    "Agent Whisper",
    "Customer Hold",
    "Outbound Whisper",
    "Legacy Satisfaction Survey",
    "Temp - Holiday Closure 2025",
]


def _dormant_flow(name: str) -> Dict[str, Any]:
    """A minimal two-action flow, enough to parse but never entered."""
    return {
        "Version": "2019-10-30",
        "StartAction": "announce",
        "Actions": [
            {
                "Identifier": "announce",
                "Type": "MessageParticipant",
                "Parameters": {"Text": name},
                "Transitions": {"NextAction": "end"},
            },
            {
                "Identifier": "end",
                "Type": "DisconnectParticipant",
                "Parameters": {},
                "Transitions": {},
            },
        ],
    }


def dormant_flow_specs(instance_index: int) -> List[Dict[str, Any]]:
    """Return ``{id, name, type, content}`` specs for the dormant flows."""
    return [
        {
            "id": f"cccccccc-{instance_index:04d}-4000-8000-{index:012d}",
            "name": name,
            "type": "CONTACT_FLOW",
            "content": _dormant_flow(name),
        }
        for index, name in enumerate(DORMANT_FLOW_NAMES)
    ]
