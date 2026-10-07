"""
Contact-flow security checks (Phase 2 / Task 5).

These checks parse contact flow JSON content (via the parser package) and
detect security vulnerabilities in the flow logic:

- sec-prompt-inject-001       : dynamic prompt content requiring source/escaping review
- sec-lambda-validation-001   : Lambda response used for branching without validation
- sec-toll-fraud-001          : External transfer to dynamic phone number (toll fraud)
- sec-sensitive-data-001      : Sensitive data stored in contact attributes
- sec-pii-prompts-001         : PII read back in voice prompts without masking

Each check operates on a parsed ContactFlowGraph derived from the flow content.
"""

import re
from typing import Dict, List, Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FlowAction,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser, reachable_from_entry
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

# Patterns indicating sensitive data in attribute names (case-insensitive).
# These are DETECTION substrings for flagging PII/PCI/PHI stored in contact
# attributes — not recommended attribute names for customer use. A match should
# trigger a compliance review (HIPAA, PCI-DSS, or GDPR as applicable).
_SENSITIVE_ATTR_PATTERNS = (
    "ssn",
    "social",
    "creditcard",
    "cardnumber",
    "cvv",
    "pin",
    "password",
    "passcode",
    "dob",
    "dateofbirth",
    "accountnumber",
    "routingnumber",
    "bankaccount",
    "taxid",
    "passportnumber",
)

# Transfer-to-phone-number action type variants.
_PHONE_TRANSFER_TYPES = {
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
}


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    """Parse a ContactFlow's content into a graph; return None on failure."""
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _is_dynamic_reference(value) -> bool:
    """True if the value references a contact attribute or external source."""
    if not isinstance(value, str):
        return False
    return value.startswith("$.") or value.startswith("$[")


# Matches a JSONPath-style contact attribute reference embedded anywhere in
# free text, e.g. the "$.Attributes.Name" in "Hello, $.Attributes.Name.".
# Captures $.<segment>(.<segment>|[...])* — stops at whitespace or a
# JSONPath-illegal character so trailing punctuation in prose ("...Name.")
# isn't swallowed into the reference.
_DYNAMIC_REF_PATTERN = re.compile(r"\$(?:\.[A-Za-z0-9_]+|\[[^\]]*\])+")


# Amazon Connect system references are excluded from review candidates. Root
# matching must stop at a complete JSONPath segment so, for example,
# ``$.AgentControlled`` is not mistaken for ``$.Agent``.
_SYSTEM_ATTRIBUTE_ROOTS = (
    "$.awsregion",
    "$.systemendpoint",
    "$.queue",
    "$.agent",
    "$.contactid",
    "$.initialcontactid",
    "$.taskcontactid",
    "$.previouscontactid",
    "$.channel",
    "$.instancearn",
    "$.initiationmethod",
    "$.languagecode",
    "$.tags",
)

_CONSTRAINED_ATTRIBUTE_ROOTS = {
    "$.storedcustomerinput": "constrained_stored_customer_input",
    "$.customerendpoint.address": "constrained_customer_endpoint_address",
}


def _matches_reference_root(value: str, root: str) -> bool:
    """Match a JSONPath root at a complete path-segment boundary."""
    lowered = value.lower()
    return lowered == root or (
        lowered.startswith(root) and lowered[len(root) : len(root) + 1] in {".", "["}
    )


def _is_system_attribute_reference(value: str) -> bool:
    """Return whether a reference is rooted in a Connect system attribute."""
    return any(_matches_reference_root(value, root) for root in _SYSTEM_ATTRIBUTE_ROOTS)


def _classify_dynamic_reference(value: str) -> str:
    """Classify a reference without inferring unobserved data provenance."""
    if _is_system_attribute_reference(value):
        return "connect_system"
    for root, category in _CONSTRAINED_ATTRIBUTE_ROOTS.items():
        if _matches_reference_root(value, root):
            return category
    if _matches_reference_root(value, "$.external"):
        return "external_or_lambda_result"
    if _matches_reference_root(value, "$.lex"):
        return "lex"
    if _matches_reference_root(value, "$.media.initialmessage"):
        return "media_initial_message"
    if _matches_reference_root(value, "$.segmentattributes") or _matches_reference_root(
        value, "$.media.segmentattributes"
    ):
        return "segment_attributes"
    if _matches_reference_root(value, "$.media.sip"):
        return "sip_metadata"
    if _matches_reference_root(value, "$.customer"):
        return "customer"
    if _matches_reference_root(value, "$.attributes"):
        return "attributes_unknown"
    return "unknown"


def _is_reviewable_reference(category: str) -> bool:
    """Return whether a category needs source and escaping review."""
    return category != "connect_system" and not category.startswith("constrained_")


_OTHER_AUDIENCE_FLOW_TYPES = {
    "AGENT_WHISPER",
    "OUTBOUND_WHISPER",
    "AGENT_HOLD",
    "AGENT_TRANSFER",
}


def _prompt_text_and_markup(action: FlowAction) -> tuple[str, bool]:
    """Return prompt text and the flow's configured Text/SSML interpretation."""
    params = action.parameters or {}

    ssml_value = params.get("SSML")
    if ssml_value:
        return str(ssml_value), True

    text_value = str(params.get("Text", "") or "")
    discriminator = str(params.get("TextType") or params.get("InterpretAs") or "")
    return text_value, discriminator.strip().lower() == "ssml"


def _get_phone_destination(action: FlowAction) -> Optional[str]:
    """Extract the phone number destination from a transfer action."""
    params = action.parameters or {}
    return (
        params.get("PhoneNumber")
        or params.get("ContactFlowId")  # some older formats
        or params.get("Endpoint", {}).get("Address")
        if isinstance(params.get("Endpoint"), dict)
        else params.get("PhoneNumber")
    )


class DynamicPromptInjectionCheck(BaseCheck):
    """Find reachable prompts that need dynamic-content safety review."""

    _PROMPT_ACTION_TYPES = {"MessageParticipant", "PlayPrompt", "PlayAudio"}

    def __init__(self):
        super().__init__(
            check_id="sec-prompt-inject-001",
            name="Potential Unsafe Dynamic Content in Prompts",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Reviews reachable prompts that combine dynamic references with SSML or "
                "an agent/other-audience flow type. Results are review candidates, not "
                "confirmed injection findings."
            ),
        )

    @staticmethod
    def _evidence_row(flow: ContactFlow, action: FlowAction, text: str, is_ssml: bool) -> dict:
        dynamic_refs = _DYNAMIC_REF_PATTERN.findall(text)
        source_categories = [_classify_dynamic_reference(ref) for ref in dynamic_refs]
        other_audience = (flow.type or "").upper() in _OTHER_AUDIENCE_FLOW_TYPES
        return {
            "flow": flow.name,
            "flow_id": flow.id,
            "action_id": action.action_id,
            "action_type": action.action_type,
            "dynamic_refs": dynamic_refs,
            "source_categories": source_categories,
            "prompt_preview": text[:120],
            "interpreted_as": "ssml" if is_ssml else "text",
            "flow_type": flow.type,
            "reachable": True,
            "audience_basis": (
                "flow type is classified as agent/other audience"
                if other_audience
                else "flow type does not establish an agent/other audience"
            ),
            "sanitization_assessed": False,
        }

    @staticmethod
    def _analysis_note(unanalyzed_flows: list[dict]) -> str:
        if not unanalyzed_flows:
            return ""
        return (
            f" Analysis was incomplete for {len(unanalyzed_flows)} flow(s); "
            "see unanalyzed_flows in the evidence."
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        actionable_candidates = []
        informational_rows = []
        excluded_rows = []
        unanalyzed_flows = []
        flows_parsed = 0
        flows_analyzed = 0

        for flow in sorted(
            instance.contact_flows,
            key=lambda item: ((item.name or "").casefold(), item.id),
        ):
            if not flow.content or not isinstance(flow.content, dict):
                unanalyzed_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content unavailable"}
                )
                continue

            graph = _parse_flow(flow)
            if graph is None:
                unanalyzed_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content parse failed"}
                )
                continue

            flows_parsed += 1
            if not graph.actions:
                flows_analyzed += 1
                continue
            if graph.entry_point_id not in graph.actions:
                unanalyzed_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "reason": "entry action is missing or invalid",
                    }
                )
                continue

            flows_analyzed += 1
            reachable_action_ids = reachable_from_entry(graph)
            for action_id in sorted(reachable_action_ids):
                action = graph.actions[action_id]
                if action.action_type not in self._PROMPT_ACTION_TYPES:
                    continue

                text, is_ssml = _prompt_text_and_markup(action)
                row = self._evidence_row(flow, action, text, is_ssml)
                if not row["dynamic_refs"]:
                    continue

                reviewable_categories = [
                    category
                    for category in row["source_categories"]
                    if _is_reviewable_reference(category)
                ]
                if not reviewable_categories:
                    row["review_reason"] = "only Connect system or constrained references"
                    excluded_rows.append(row)
                    continue

                other_audience = (flow.type or "").upper() in _OTHER_AUDIENCE_FLOW_TYPES
                if is_ssml or other_audience:
                    row["review_reason"] = (
                        "reachable SSML prompt with a non-system, non-constrained reference"
                        if is_ssml
                        else "reachable plain-text prompt in an agent/other-audience flow type"
                    )
                    row["severity"] = Severity.MEDIUM.value
                    actionable_candidates.append(row)
                else:
                    row["review_reason"] = (
                        "reachable plain-text prompt outside agent/other-audience flow types"
                    )
                    informational_rows.append(row)

        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "flows_parsed": flows_parsed,
            "flows_analyzed": flows_analyzed,
            "flows_unanalyzed": len(unanalyzed_flows),
            "unanalyzed_flows": unanalyzed_flows,
            "analysis_complete": not unanalyzed_flows,
            "actionable_review_candidates": actionable_candidates,
            # Compatibility alias. These rows are review candidates, not confirmed injection.
            "flagged_prompts": actionable_candidates,
            "informational_dynamic_references": informational_rows,
            "informational_prompts_spoken_to_source": informational_rows,
            "excluded_reference_prompts": excluded_rows,
            "system_attribute_prompts_excluded": sum(
                all(category == "connect_system" for category in row["source_categories"])
                for row in excluded_rows
            ),
            "constrained_reference_prompts_excluded": sum(
                any(category.startswith("constrained_") for category in row["source_categories"])
                for row in excluded_rows
            ),
        }
        analysis_note = self._analysis_note(unanalyzed_flows)

        if actionable_candidates:
            target_action_ids = list(
                dict.fromkeys(row["action_id"] for row in actionable_candidates)
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(actionable_candidates)} reachable prompt(s) need review for "
                    f"dynamic-content safety.**{analysis_note}\n\n"
                    "A security issue requires all of these conditions: the referenced source "
                    "allows arbitrary text, the value reaches the prompt without the required "
                    "escaping, and the prompt reaches another person or an invalid value follows "
                    "an unsafe Error branch. Trusted IVR or agent instructions could then be "
                    "manipulated. Invalid SSML could instead break the prompt and follow its Error "
                    "branch.\n\n"
                    "This check does not prove the value's source, sanitization, Amazon Connect "
                    "escaping behavior, or exploitation. `$.Attributes` remains unknown unless its "
                    "writer is traced, and this check does not perform that trace. This finding is "
                    "not evidence of code execution or account takeover. If sandbox testing shows "
                    "that Connect inserts a value into SSML without XML escaping, a valid tag such "
                    'as `<break time="10s"/>` is one conditional test example; runtime behavior '
                    "still needs validation.\n\n"
                    "Review the candidates in the evidence and close any candidate whose source is "
                    "limited to DTMF, a fixed enum, a trusted constant, or a correctly escaped value."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Trace and constrain each dynamic value used by the listed prompts.",
                    target_resources=target_action_ids,
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Trace where each reference is set and document its allowed "
                                "characters and maximum length. Close candidates that are limited "
                                "to DTMF, a fixed enum, a trusted constant, or an escaped value."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction="Switch SSML prompts to Text when markup is not required.",
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "When SSML is required, XML-escape &, <, and > and enforce the "
                                "expected character set and length before the prompt uses the value."
                            ),
                        ),
                        RemediationStep(
                            order=4,
                            instruction=(
                                "Review the prompt's Error branch and make sure synthesis failures "
                                "take a safe path."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Amazon Polly SSML reference",
                            url="https://docs.aws.amazon.com/polly/latest/dg/supportedtags.html",
                        ),
                        RemediationReference(
                            title="Using contact attributes in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-attrib-list.html",  # noqa: E501
                        ),
                    ],
                    applies_if=(
                        "source tracing and runtime validation show arbitrary, unescaped text can "
                        "reach the prompt and create a security-relevant audience or error path."
                    ),
                ),
            )

        if unanalyzed_flows:
            if flows_analyzed == 0:
                reason = (
                    "No input contact flow could be parsed."
                    if flows_parsed == 0
                    else "No parsed contact flow had actions reachable from a valid entry point."
                )
            else:
                reason = "The analysis could not inspect every input contact flow."
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{reason} The check did not scan every action as a fallback. "
                    "See unanalyzed_flows in the evidence."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                "No reachable prompt met the review threshold. Plain-text dynamic references in "
                "flow types that do not establish an agent/other audience are listed separately "
                f"as informational evidence.{analysis_note} This result does not determine who "
                "set or received a value, whether values were sanitized, or how Connect escapes "
                "dynamic substitutions."
            ),
            evidence=evidence,
        )


class LambdaResponseValidationCheck(BaseCheck):
    """Review Lambda conditional branches for a default fallback edge."""

    def __init__(self):
        super().__init__(
            check_id="sec-lambda-validation-001",
            name="Lambda Branch Default Fallback Review",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Identifies Lambda actions with conditional branches but no "
                "parser-visible default fallback edge."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type != "InvokeLambdaFunction":
                    continue
                # Check if action's transitions include conditions (branching
                # on the return). If conditions exist but no default/error path,
                # it's unvalidated branching.
                cond_targets = [t for t in action.transitions if t.transition_type == "condition"]
                has_default = any(t.transition_type == "default" for t in action.transitions)
                if cond_targets and not has_default:
                    flagged.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "lambda_arn": action.parameters.get("FunctionArn", "unknown"),
                        }
                    )

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(flagged)} Lambda invocation(s) branch on return "
                    "values without a default fallback path."
                ),
                evidence={"flagged_lambdas": flagged},
                structured_remediation=Remediation(
                    summary="Add default/fallback branches after Lambda invocations.",
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged Lambda action, add a 'Default' "
                                "transition that handles unexpected return values "
                                "safely (e.g., route to an error prompt or retry)."
                            ),
                        ),
                    ],
                    applies_if="Lambda functions may return unexpected data.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="Lambda branching includes default paths.",
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


class ExternalTransferTollFraudCheck(BaseCheck):
    """Detect dynamic phone-number transfers (toll fraud risk, Req 22)."""

    def __init__(self):
        super().__init__(
            check_id="sec-toll-fraud-001",
            name="External Transfer Toll Fraud Risk",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            description=(
                "Detects contact flows that transfer calls to dynamically "
                "determined phone numbers without a validation step, "
                "exposing the instance to toll fraud."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []
        static_count = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in _PHONE_TRANSFER_TYPES:
                    continue
                dest = _get_phone_destination(action)
                if dest and _is_dynamic_reference(dest):
                    flagged.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "dynamic_source": dest,
                        }
                    )
                else:
                    static_count += 1

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(flagged)} external transfer(s) use a dynamic phone "
                    "number without validation — toll fraud risk."
                ),
                evidence={
                    "dynamic_transfers": flagged,
                    "static_transfers": static_count,
                },
                structured_remediation=Remediation(
                    summary="Constrain dynamic transfer destinations to an allowlist.",
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Add a Check Attribute or Lambda validation "
                                "action before the transfer that confirms the "
                                "destination number is on a pre-approved list."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Alternatively, replace the dynamic reference "
                                "with a static, hardcoded number for each "
                                "known destination."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Transfer contacts to a phone number",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/transfer-to-phone-number.html",  # noqa: E501
                        )
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(f"All {static_count} external transfer(s) use static phone numbers."),
            evidence={"static_transfers": static_count},
        )


class SensitiveDataInAttributesCheck(BaseCheck):
    """Detect sensitive data stored in contact attributes (Req 23)."""

    def __init__(self):
        super().__init__(
            check_id="sec-sensitive-data-001",
            name="Sensitive Data in Contact Attributes",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects contact flows that store potentially sensitive data "
                "(PII, credentials) in contact attributes, which are visible "
                "in CTRs, logs, and reporting."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in (
                    "UpdateContactAttributes",
                    "SetContactAttributes",
                ):
                    continue
                attrs = action.parameters.get("Attributes", {})
                if isinstance(attrs, dict):
                    for key in attrs:
                        if any(p in key.lower() for p in _SENSITIVE_ATTR_PATTERNS):
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "action_id": action.action_id,
                                    "attribute_name": key,
                                }
                            )

        if flagged:
            # Group flagged items by flow so the reader can jump to each
            # flow once rather than scanning a de-duplicated action list.
            by_flow: Dict[str, List[Dict[str, str]]] = {}
            for f in flagged:
                by_flow.setdefault(f["flow"], []).append(f)

            flow_lines = []
            for flow_name, entries in list(by_flow.items())[:5]:
                attr_names = ", ".join(sorted({f"`{e['attribute_name']}`" for e in entries}))
                flow_lines.append(f"* `{flow_name}` — sets: {attr_names}")
            more_note = (
                f"\n\n_+ {len(by_flow) - 5} more flow(s) with flagged attributes; see JSON export._"
                if len(by_flow) > 5
                else ""
            )

            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} `Set contact attributes` action(s) in "
                    f"{len(by_flow)} flow(s) store data under names that "
                    "look like PII or credentials.**\n\n"
                    "The attribute name is the giveaway — this check "
                    "watches for keys like `ssn`, `dob`, `creditcard`, "
                    "`cvv`, `pin`, `password`, `accountnumber`, "
                    "`bankaccount`, `taxid`, `passportnumber` (full list in "
                    "the source). If a Connect flow writes those names into "
                    "contact attributes, the values end up in three places "
                    "you probably don't want them:\n\n"
                    "1. **Contact Trace Records (CTRs)** — attributes are "
                    "part of the CTR JSON exported to your Kinesis or S3 "
                    "stream after every contact. Anyone with read on that "
                    "bucket sees the raw value.\n"
                    "2. **Agent workspace** — supervisors and agents with "
                    "'View contact record' permission can see attributes "
                    "on a completed contact.\n"
                    "3. **Flow logs / CloudWatch** — if flow logging is "
                    "enabled, every attribute change writes a log line "
                    "containing the value.\n\n"
                    "**What the check flagged:**\n\n"
                    f"{chr(10).join(flow_lines)}{more_note}\n\n"
                    "**Fix (per attribute):** keep the *reference*, drop "
                    "the *value*. In the flow, replace:\n\n"
                    "```\n"
                    "Set contact attribute:  ssn        = <raw 9-digit value>\n"
                    "```\n\n"
                    "with:\n\n"
                    "```\n"
                    "Set contact attribute:  ssn_last4  = <last 4 digits only>       # safe to voice/log\n"
                    "Set contact attribute:  customer_token = <Lambda-returned UUID>  # opaque handle\n"
                    "```\n\n"
                    "Store the full value in Amazon Connect Customer "
                    "Profiles (encrypted at rest, access-scoped) and "
                    "resolve it via Lambda only when a specific step needs "
                    "the full number. The attribute in the flow then "
                    "carries only the token — logs and CTRs stay clean."
                ),
                evidence={"flagged_attributes": flagged},
                structured_remediation=Remediation(
                    summary=(
                        "Replace raw-PII contact attributes with tokenized "
                        "references; resolve the full value via Lambda "
                        "only when a step needs it."
                    ),
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged attribute, decide the "
                                "smallest form the flow actually needs: "
                                "last-4 digits for confirmation prompts, "
                                "an opaque token for downstream Lambdas, "
                                "or nothing at all if the value was "
                                "written but never read."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Move the full value into Amazon Connect "
                                "Customer Profiles (or your own encrypted "
                                "store) keyed by a UUID. Update the flow "
                                "to store only the UUID as a contact "
                                "attribute; write a small Lambda that "
                                "returns the full value on demand for the "
                                "one or two blocks that need it."
                            ),
                            console_path=("Connect console -> Customer Profiles"),
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "If you can't avoid attributes at all, at "
                                "least enable Contact Lens sensitive-data "
                                "redaction so the values are scrubbed "
                                "before CTRs and recordings are exported."
                            ),
                            console_path=("Connect console -> Analytics -> Contact Lens settings"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Customer Profiles for Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/customer-profiles.html",  # noqa: E501
                        ),
                        RemediationReference(
                            title="Contact Lens sensitive data redaction",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/sensitive-data-redaction.html",  # noqa: E501
                        ),
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"None of the {len(instance.contact_flows)} flow(s) "
                "analyzed store data under attribute names that look like "
                "PII or credentials (ssn, dob, creditcard, cvv, pin, "
                "accountnumber, etc.). If PII passes through a flow at "
                "all, this pattern keeps it out of CTRs and flow logs — "
                "which is where accidental exposure usually happens."
            ),
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


class PIIInPromptsCheck(BaseCheck):
    """Detect PII read back in voice prompts without masking (Req 39)."""

    def __init__(self):
        super().__init__(
            check_id="sec-pii-prompts-001",
            name="PII Exposure in Voice Prompts",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects contact flows that read back sensitive customer data "
                "(account numbers, SSN, etc.) in voice prompts without masking."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in ("MessageParticipant", "PlayPrompt"):
                    continue
                raw_text = str(action.parameters.get("Text", ""))
                text = raw_text.lower()
                for pattern in _SENSITIVE_ATTR_PATTERNS:
                    if pattern in text:
                        # Check if masking is applied (heuristic: "last4",
                        # "ending in", "substring" in same text).
                        has_mask = any(
                            m in text
                            for m in (
                                "last4",
                                "lastfour",
                                "ending in",
                                "substring",
                                "mask",
                                "redact",
                            )
                        )
                        if not has_mask:
                            # Preserve a truncated copy of the raw prompt
                            # text so the finding can show the reader
                            # what actually got flagged.
                            excerpt = raw_text.replace("\n", " ").strip()
                            if len(excerpt) > 140:
                                excerpt = excerpt[:137] + "\u2026"
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "action_id": action.action_id,
                                    "attribute_pattern": pattern,
                                    "prompt_text": excerpt,
                                }
                            )
                        break  # one flag per action is enough

        if flagged:
            worst_lines = []
            for f in flagged[:3]:
                worst_lines.append(
                    f"* `{f['flow']}` \u2192 matches `{f['attribute_pattern']}` "
                    f"in prompt: \u201c{f['prompt_text']}\u201d"
                )
            more_note = (
                f"\n\n_+ {len(flagged) - 3} more prompt(s); see JSON export._"
                if len(flagged) > 3
                else ""
            )

            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} voice prompt(s) speak a piece of "
                    "sensitive data back to the caller without masking "
                    "it.**\n\n"
                    "The check reads the `Text` parameter of every "
                    "`Play prompt` / `Message participant` action, looks "
                    "for references to values that sound like PII "
                    "(`ssn`, `dob`, `creditcard`, `accountnumber`, "
                    "`taxid`, `passportnumber`, and similar), and checks "
                    "whether the prompt also contains a masking hint "
                    "nearby (`last4`, `ending in`, `substring`, `mask`, "
                    "`redact`). If the sensitive reference is present but "
                    "no masking hint is, the prompt gets flagged.\n\n"
                    "**Unmasked vs masked, side by side:**\n\n"
                    "```\n"
                    '\u274c  Play prompt: "Your account number is $.Attributes.AccountNumber."\n'
                    "         \u2514\u2500 caller hears all 12 digits, anyone nearby hears them too.\n"
                    "\n"
                    '\u2705  Play prompt: "Your account ending in $.Attributes.AccountNumberLast4."\n'
                    "         \u2514\u2500 last 4 digits only, enough for the caller to recognize.\n"
                    "```\n\n"
                    "**Why this matters.** Callers phone from open "
                    "offices, cars, and public spaces. Whatever the "
                    "prompt says gets heard by anyone in earshot AND is "
                    "captured verbatim in the call recording. Recordings "
                    "sit in S3 for weeks or years. If a support team, "
                    "auditor, or breached recording bucket touches the "
                    "recordings later, the PII is right there in the "
                    "audio.\n\n"
                    "**What the check flagged:**\n\n"
                    f"{chr(10).join(worst_lines)}{more_note}\n\n"
                    "**Fix (per prompt):** replace the full attribute "
                    "reference with a `*Last4` variant, or a "
                    "confirmation pattern that doesn't voice the value "
                    "at all (\u201cThe account ending in 4 3 2 1, is that "
                    "correct?\u201d). Compute the last-4 attribute with a "
                    "small `Set contact attributes` block upstream of "
                    "the prompt. Additionally, turn on **Contact Lens "
                    "sensitive-data redaction** so if a caller says the "
                    "full number back, it's redacted from the recording "
                    "and transcript."
                ),
                evidence={"flagged_prompts": flagged},
                structured_remediation=Remediation(
                    summary=(
                        "Voice only the last 4 digits (or a tokenized "
                        "reference) instead of the full value, and turn "
                        "on Contact Lens redaction as a safety net."
                    ),
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged prompt, compute a "
                                "last-4 attribute upstream (Set contact "
                                "attributes \u2192 "
                                "`AccountNumberLast4 = $.Attributes.AccountNumber` "
                                "with a substring transform), then edit "
                                "the prompt to reference the last-4 "
                                "attribute instead of the full one."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Enable Contact Lens sensitive-data "
                                "redaction on the instance. This scrubs "
                                "numeric PII patterns (account numbers, "
                                "SSNs, credit cards) from call "
                                "recordings and transcripts before they "
                                "land in S3."
                            ),
                            console_path=("Connect console -> Analytics -> Contact Lens settings"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Contact Lens sensitive data redaction",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/sensitive-data-redaction.html",  # noqa: E501
                        )
                    ],
                    applies_if=("prompts include values that identify or authenticate a customer."),
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"None of the {len(instance.contact_flows)} flow(s) "
                "analyzed voice sensitive attributes (ssn, dob, "
                "creditcard, accountnumber, etc.) to callers without a "
                "masking hint nearby (`last4`, `ending in`, `substring`, "
                "`mask`, `redact`). This is the pattern that keeps PII "
                "out of call recordings and stops passers-by in the "
                "caller's environment from overhearing account numbers."
            ),
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


def register_contact_flow_security_checks(registry) -> None:
    """Register all contact-flow security checks."""
    registry.register_check(DynamicPromptInjectionCheck())
    registry.register_check(LambdaResponseValidationCheck())
    registry.register_check(ExternalTransferTollFraudCheck())
    registry.register_check(SensitiveDataInAttributesCheck())
    registry.register_check(PIIInPromptsCheck())
