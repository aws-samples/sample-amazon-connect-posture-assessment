"""
Blast-radius security checks for Lambda functions reachable from contact flows.

- sec-excessive-agency-001 : Lambda execution role overly broad (OWASP LLM06)

The check combines flow-content analysis (parser) with AWS API inspection
(Lambda configurations and IAM inline and attached managed identity policies),
and degrades to SKIPPED when a required source cannot be read unless an inspected
source already proves a selected high-risk action.

Three checks were removed from this module rather than left in place:

``sec-ai-lambda-001`` took the same input as ``sec-excessive-agency-001`` (Lambda
ARNs harvested from flow content), concerned the same subject (execution-role
privilege), and recommended the same fix (scope the role down) — but it
name-matched the ARN and asked the reader to go review the role, where
``ExcessiveAgencyCheck`` below resolves the role and reads its inline and attached
managed identity-policy documents. A weaker duplicate of a check that already
measures the bounded condition.

``sec-ai-lex-001`` failed every Lex integration it found, unconditionally. It
could not read a bot's configuration, so a deployment with correctly guarded
bots received the same HIGH finding as one with none. Reimplementing it means
reading intent and slot configuration (``lex:ListIntents``, ``DescribeIntent``,
``ListSlots``, ``DescribeSlot``), which the assessment policy does not currently
grant.

``sec-ai-cascade-001`` asked a sound question — whether one model's output feeds
another's input with nothing validating in between — but identified AI stages by
substring-matching the Lambda ARN against hints including ``"ai"`` and ``"ml"``,
which match unrelated names such as ``ClaimLookup`` or ``EmailHandler`` while
missing any AI Lambda whose name does not advertise itself. Reimplementing it
means deriving AI involvement from the execution role's granted actions, the way
``ExcessiveAgencyCheck`` below already resolves roles.

All three are absent rather than approximated: a check that only duplicates one
already measuring the condition, or that cannot distinguish a healthy
configuration from a broken one, does not belong in a report someone makes
decisions from.
"""

import json
from typing import Any, Optional
from urllib.parse import unquote

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser
from .base import BaseCheck, CheckContext, _error_code

_PARSER = ContactFlowParser()

_SENSITIVE_SERVICE_PREFIXES = (
    "iam:",
    "kms:decrypt",
    "s3:put",
    "s3:delete",
    "dynamodb:delete",
    "sqs:send",
    "sns:publish",
    "secretsmanager:",
    "organizations:",
)

# Services whose service-level wildcards (``svc:*``) grant the sensitive actions above.
_SENSITIVE_WILDCARD_SERVICES = frozenset(
    {"s3", "kms", "sqs", "sns", "dynamodb", "secretsmanager", "iam", "organizations"}
)
_READ_ONLY_ACTION_PREFIXES = ("get", "list", "describe")

_IDENTITY_POLICY_LIMITATIONS = [
    "Permission boundaries are not inspected.",
    "Service control policies (SCPs) are not inspected.",
    "Session policies are not inspected.",
    "Resource policies are not inspected.",
    "Role trust policies are not inspected.",
    "Function code behavior and business necessity are not inspected.",
    "Resource and condition combinations are not evaluated as effective permissions.",
    "NotAction statements are not evaluated by the selected high-risk Action scan.",
]


def _normalize_policy_document(document: object) -> dict[str, Any]:
    """Return an IAM policy document whether the API returned JSON or URL encoding."""
    if isinstance(document, dict):
        return document
    if not isinstance(document, str):
        raise ValueError("IAM policy document is not an object or encoded JSON string")
    decoded = unquote(document)
    parsed = json.loads(decoded)
    if not isinstance(parsed, dict):
        raise ValueError("IAM policy document JSON is not an object")
    return parsed


def _policy_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _risky_actions(document: dict[str, Any]) -> list[str]:
    risky: list[str] = []
    for statement in _policy_statements(document):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions if isinstance(actions, list) else []:
            if not isinstance(action, str):
                continue
            if _is_risky_action(action):
                risky.append(action)
    return risky


def _is_risky_action(action: str) -> bool:
    normalized = action.lower()
    if normalized in {"*", "*:*"}:
        return True
    service, _, name = normalized.partition(":")
    if service in _SENSITIVE_WILDCARD_SERVICES and name:
        if service == "iam" and name.startswith(_READ_ONLY_ACTION_PREFIXES):
            # Read-only IAM actions/wildcards (iam:Get*, iam:List*) are not excessive agency.
            return False
        if name == "*" or name.startswith("*"):
            return True
    return any(normalized.startswith(prefix) for prefix in _SENSITIVE_SERVICE_PREFIXES)


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _role_name_from_arn(arn: str) -> Optional[str]:
    if not arn or ":role/" not in arn:
        return None
    return arn.split(":role/", 1)[1].split("/")[-1]


class ExcessiveAgencyCheck(BaseCheck):
    """Inspect Lambda role identity policies for selected high-risk Allow actions."""

    def __init__(self):
        super().__init__(
            check_id="sec-excessive-agency-001",
            name="Excessive Agency / Lambda Identity-Policy Scope",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Inspects inline and attached managed identity-policy documents for "
                "Lambda execution roles referenced by contact flows and reports selected "
                "high-risk Allow actions."
            ),
        )

    @staticmethod
    def _list_all_inline_policy_names(factory: Any, role_name: str) -> list[str]:
        names: list[str] = []
        marker: Optional[str] = None
        while True:
            kwargs = {"Marker": marker} if marker else {}
            response = factory.list_role_policies_resilient(role_name, **kwargs)
            names.extend(response.get("PolicyNames", []) or [])
            if not response.get("IsTruncated"):
                return names
            marker = response.get("Marker")
            if not marker:
                raise ValueError("ListRolePolicies response is truncated without a Marker")

    @staticmethod
    def _list_all_attached_policies(factory: Any, role_name: str) -> list[dict[str, Any]]:
        policies: list[dict[str, Any]] = []
        marker: Optional[str] = None
        while True:
            kwargs = {"Marker": marker} if marker else {}
            response = factory.list_attached_role_policies_resilient(role_name, **kwargs)
            page = response.get("AttachedPolicies", []) or []
            policies.extend(policy for policy in page if isinstance(policy, dict))
            if not response.get("IsTruncated"):
                return policies
            marker = response.get("Marker")
            if not marker:
                raise ValueError("ListAttachedRolePolicies response is truncated without a Marker")

    @staticmethod
    def _source_failure(
        *,
        factory: Any,
        function_arn: str,
        role_name: Optional[str],
        source: str,
        operation: str,
        error: Exception,
        policy_name: Optional[str] = None,
        policy_arn: Optional[str] = None,
    ) -> dict[str, Any]:
        return {
            "function_arn": function_arn,
            "role_name": role_name,
            "policy_source": source,
            "policy_name": policy_name,
            "policy_arn": policy_arn,
            "operation": operation,
            "access_denied": factory.is_access_denied(error),
            "error_type": type(error).__name__,
            "error_code": _error_code(error),
        }

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        flagged: list[dict[str, Any]] = []
        evaluated: list[dict[str, Any]] = []
        source_failures: list[dict[str, Any]] = []

        lambda_arns = set()
        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type == "InvokeLambdaFunction":
                    arn = action.parameters.get("FunctionArn")
                    if arn:
                        lambda_arns.add(arn)

        base_evidence: dict[str, Any] = {
            "lambda_count": len(lambda_arns),
            "inspection_scope": (
                "Inline and attached managed identity-policy documents on Lambda "
                "execution roles referenced by parsed contact flows."
            ),
            "limitations": list(_IDENTITY_POLICY_LIMITATIONS),
        }
        if not lambda_arns:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description="No Lambda integrations were found in the parsed contact flows.",
                evidence=base_evidence,
            )

        for function_arn in sorted(lambda_arns):
            try:
                function_response = factory.get_lambda_function_resilient(function_arn)
                role_arn = function_response.get("Configuration", {}).get("Role", "")
                role_name = _role_name_from_arn(role_arn)
                if not role_name:
                    raise ValueError("Lambda configuration did not contain a valid IAM role ARN")
            except Exception as error:  # noqa: BLE001
                source_failures.append(
                    self._source_failure(
                        factory=factory,
                        function_arn=function_arn,
                        role_name=None,
                        source="lambda_configuration",
                        operation="lambda:GetFunction",
                        error=error,
                    )
                )
                continue

            try:
                inline_names = self._list_all_inline_policy_names(factory, role_name)
            except Exception as error:  # noqa: BLE001
                source_failures.append(
                    self._source_failure(
                        factory=factory,
                        function_arn=function_arn,
                        role_name=role_name,
                        source="inline",
                        operation="iam:ListRolePolicies",
                        error=error,
                    )
                )
                inline_names = []

            for policy_name in inline_names:
                try:
                    response = factory.get_role_policy_resilient(role_name, policy_name)
                    document = _normalize_policy_document(response.get("PolicyDocument"))
                    evaluated.append(
                        {
                            "function_arn": function_arn,
                            "role_name": role_name,
                            "policy_source": "inline",
                            "policy_name": policy_name,
                        }
                    )
                    for action in _risky_actions(document):
                        flagged.append(
                            {
                                "function_arn": function_arn,
                                "role_name": role_name,
                                "policy_source": "inline",
                                "policy_name": policy_name,
                                "excessive_action": action,
                            }
                        )
                except Exception as error:  # noqa: BLE001
                    source_failures.append(
                        self._source_failure(
                            factory=factory,
                            function_arn=function_arn,
                            role_name=role_name,
                            source="inline",
                            operation="iam:GetRolePolicy",
                            policy_name=policy_name,
                            error=error,
                        )
                    )

            try:
                attached_policies = self._list_all_attached_policies(factory, role_name)
            except Exception as error:  # noqa: BLE001
                source_failures.append(
                    self._source_failure(
                        factory=factory,
                        function_arn=function_arn,
                        role_name=role_name,
                        source="attached",
                        operation="iam:ListAttachedRolePolicies",
                        error=error,
                    )
                )
                attached_policies = []

            for attached in attached_policies:
                policy_name = attached.get("PolicyName")
                policy_arn = attached.get("PolicyArn")
                operation = "iam:ListAttachedRolePolicies"
                try:
                    if not policy_arn:
                        raise ValueError("Attached policy entry did not contain PolicyArn")
                    operation = "iam:GetPolicy"
                    policy = factory.get_policy_resilient(policy_arn).get("Policy", {})
                    version_id = policy.get("DefaultVersionId")
                    if not version_id:
                        raise ValueError("Managed policy did not contain DefaultVersionId")
                    operation = "iam:GetPolicyVersion"
                    version = factory.get_policy_version_resilient(policy_arn, version_id).get(
                        "PolicyVersion", {}
                    )
                    document = _normalize_policy_document(version.get("Document"))
                    evaluated.append(
                        {
                            "function_arn": function_arn,
                            "role_name": role_name,
                            "policy_source": "attached",
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "default_version_id": version_id,
                        }
                    )
                    for action in _risky_actions(document):
                        flagged.append(
                            {
                                "function_arn": function_arn,
                                "role_name": role_name,
                                "policy_source": "attached",
                                "policy_name": policy_name,
                                "policy_arn": policy_arn,
                                "default_version_id": version_id,
                                "excessive_action": action,
                            }
                        )
                except Exception as error:  # noqa: BLE001
                    source_failures.append(
                        self._source_failure(
                            factory=factory,
                            function_arn=function_arn,
                            role_name=role_name,
                            source="attached",
                            operation=operation,
                            policy_name=policy_name,
                            policy_arn=policy_arn,
                            error=error,
                        )
                    )

        evidence = {
            **base_evidence,
            "evaluated_identity_policies": evaluated,
            "inspection_complete": not source_failures,
            "policy_source_failures": source_failures,
        }

        if flagged:
            evidence["excessive_permissions"] = flagged
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    f"{len(flagged)} selected high-risk Allow action(s) were found in "
                    "Lambda role identity-policy documents referenced by contact flows."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Remove or constrain each flagged high-risk action after validating "
                        "the Lambda function's required access."
                    ),
                    target_resources=sorted({item["function_arn"] for item in flagged}),
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Review each flagged inline or attached managed policy and "
                                "scope actions, resources, and conditions to demonstrated "
                                "function requirements."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Separately review permission boundaries, SCPs, session and "
                                "resource policies, the trust policy, and function behavior."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="OWASP LLM06: Excessive Agency",
                            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",  # noqa: E501
                        )
                    ],
                    applies_if="Lambda functions handle untrusted contact-flow data.",
                ),
            )

        if source_failures:
            denied = any(item["access_denied"] for item in source_failures)
            reason = "Access was denied" if denied else "An API or policy-document read failed"
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    f"{reason} before all referenced Lambda role identity-policy documents "
                    "could be inspected, so a clean result cannot be reported."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="LambdaFunction",
            description=(
                f"Inspected {len(evaluated)} inline and attached managed identity-policy "
                "document(s) for referenced Lambda roles; no selected high-risk Allow "
                "actions were found."
            ),
            evidence=evidence,
        )


def register_ai_agent_security_checks(registry) -> None:
    """Register all AI/agentic security checks."""
    registry.register_check(ExcessiveAgencyCheck())
