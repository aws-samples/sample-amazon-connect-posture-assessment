"""
Deep-inspection security checks for Amazon Connect (Phase 2).

These checks go beyond presence/absence heuristics and inspect real AWS
configuration via read-only APIs:

- sec-iam-deep-001    : IAM service role policy least-privilege inspection
- sec-storage-001     : Instance storage encryption (customer-managed KMS)
- sec-origins-001     : Approved origins / CCP embedding allowlist
- sec-cloudtrail-001  : CloudTrail coverage of Connect API events
- sec-federation-001  : Identity federation / MFA posture
- sec-profile-audit-001 : Security profile permission audit

Every API-backed check degrades to SKIPPED on AccessDenied via the shared
helper, and every FAIL emits evidence-specific structured remediation.
"""

import json
from typing import Any, List, Optional
from urllib.parse import unquote

from ..models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

# Actions that are clearly outside the scope of a Connect service role and
# indicate excessive privilege if present.
_OUT_OF_SCOPE_ACTION_PREFIXES = (
    "iam:",
    "ec2:runinstances",
    "s3:deletebucket",
    "organizations:",
    "sts:assumerole",
)
_BROAD_WRITE_PREFIXES = (
    "delete",
    "put",
    "create",
    "write",
    "modify",
    "update",
    "attach",
    "detach",
    "start",
    "stop",
    "terminate",
    "send",
    "publish",
    "invoke",
)
_READ_ONLY_ACTION_PREFIXES = ("get", "list", "describe")


def _is_broad_write_action(action: str) -> bool:
    """True for ``*``/``svc:*`` and write-verb actions; read-only wildcards are excluded."""
    normalized = action.lower()
    if normalized in {"*", "*:*"}:
        return True
    _, _, name = normalized.rpartition(":")
    if not name:
        return False
    if name == "*":
        return True
    if name.startswith(_READ_ONLY_ACTION_PREFIXES):
        return False
    if name.startswith(_BROAD_WRITE_PREFIXES):
        return True
    # Leading-wildcard patterns such as ``*Object`` or ``*Policy`` may match writes.
    return name.startswith("*")


def _error_code(error: BaseException) -> Optional[str]:
    """AWS error code for a botocore ClientError, else None (never the message)."""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
        if isinstance(code, str):
            return code
    return None


_MAX_IAM_POLICY_EVIDENCE_ITEMS = 100
_IDENTITY_POLICY_LIMITATIONS = [
    "Only identity-policy documents are inspected.",
    "Role trust policies are not inspected.",
    "Permission boundaries are not inspected.",
    "Service control policies (SCPs) are not inspected.",
    "Session policies are not inspected.",
    "Resource policies are not inspected.",
    "NotAction effective permissions are not evaluated.",
    "Business necessity is not proven.",
]


def _normalize_policy_document(document: object) -> dict[str, Any]:
    """Return an IAM policy document supplied as an object or URL-encoded JSON."""
    if isinstance(document, dict):
        return document
    if not isinstance(document, str):
        raise ValueError("IAM policy document is not an object or encoded JSON string")
    parsed = json.loads(unquote(document))
    if not isinstance(parsed, dict):
        raise ValueError("IAM policy document JSON is not an object")
    return parsed


def _role_name_from_arn(role_arn: str):
    """Extract the role name (last path segment) from an IAM role ARN."""
    if not role_arn or ":role/" not in role_arn:
        return None
    return role_arn.split(":role/", 1)[1].split("/")[-1]


def _statements(policy_doc: dict[str, Any]) -> List[dict]:
    """Normalize a policy document's Statement and reject malformed content."""
    if "Statement" not in policy_doc:
        raise ValueError("IAM policy document did not contain Statement")
    statements = policy_doc["Statement"]
    if isinstance(statements, dict):
        return [statements]
    if not isinstance(statements, list) or any(
        not isinstance(statement, dict) for statement in statements
    ):
        raise ValueError("IAM policy document Statement is not an object or object list")
    return statements


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


class IAMServiceRolePolicyCheck(BaseCheck):
    """Inspect Connect service-role identity policies for excessive Allow grants."""

    def __init__(self):
        super().__init__(
            check_id="sec-iam-deep-001",
            name="IAM Service Role Policy Inspection",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Inspects all inline and attached managed identity-policy documents "
                "on the Amazon Connect service role for broad wildcard and out-of-scope "
                "Allow actions."
            ),
        )

    @staticmethod
    def _list_all_inline_policy_names(
        factory: Any, role_name: str
    ) -> tuple[list[object], Optional[Exception]]:
        names: list[object] = []
        marker: Optional[str] = None
        seen_markers: set[str] = set()
        while True:
            try:
                kwargs = {"Marker": marker} if marker else {}
                response = factory.list_role_policies_resilient(role_name, **kwargs)
                page = response.get("PolicyNames")
                if not isinstance(page, list):
                    raise ValueError("ListRolePolicies returned invalid PolicyNames")
                names.extend(page)
                if not response.get("IsTruncated"):
                    return names, None
                next_marker = response.get("Marker")
                if not isinstance(next_marker, str) or not next_marker:
                    raise ValueError("ListRolePolicies response is truncated without a Marker")
                if next_marker in seen_markers:
                    raise ValueError("ListRolePolicies returned a repeated Marker")
                seen_markers.add(next_marker)
                marker = next_marker
            except Exception as error:  # noqa: BLE001
                return names, error

    @staticmethod
    def _list_all_attached_policies(
        factory: Any, role_name: str
    ) -> tuple[list[object], Optional[Exception]]:
        policies: list[object] = []
        marker: Optional[str] = None
        seen_markers: set[str] = set()
        while True:
            try:
                kwargs = {"Marker": marker} if marker else {}
                response = factory.list_attached_role_policies_resilient(role_name, **kwargs)
                page = response.get("AttachedPolicies")
                if not isinstance(page, list):
                    raise ValueError("ListAttachedRolePolicies returned invalid AttachedPolicies")
                policies.extend(page)
                if not response.get("IsTruncated"):
                    return policies, None
                next_marker = response.get("Marker")
                if not isinstance(next_marker, str) or not next_marker:
                    raise ValueError(
                        "ListAttachedRolePolicies response is truncated without a Marker"
                    )
                if next_marker in seen_markers:
                    raise ValueError("ListAttachedRolePolicies returned a repeated Marker")
                seen_markers.add(next_marker)
                marker = next_marker
            except Exception as error:  # noqa: BLE001
                return policies, error

    @staticmethod
    def _source_failure(
        *,
        factory: Any,
        source: str,
        operation: str,
        error: Exception,
        policy_name: object = None,
        policy_arn: object = None,
        policy_version_id: object = None,
    ) -> dict[str, Any]:
        return {
            "policy_source": source,
            "policy_name": policy_name,
            "policy_arn": policy_arn,
            "policy_version_id": policy_version_id,
            "operation": operation,
            "access_denied": bool(factory.is_access_denied(error)),
            "error_type": type(error).__name__,
            "error_code": _error_code(error),
        }

    @staticmethod
    def _analyze_document(
        document: dict[str, Any], metadata: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        broad_violations: list[dict[str, Any]] = []
        out_of_scope: list[dict[str, Any]] = []
        for statement_index, statement in enumerate(_statements(document)):
            if str(statement.get("Effect", "")).lower() != "allow":
                continue
            actions = _as_list(statement.get("Action"))
            resource = statement.get("Resource")
            resources = _as_list(resource)
            condition = statement.get("Condition")
            wildcard_resource = "*" in resources
            for action in actions:
                normalized_action = action.lower()
                context = {
                    **metadata,
                    "statement_index": statement_index,
                    "action": action,
                    "resource": resource,
                    "condition": condition,
                }
                if wildcard_resource and _is_broad_write_action(action):
                    broad_violations.append(context)
                if any(
                    normalized_action.startswith(prefix) for prefix in _OUT_OF_SCOPE_ACTION_PREFIXES
                ):
                    out_of_scope.append(context)
        return broad_violations, out_of_scope

    @staticmethod
    def _bounded(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return items[:_MAX_IAM_POLICY_EVIDENCE_ITEMS]

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        if not instance.service_role:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} has no service role "
                    "configured; role policies cannot be evaluated."
                ),
                evidence={"service_role": None},
                structured_remediation=Remediation(
                    summary="Configure a least-privilege service role for the instance.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Assign a dedicated service-linked role to the "
                                "instance so Connect can access other AWS services "
                                "under least privilege."
                            ),
                            console_path="Connect console -> Instance -> Service role",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Amazon Connect service-linked roles",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-slr.html",  # noqa: E501
                        )
                    ],
                ),
            )

        role_name = _role_name_from_arn(instance.service_role)
        if not role_name:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(f"Service role ARN is malformed: {instance.service_role}"),
                evidence={"service_role": instance.service_role},
                remediation="Correct the service role ARN on the instance.",
            )

        broad_violations: list[dict[str, Any]] = []
        out_of_scope: list[dict[str, Any]] = []
        evaluated: list[dict[str, Any]] = []
        source_failures: list[dict[str, Any]] = []

        inline_names, inline_list_error = self._list_all_inline_policy_names(factory, role_name)
        if inline_list_error is not None:
            source_failures.append(
                self._source_failure(
                    factory=factory,
                    source="inline",
                    operation="iam:ListRolePolicies",
                    error=inline_list_error,
                )
            )

        for policy_name in inline_names:
            operation = "iam:GetRolePolicy"
            try:
                if not isinstance(policy_name, str) or not policy_name:
                    raise ValueError("Inline policy entry did not contain a valid PolicyName")
                response = factory.get_role_policy_resilient(role_name, policy_name)
                document = _normalize_policy_document(response.get("PolicyDocument"))
                metadata = {
                    "policy_source": "inline",
                    "policy_name": policy_name,
                    "policy_arn": None,
                    "policy_version_id": None,
                }
                broad, unrelated = self._analyze_document(document, metadata)
                evaluated.append(metadata)
                broad_violations.extend(broad)
                out_of_scope.extend(unrelated)
            except Exception as error:  # noqa: BLE001
                source_failures.append(
                    self._source_failure(
                        factory=factory,
                        source="inline",
                        operation=operation,
                        policy_name=policy_name,
                        error=error,
                    )
                )

        attached_policies, attached_list_error = self._list_all_attached_policies(
            factory, role_name
        )
        if attached_list_error is not None:
            source_failures.append(
                self._source_failure(
                    factory=factory,
                    source="attached",
                    operation="iam:ListAttachedRolePolicies",
                    error=attached_list_error,
                )
            )

        for attached in attached_policies:
            policy_name: object = None
            policy_arn: object = None
            version_id: object = None
            operation = "iam:ListAttachedRolePolicies"
            try:
                if not isinstance(attached, dict):
                    raise ValueError("Attached policy entry is not an object")
                policy_name = attached.get("PolicyName")
                policy_arn = attached.get("PolicyArn")
                if not isinstance(policy_arn, str) or not policy_arn:
                    raise ValueError("Attached policy entry did not contain a valid PolicyArn")

                operation = "iam:GetPolicy"
                policy = factory.get_policy_resilient(policy_arn).get("Policy")
                if not isinstance(policy, dict):
                    raise ValueError("GetPolicy did not return valid Policy metadata")
                policy_name = policy_name or policy.get("PolicyName")
                if not isinstance(policy_name, str) or not policy_name:
                    raise ValueError("Managed policy metadata did not contain PolicyName")
                version_id = policy.get("DefaultVersionId")
                if not isinstance(version_id, str) or not version_id:
                    raise ValueError("Managed policy did not contain DefaultVersionId")

                operation = "iam:GetPolicyVersion"
                version = factory.get_policy_version_resilient(policy_arn, version_id).get(
                    "PolicyVersion"
                )
                if not isinstance(version, dict):
                    raise ValueError("GetPolicyVersion did not return a valid PolicyVersion")
                document = _normalize_policy_document(version.get("Document"))
                metadata = {
                    "policy_source": "attached",
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "policy_version_id": version_id,
                }
                broad, unrelated = self._analyze_document(document, metadata)
                evaluated.append(metadata)
                broad_violations.extend(broad)
                out_of_scope.extend(unrelated)
            except Exception as error:  # noqa: BLE001
                source_failures.append(
                    self._source_failure(
                        factory=factory,
                        source="attached",
                        operation=operation,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                        policy_version_id=version_id,
                        error=error,
                    )
                )

        inspection_complete = not source_failures
        limitations = list(_IDENTITY_POLICY_LIMITATIONS)
        if source_failures:
            limitations.append(
                f"Inspection was incomplete because {len(source_failures)} policy source "
                "read or policy-document parse operation(s) failed."
            )
        evidence_sets = {
            "evaluated_identity_policies": evaluated,
            "policy_source_failures": source_failures,
            "least_privilege_violations": broad_violations,
            "out_of_scope_actions": out_of_scope,
        }
        evidence = {
            "service_role": instance.service_role,
            "role_name": role_name,
            "inspection_scope": (
                "Inline and attached managed identity-policy documents on the Amazon "
                "Connect service role."
            ),
            "limitations": limitations,
            "inspection_complete": inspection_complete,
            "inline_policy_count": len(inline_names),
            "attached_policy_count": len(attached_policies),
            "evaluated_identity_policy_count": len(evaluated),
            "evidence_item_limit": _MAX_IAM_POLICY_EVIDENCE_ITEMS,
            **{key: self._bounded(items) for key, items in evidence_sets.items()},
            "evidence_items_omitted": {
                key: max(0, len(items) - _MAX_IAM_POLICY_EVIDENCE_ITEMS)
                for key, items in evidence_sets.items()
            },
        }

        if broad_violations or out_of_scope:
            issue_parts = []
            if broad_violations:
                issue_parts.append(f"{len(broad_violations)} broad action(s) on wildcard resources")
            if out_of_scope:
                issue_parts.append(f"{len(out_of_scope)} out-of-scope action(s)")
            incomplete_note = (
                " Inspection was incomplete; see the recorded source failures and limitations."
                if source_failures
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="IAMRole",
                description=(
                    f"Service role '{role_name}' has least-privilege violations: "
                    f"{'; '.join(issue_parts)}.{incomplete_note}"
                ),
                evidence=evidence,
                structured_remediation=self._scope_remediation(
                    role_name, len(broad_violations) + len(out_of_scope)
                ),
            )

        if source_failures:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="IAMRole",
                description=(
                    f"Service role '{role_name}' identity-policy inspection was incomplete, "
                    "so a clean result cannot be reported."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="IAMRole",
            description=(
                f"Inspected {len(evaluated)} inline and attached managed identity-policy "
                f"document(s) on service role '{role_name}'; no broad wildcard or "
                "out-of-scope Allow actions were found."
            ),
            evidence=evidence,
        )

    def _scope_remediation(self, role_name: str, issue_count: int) -> Remediation:
        return Remediation(
            summary=f"Scope down the Connect service role '{role_name}' to least privilege.",
            target_resources=[role_name],
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        f"Review the flagged statements on role '{role_name}' "
                        f"({issue_count} issue(s)) and replace Resource:'*' with "
                        "specific resource ARNs the instance actually needs."
                    ),
                    console_path="IAM console -> Roles -> " + role_name,
                    command=f"aws iam list-role-policies --role-name {role_name}",
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "Remove actions that are unrelated to Connect's operation "
                        "(e.g., iam:*, organizations:*, sts:AssumeRole)."
                    ),
                ),
            ],
            references=[
                RemediationReference(
                    title="IAM least-privilege guidance",
                    url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                )
            ],
            applies_if="this role is used only by the Amazon Connect service.",
        )


# Storage resource types that support encryption configuration.
_STORAGE_RESOURCE_TYPES = [
    "CALL_RECORDINGS",
    "CHAT_TRANSCRIPTS",
    "SCHEDULED_REPORTS",
    "MEDIA_STREAMS",
    "CONTACT_TRACE_RECORDS",
    "AGENT_EVENTS",
]


class InstanceStorageEncryptionCheck(BaseCheck):
    """Verify that configured instance storage is encrypted (Requirement 8)."""

    def __init__(self):
        super().__init__(
            check_id="sec-storage-001",
            name="Instance Storage Encryption Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks each returned Amazon Connect storage configuration "
                "for encryption at rest. AWS-managed and customer-managed KMS "
                "encryption both satisfy this control."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        unencrypted = []
        aws_managed = []
        stream_managed: List[str] = []
        failed_reads = []
        evidence: dict = {"storage": {}}

        for resource_type in _STORAGE_RESOURCE_TYPES:
            try:
                configs = self._list_all_storage_configs(
                    factory, instance.instance_id, resource_type
                )

                for cfg in configs:
                    kms = self._kms_type(cfg)
                    bucket = (cfg.get("S3Config") or {}).get("BucketName")
                    evidence["storage"].setdefault(resource_type, []).append(
                        {
                            "kms_key_type": kms,
                            "bucket": bucket,
                            "storage_type": cfg.get("StorageType"),
                            "encrypted": None if kms == "stream_managed" else kms != "none",
                            "customer_managed_key_configured": kms == "customer_managed",
                        }
                    )
                    if kms == "none":
                        if resource_type not in unencrypted:
                            unencrypted.append(resource_type)
                    elif kms == "aws_managed":
                        if resource_type not in aws_managed:
                            aws_managed.append(resource_type)
                    elif kms == "stream_managed":
                        if resource_type not in stream_managed:
                            stream_managed.append(resource_type)
            except Exception as e:  # noqa: BLE001
                failed_reads.append(
                    {
                        "resource_type": resource_type,
                        "error_type": type(e).__name__,
                        "access_denied": bool(factory.is_access_denied(e)),
                    }
                )

        limitations = (
            [f"{len(failed_reads)} storage resource type read(s) did not complete"]
            if failed_reads
            else []
        )
        evidence.update(
            {
                "resource_types_failed": failed_reads,
                "analysis_complete": not failed_reads,
                "limitations": limitations,
                "unencrypted_resource_types": unencrypted,
                "aws_managed_encryption_resource_types": aws_managed,
                "stream_managed_encryption_resource_types": stream_managed,
                "customer_managed_key_not_configured": aws_managed,
            }
        )

        if unencrypted:
            limitation_note = (
                " Analysis was also incomplete because " + "; ".join(limitations) + "."
                if limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="InstanceStorageConfig",
                description=(
                    f"Connect instance {instance.display_name} has unencrypted storage "
                    f"for: {', '.join(unencrypted)}.{limitation_note}"
                ),
                evidence=evidence,
                structured_remediation=self._encryption_remediation(
                    instance.instance_id, unencrypted
                ),
            )

        if failed_reads:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="InstanceStorageConfig",
                description=(
                    "Storage encryption analysis was incomplete and cannot report PASS: "
                    + "; ".join(limitations)
                    + "."
                ),
                evidence=evidence,
            )

        if aws_managed:
            evidence["conditional_policy_guidance"] = (
                "If organizational policy requires customer-managed KMS keys, review "
                "these storage types and their key-policy requirements."
            )
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="InstanceStorageConfig",
                description=(
                    f"All evaluated storage configurations for instance "
                    f"{instance.display_name} are encrypted. AWS-managed encryption is "
                    f"used for: {', '.join(aws_managed)}; a customer-managed key is not "
                    "configured for those storage types. If organizational policy "
                    "requires customer-managed keys, review the key ownership and policy "
                    "requirements separately."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="InstanceStorageConfig",
            description=(
                f"All evaluated storage configurations for instance "
                f"{instance.display_name} use customer-managed KMS encryption."
            ),
            evidence=evidence,
        )

    @staticmethod
    def _list_all_storage_configs(factory: Any, instance_id: str, resource_type: str) -> List[dict]:
        configs: List[dict] = []
        token: Optional[str] = None
        seen: set = set()
        while True:
            kwargs = {"NextToken": token} if token else {}
            resp = factory.list_instance_storage_configs_resilient(
                instance_id, resource_type, **kwargs
            )
            page = resp.get("StorageConfigs", [])
            if not isinstance(page, list):
                raise ValueError("ListInstanceStorageConfigs returned invalid StorageConfigs")
            for cfg in page:
                if not isinstance(cfg, dict):
                    raise ValueError("ListInstanceStorageConfigs returned an invalid config")
                configs.append(cfg)
            token = resp.get("NextToken")
            if not token:
                return configs
            if token in seen:
                raise ValueError("ListInstanceStorageConfigs returned a repeated NextToken")
            seen.add(token)

    @staticmethod
    def _kms_type(cfg: dict) -> str:
        """Classify a storage config's encryption.

        Returns customer_managed / aws_managed / none, or ``stream_managed`` for
        Kinesis Data Stream / Firehose configs, which have no EncryptionConfig field
        (encryption is managed on the stream itself and is not evaluated here).
        """
        s3 = cfg.get("S3Config") or {}
        if (
            not s3
            and not cfg.get("KinesisVideoStreamConfig")
            and (cfg.get("KinesisStreamConfig") or cfg.get("KinesisFirehoseConfig"))
        ):
            return "stream_managed"
        kinesis = cfg.get("KinesisVideoStreamConfig") or {}
        enc = s3.get("EncryptionConfig") or kinesis.get("EncryptionConfig") or {}
        key_id = enc.get("KeyId") if enc else None
        if not enc or not key_id:
            return "none"
        # Customer-managed keys are referenced by key ARN/ID or alias; the
        # AWS-managed Connect key uses the 'aws/connect' alias.
        if "aws/connect" in str(key_id) or str(key_id).endswith(":alias/aws/connect"):
            return "aws_managed"
        return "customer_managed"

    def _encryption_remediation(self, instance_id: str, resource_types: List[str]) -> Remediation:
        return Remediation(
            summary=f"Enable encryption at rest for storage: {', '.join(resource_types)}.",
            target_resources=[instance_id] + resource_types,
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        "In the Connect instance Data storage settings, edit each "
                        f"flagged storage type ({', '.join(resource_types)}) and "
                        "select a supported KMS key for encryption at rest."
                    ),
                    console_path="Connect console -> Instance -> Data storage",
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "If selecting a customer-managed key, ensure its key policy "
                        "grants the required Amazon Connect permissions."
                    ),
                    command=(
                        "aws connect list-instance-storage-configs "
                        f"--instance-id {instance_id} --resource-type CALL_RECORDINGS"
                    ),
                ),
            ],
            references=[
                RemediationReference(
                    title="Encryption at rest in Amazon Connect",
                    url="https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html",  # noqa: E501
                )
            ],
            applies_if="a returned storage configuration lacks encryption at rest.",
        )


class ApprovedOriginsCheck(BaseCheck):
    """Validate the CCP approved origins allowlist (Requirement 9)."""

    def __init__(self):
        super().__init__(
            check_id="sec-origins-001",
            name="Approved Origins / CCP Access Control Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Validates the approved origins allowlist that controls which "
                "domains may embed the Contact Control Panel (CCP)."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.list_approved_origins_resilient(instance.instance_id)
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListApprovedOrigins")
            raise

        origins = resp.get("Origins", []) or []
        evidence = {"approved_origins": origins, "count": len(origins)}

        broad = [
            o
            for o in origins
            if "*" in o or "localhost" in o.lower() or o.strip() in ("http://", "https://")
        ]
        evidence["overly_broad_origins"] = broad

        if broad:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} has overly broad "
                    f"approved origins: {', '.join(broad)}."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Restrict CCP approved origins to specific trusted domains.",
                    target_resources=[instance.instance_id] + broad,
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Remove wildcard/localhost origins and add only the "
                                "exact HTTPS domains that host your agent application."
                            ),
                            console_path="Connect console -> Instance -> Approved origins",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Use an allow list for integrated applications",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/allowlist-domains.html",  # noqa: E501
                        )
                    ],
                ),
            )

        if not origins:
            # An empty list is the safe default for the native agent workspace.
            # Preserve conditional guidance for customers that embed CCP.
            return self.not_applicable(
                context,
                reason=(
                    f"Connect instance {instance.display_name} has no approved-origins "
                    "allowlist configured.\n\n"
                    "**What this means.** The approved-origins allowlist is the list "
                    "of external website domains that are allowed to load the Contact "
                    "Control Panel (CCP) — the browser UI agents use to take calls — "
                    "as an embedded iframe. When the list is empty, no external site "
                    "can embed the CCP; agents can only reach it through the native "
                    "Connect agent workspace URL "
                    f"(`https://{instance.instance_alias or 'YOUR-ALIAS'}.my.connect.aws/ccp-v2/`).\n\n"
                    "**When to act.** Add an entry only if you plan to embed the CCP "
                    "in a custom agent desktop or CRM. In that case, add the specific "
                    "HTTPS domain(s) of those applications so agents can access CCP "
                    "through them.\n\n"
                    "**When to leave as-is.** If your agents use only the native "
                    "Connect UI, no allowlist entries are needed — the empty list is "
                    "the safe default and blocks arbitrary websites from framing "
                    "CCP against your instance."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Only if the CCP is embedded in a custom agent application: "
                        "add its HTTPS domain to the approved-origins allowlist."
                    ),
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "In the Connect console, go to Instance -> Approved "
                                "origins and add the specific HTTPS domain(s) of the "
                                "custom agent app(s) that embed the CCP. Use full "
                                "https:// URLs (no wildcards, no localhost)."
                            ),
                            console_path="Connect console -> Instance -> Approved origins",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Use an allow list for integrated applications",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/allowlist-domains.html",  # noqa: E501
                        )
                    ],
                    applies_if="the CCP is embedded in a custom agent application.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Connect instance {instance.display_name} restricts CCP embedding to "
                f"{len(origins)} explicit origin(s)."
            ),
            evidence=evidence,
        )


def _selector_condition_matches(value: str, field_selector: dict) -> bool:
    """Evaluate an advanced selector field against one candidate event value."""
    conditions = {
        "Equals": lambda candidate, expected: candidate == expected,
        "NotEquals": lambda candidate, expected: candidate != expected,
        "StartsWith": lambda candidate, expected: candidate.startswith(expected),
        "NotStartsWith": lambda candidate, expected: not candidate.startswith(expected),
        "EndsWith": lambda candidate, expected: candidate.endswith(expected),
        "NotEndsWith": lambda candidate, expected: not candidate.endswith(expected),
    }
    for operator, matcher in conditions.items():
        if operator not in field_selector:
            continue
        expected_values = _as_list(field_selector[operator])
        if operator.startswith("Not"):
            if not all(matcher(value, expected) for expected in expected_values):
                return False
        elif not any(matcher(value, expected) for expected in expected_values):
            return False
    return True


def _advanced_selector_covers_connect_writes(selector: dict) -> tuple[bool, str]:
    candidates = {
        "eventCategory": "Management",
        "readOnly": "false",
        "eventSource": "connect.amazonaws.com",
    }
    fields = selector.get("FieldSelectors", []) or []
    if not isinstance(fields, list):
        return False, "Advanced selector FieldSelectors is not a list."
    if not any(
        isinstance(field_selector, dict) and field_selector.get("Field") == "eventCategory"
        for field_selector in fields
    ):
        return False, "Advanced selector does not identify management events."

    for field_selector in fields:
        if not isinstance(field_selector, dict):
            return False, "Advanced selector contains a malformed field selector."
        field = field_selector.get("Field")
        if field not in candidates:
            return False, f"Unsupported advanced selector field {field!r} prevents proof."
        if not _selector_condition_matches(candidates[field], field_selector):
            return False, (
                f"Advanced selector field {field!r} excludes the Connect management "
                "write-event candidate."
            )
    return True, (
        "Advanced selector includes management write events and does not exclude "
        "eventSource connect.amazonaws.com."
    )


def _basic_selector_covers_connect_writes(selector: dict) -> tuple[bool, str]:
    if selector.get("IncludeManagementEvents", True) is not True:
        return False, "Basic selector disables management events."
    read_write_type = selector.get("ReadWriteType", "All")
    if read_write_type not in {"All", "WriteOnly"}:
        return False, f"Basic selector ReadWriteType={read_write_type!r} excludes writes."
    excluded_sources = _as_list(selector.get("ExcludeManagementEventSources"))
    if "connect.amazonaws.com" in excluded_sources:
        return False, "Basic selector explicitly excludes Connect management events."
    return True, (
        f"Basic selector includes management events with ReadWriteType={read_write_type} "
        "and does not exclude Connect."
    )


def _selector_coverage_reasoning(response: dict) -> tuple[bool, list[dict]]:
    reasoning: list[dict] = []
    covered = False
    for index, selector in enumerate(response.get("EventSelectors", []) or []):
        qualifies, reason = _basic_selector_covers_connect_writes(selector)
        covered = covered or qualifies
        reasoning.append(
            {
                "selector_type": "basic",
                "selector_index": index,
                "qualifies": qualifies,
                "reason": reason,
            }
        )
    for index, selector in enumerate(response.get("AdvancedEventSelectors", []) or []):
        qualifies, reason = _advanced_selector_covers_connect_writes(selector)
        covered = covered or qualifies
        reasoning.append(
            {
                "selector_type": "advanced",
                "selector_index": index,
                "qualifies": qualifies,
                "reason": reason,
            }
        )
    if not reasoning:
        reasoning.append(
            {
                "selector_type": "none",
                "selector_index": None,
                "qualifies": False,
                "reason": "GetEventSelectors returned no basic or advanced selectors.",
            }
        )
    return covered, reasoning


class CloudTrailIntegrationCheck(BaseCheck):
    """Verify active CloudTrail management write-event coverage for Connect."""

    def __init__(self):
        super().__init__(
            check_id="sec-cloudtrail-001",
            name="CloudTrail Connect Management Write-Event Coverage",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Verifies that at least one trail returned for the assessed region is "
                "actively logging selectors that cover Amazon Connect management write events."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            response = factory.describe_trails_resilient()
        except Exception as error:  # noqa: BLE001
            if factory.is_access_denied(error):
                return self.skipped_for_access_denied(context, "cloudtrail:DescribeTrails")
            raise

        trails = response.get("trailList", []) or []
        trail_evidence = []
        detail_failures = []
        qualifying_trails = []

        for trail in trails:
            trail_name = trail.get("Name")
            trail_identifier = trail.get("TrailARN") or trail_name
            item = {
                "trail_name": trail_name,
                "trail_arn": trail.get("TrailARN"),
                "home_region": trail.get("HomeRegion"),
                "is_multi_region_trail": bool(trail.get("IsMultiRegionTrail")),
                "applicability": (
                    "Returned by DescribeTrails for the assessed region, including any "
                    "applicable shadow trail."
                ),
                "is_logging": None,
                "selector_covers_connect_management_writes": None,
                "selector_reasoning": [],
            }

            try:
                if not trail_identifier:
                    raise ValueError("DescribeTrails entry has no Name or TrailARN")
                status = factory.get_trail_status_resilient(trail_identifier)
                item["is_logging"] = status.get("IsLogging") is True
            except Exception as error:  # noqa: BLE001
                detail_failures.append(
                    {
                        "trail_name": trail_name,
                        "operation": "cloudtrail:GetTrailStatus",
                        "access_denied": factory.is_access_denied(error),
                        "error_type": type(error).__name__,
                        "error_code": _error_code(error),
                    }
                )

            try:
                if not trail_identifier:
                    raise ValueError("DescribeTrails entry has no Name or TrailARN")
                selectors = factory.get_trail_event_selectors_resilient(trail_identifier)
                selector_coverage, reasoning = _selector_coverage_reasoning(selectors)
                item["selector_covers_connect_management_writes"] = selector_coverage
                item["selector_reasoning"] = reasoning
            except Exception as error:  # noqa: BLE001
                detail_failures.append(
                    {
                        "trail_name": trail_name,
                        "operation": "cloudtrail:GetEventSelectors",
                        "access_denied": factory.is_access_denied(error),
                        "error_type": type(error).__name__,
                        "error_code": _error_code(error),
                    }
                )

            if (
                item["is_logging"] is True
                and item["selector_covers_connect_management_writes"] is True
            ):
                qualifying_trails.append(trail_name or trail_identifier)
            trail_evidence.append(item)

        evidence = {
            "trail_count": len(trails),
            "qualifying_trails": qualifying_trails,
            "inspection_complete": not detail_failures,
            "trail_details": trail_evidence,
            "detail_failures": detail_failures,
            "limitations": [
                "Configuration does not prove event delivery or destination availability.",
                "Configuration does not prove retention, immutability, or log-file integrity.",
                "This check does not inspect S3, CloudWatch Logs, or KMS destination controls.",
            ],
        }

        if qualifying_trails:
            qualifier = (
                " Other returned trails could not be fully inspected." if detail_failures else ""
            )
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Verified {len(qualifying_trails)} active applicable CloudTrail "
                    "trail(s) whose selectors cover Connect management write events."
                    f"{qualifier}"
                ),
                evidence=evidence,
            )

        if detail_failures:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "CloudTrail trail details could not be fully inspected, so the "
                    "absence of active Connect management write-event coverage could "
                    "not be established."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "No applicable CloudTrail trail is actively logging selectors that "
                "cover Amazon Connect management write events."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Configure and start an applicable CloudTrail trail with management "
                    "write-event selectors that include Amazon Connect."
                ),
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Create or update an applicable trail so it is logging and its "
                            "basic or advanced selectors include Connect management writes."
                        ),
                        console_path="CloudTrail console -> Trails -> Event selectors",
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Validate delivery, retention, destination protection, and a "
                            "recent controlled Connect management event separately."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Logging Amazon Connect API calls with CloudTrail",
                        url="https://docs.aws.amazon.com/connect/latest/adminguide/logging-using-cloudtrail.html",  # noqa: E501
                    )
                ],
            ),
        )


class IdentityFederationCheck(BaseCheck):
    """Assess identity management strength (Requirement 11)."""

    def __init__(self):
        super().__init__(
            check_id="sec-federation-001",
            name="Identity Federation / MFA Check",
            pillar=Pillar.SECURITY,
            severity=Severity.LOW,
            description=(
                "Reports the instance's identity management type so you can "
                "confirm centralized authentication and MFA are enforced "
                "somewhere in the sign-in path — either via SAML federation "
                "to your enterprise IdP, or via Connect-managed identity "
                "combined with your own SSO/MFA layer (e.g. Okta, Entra ID) "
                "in front of it."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        idm = (instance.identity_management_type or "").upper()
        evidence = {"identity_management_type": idm}

        if idm == "SAML":
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Instance {instance.display_name} uses SAML federation, enabling "
                    "centralized authentication and MFA enforcement at the IdP."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Instance {instance.display_name} reports '{idm or 'unknown'}' identity "
                "management. This inventory does not establish whether MFA or "
                "centralized lifecycle controls are enforced. Verify the actual sign-in "
                "path, identity-provider or native MFA policy, and break-glass access."
            ),
            evidence=evidence,
        )


# Administrative permission names that should not appear on non-admin profiles.
_ADMIN_PERMISSIONS = {
    "Users.Create",
    "Users.Edit",
    "Users.Delete",
    "SecurityProfiles.Create",
    "SecurityProfiles.Edit",
    "SecurityProfiles.Delete",
    "InstanceSettings.Edit",
}


def _paginate_connect(call: Any, list_key: str) -> List[Any]:
    """Collect every page of a Connect list call that uses NextToken."""
    items: List[Any] = []
    token: Optional[str] = None
    seen: set = set()
    while True:
        resp = call(**({"NextToken": token} if token else {}))
        items.extend(resp.get(list_key, []) or [])
        token = resp.get("NextToken")
        if not token:
            return items
        if token in seen:
            raise ValueError("Repeated NextToken in paginated response")
        seen.add(token)


class SecurityProfileAuditCheck(BaseCheck):
    """Audit security profile permissions (Requirement 12)."""

    def __init__(self):
        super().__init__(
            check_id="sec-profile-audit-001",
            name="Security Profile Permissions Audit",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Audits security profile permissions to flag non-administrator "
                "profiles that grant administrative capabilities."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            profiles = _paginate_connect(
                lambda **kw: factory.list_security_profiles_resilient(instance.instance_id, **kw),
                "SecurityProfileSummaryList",
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListSecurityProfiles")
            raise

        over_privileged = []
        source_failures: List[dict] = []
        evidence: dict = {
            "profile_count": len(profiles),
            "profiles": {},
            "source_failures": source_failures,
        }

        for profile in profiles:
            name = profile.get("Name", "")
            pid = profile.get("Id", "")
            try:
                perms = set(
                    _paginate_connect(
                        lambda pid=pid, **kw: factory.list_security_profile_permissions_resilient(
                            instance.instance_id, pid, **kw
                        ),
                        "Permissions",
                    )
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(
                        context, "connect:ListSecurityProfilePermissions"
                    )
                source_failures.append(
                    {
                        "profile_name": name,
                        "operation": "connect:ListSecurityProfilePermissions",
                        "error_type": type(e).__name__,
                        "error_code": _error_code(e),
                    }
                )
                continue

            admin_perms = perms & _ADMIN_PERMISSIONS
            evidence["profiles"][name] = {
                "permission_count": len(perms),
                "has_admin_permissions": bool(admin_perms),
            }
            # Treat the canonical "Admin" profile as expected to hold admin perms.
            if admin_perms and name.lower() not in ("admin", "administrator"):
                over_privileged.append(f"{name} ({', '.join(sorted(admin_perms))})")

        if over_privileged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="SecurityProfile",
                description=(
                    "Non-administrator security profiles grant administrative "
                    f"permissions: {'; '.join(over_privileged)}."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Remove administrative permissions from non-admin profiles.",
                    target_resources=[p.split(" ")[0] for p in over_privileged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Edit each flagged security profile and remove "
                                "Users.*/SecurityProfiles.*/InstanceSettings.Edit "
                                "permissions unless the role is genuinely an admin."
                            ),
                            console_path="Connect console -> Users -> Security profiles",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Security profiles in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-security-profiles.html",  # noqa: E501,
                        )
                    ],
                    applies_if="agents assigned these profiles should not administer the instance.",
                ),
            )

        if source_failures:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="SecurityProfile",
                description=(
                    f"Permissions could not be read for {len(source_failures)} security "
                    "profile(s), so a clean result cannot be reported."
                ),
                evidence={**evidence, "evidence_complete": False},
                context=context,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="SecurityProfile",
            description=(
                f"No non-administrator profile among {len(profiles)} grants "
                "administrative permissions."
            ),
            evidence=evidence,
        )


def register_security_deep_checks(registry) -> None:
    """Register all deep-inspection security checks with the given registry."""
    registry.register_check(IAMServiceRolePolicyCheck())
    registry.register_check(InstanceStorageEncryptionCheck())
    registry.register_check(ApprovedOriginsCheck())
    registry.register_check(CloudTrailIntegrationCheck())
    registry.register_check(IdentityFederationCheck())
    registry.register_check(SecurityProfileAuditCheck())
