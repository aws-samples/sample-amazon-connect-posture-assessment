"""
Security checks for Amazon Connect Assessment Tool.

This module implements checks for the Security pillar of the AWS
Well-Architected Framework. It currently ships two checks:

  * :class:`IAMServiceRoleCheck` — validates the presence and ARN format
    of the Connect service role.
  * :class:`DataProtectionCheck` — verifies every Connect user has at
    least one security profile assigned. Historically this check also
    emitted CISO-boilerplate lines about "contact flows configured —
    ensure they handle customer data appropriately"; those were
    removed because they said nothing actionable. Real data-protection
    signal now comes from sec-sensitive-data-001 (attributes storing
    PII), sec-pii-prompts-001 (prompts speaking PII), sec-storage-001
    (recording/transcript encryption), and sec-profile-audit-001
    (role-based access review).

Two earlier checks were removed after user feedback:

  * ``EncryptionConfigurationCheck`` (``security-encryption-001``) fired
    a HIGH-severity FAIL for every S3 or Lambda integration with the
    string "requires encryption validation", but did not actually check
    the buckets' encryption or the functions' environment encryption.
    It was a placeholder that shipped as a finding; the real signal now
    lives in :class:`security_deep_checks.InstanceStorageEncryptionCheck`
    (``sec-storage-001``).
  * ``NetworkSecurityCheck`` (``security-network-001``) fired HIGH-severity
    FAILs for ``CONNECT_MANAGED`` identity ("ensure strong password
    policies") and for having both inbound + outbound calls enabled
    ("ensure proper access controls"). Neither condition is a network-
    security defect — the first is an identity choice, the second is
    the majority Connect deployment shape. The name was misleading too
    (the check did not inspect network configuration at all). Identity-
    federation posture is covered by
    :class:`security_deep_checks.IdentityFederationCheck`
    (``sec-federation-001``).

AWS Well-Architected Framework Reference:
https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
"""

import re

from ..models import (
    CheckStatus,
    Finding,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

_IAM_ROLE_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$"
)


class IAMServiceRoleCheck(BaseCheck):
    """Check only that Connect reports a syntactically valid service-role ARN."""

    def __init__(self):
        super().__init__(
            check_id="security-iam-001",
            name="IAM Service Role Presence and ARN Format",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            description=(
                "Checks whether the Amazon Connect instance reports a service-role "
                "ARN in a supported AWS partition and IAM role ARN format."
            ),
            remediation_template=(
                "Configure the Amazon Connect instance with its intended IAM service-role "
                "ARN, or correct the reported ARN format. Validate role permissions and "
                "trust separately. Reference: "
                "https://docs.aws.amazon.com/connect/latest/adminguide/connect-slr.html"
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        """Evaluate service-role presence and IAM role ARN syntax."""
        instance = context.instance
        evidence = {
            "instance_id": instance.instance_id,
            "service_role_arn": instance.service_role,
            "identity_management_type": instance.identity_management_type,
            "supported_partitions": ["aws", "aws-us-gov", "aws-cn"],
            "validation_scope": "service-role presence and IAM role ARN format only",
            "limitations": [
                "Does not verify that the role exists.",
                "Does not inspect the role trust policy or permissions.",
                "Does not establish least privilege or effective access.",
            ],
        }

        if not instance.service_role:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} does not report a service-role ARN."
                ),
                evidence=evidence,
            )

        if not _IAM_ROLE_ARN_RE.fullmatch(instance.service_role):
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} reports a malformed or "
                    f"unsupported IAM role ARN: {instance.service_role}"
                ),
                evidence=evidence,
            )

        evidence["service_role_present"] = True
        evidence["service_role_arn_format_valid"] = True
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Connect instance {instance.display_name} reports a service-role ARN "
                "in the expected IAM role ARN format."
            ),
            evidence=evidence,
        )


class DataProtectionCheck(BaseCheck):
    """
    Access-control hygiene: every user has a security profile.

    Historically this check emitted three lines: (1) "no security profiles",
    (2) "only one security profile — consider role-based access", and
    (3) "contact flows configured — ensure they handle customer data
    appropriately and comply with privacy regulations". Lines 2 and 3
    fired on almost every instance and said nothing useful — the first
    was a preference dressed as a defect, the second was pure CISO-
    boilerplate that made the report sound scolding.

    The check now focuses on the one thing it can actually verify from
    the API surface: whether every enabled Connect user has at least one
    security profile assigned. A user with no profile can sign in but
    can't access anything — that's a real deployment defect, not a
    style preference. See the ``sec-profile-audit-001`` check in
    ``security_deep_checks`` for role-based-access-control review; and
    the ``sec-sensitive-data-001`` / ``sec-pii-prompts-001`` /
    ``sec-storage-001`` checks for the substantive data-protection
    signal that this check used to gesture at.
    """

    def __init__(self):
        super().__init__(
            check_id="security-data-001",
            name="User Security Profile Assignment",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Every Amazon Connect user needs at least one security "
                "profile assigned. Without one, the user can sign in but "
                "can't access anything meaningful — a deployment defect "
                "that this check catches."
            ),
            # Fallback remediation string used when a specific finding
            # doesn't attach a `structured_remediation`. Real remediation
            # is per-finding (built inline for the FAIL case above);
            # this stub exists so the MVP validator's completeness
            # assertion is satisfied.
            remediation_template=(
                "Assign a security profile to each user in the Connect "
                "console under Users -> User management, or delete the "
                "user if they were created in error."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance

        try:
            users_without_profile = [u for u in instance.users if not u.security_profile_ids]

            evidence = {
                "instance_id": instance.instance_id,
                "users_total": len(instance.users),
                "users_without_security_profile": len(users_without_profile),
                "usernames_without_profile": [u.username for u in users_without_profile[:10]],
                "security_profiles_total": len(instance.security_profiles),
            }

            if not instance.users:
                return self.create_finding(
                    status=CheckStatus.PASS,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=(
                        f"Connect instance {instance.display_name} has no "
                        "users configured yet, so there's nothing to check "
                        "for security-profile assignment. Once you add "
                        "users, each one needs at least one profile."
                    ),
                    evidence=evidence,
                )

            if not users_without_profile:
                return self.create_finding(
                    status=CheckStatus.PASS,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=(
                        f"All {len(instance.users)} user(s) on Connect "
                        f"instance {instance.display_name} have at least "
                        "one security profile assigned. Access control is "
                        "in place at the user level."
                    ),
                    evidence=evidence,
                )

            username_list = ", ".join(f"`{u}`" for u in evidence["usernames_without_profile"])
            more_note = (
                f" (+ {len(users_without_profile) - 10} more)"
                if len(users_without_profile) > 10
                else ""
            )

            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"**{len(users_without_profile)} of "  # nosec B608 - Markdown prose, not SQL
                    f"{len(instance.users)} user(s) on Connect instance "
                    f"{instance.display_name} have no security profile "
                    "assigned.**\n\n"
                    "In Amazon Connect, a security profile is the bag of "
                    "permissions a user gets — access to CCP, the agent "
                    "workspace, reports, admin pages, and so on. A user "
                    "without any profile can authenticate but can't "
                    "reach anything useful; they'll typically see a "
                    "blank workspace or an access-denied page.\n\n"
                    "This is almost always a leftover from bulk user "
                    "creation where the profile step got missed. It's "
                    "also a soft security signal — an unassigned user "
                    "record is a login that shouldn't exist yet.\n\n"
                    f"**Users without a profile:** {username_list}{more_note}\n\n"
                    "**Fix.** For each user, either assign the "
                    "appropriate profile (Agent, Admin, or one you've "
                    "created for their role) or disable/delete the user "
                    "if they were created in error. Connect \u2192 Users \u2192 "
                    "select the user \u2192 pick a security profile from the "
                    "dropdown \u2192 save."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        f"Assign a security profile to each of the "
                        f"{len(users_without_profile)} unprofiled user(s), "
                        "or remove the users if they were created in "
                        "error."
                    ),
                    target_resources=[u.username for u in users_without_profile[:10]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "In the Connect console, open Users \u2192 "
                                "User management. Sort by 'Security "
                                "profiles' and find rows that are blank. "
                                "For each: assign a profile appropriate "
                                "for the user's role, or delete the row "
                                "if the user shouldn't exist."
                            ),
                            console_path="Connect console -> Users -> User management",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "If none of the built-in profiles fit, "
                                "define a custom one under Users \u2192 "
                                "Security profiles first, then assign it. "
                                "Custom profiles are the way to grant "
                                "narrower access than 'Agent' — e.g. an "
                                "outbound-only profile with no historical "
                                "metrics access."
                            ),
                            console_path=("Connect console -> Users -> Security profiles"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Security profiles in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-security-profiles.html",  # noqa: E501
                        )
                    ],
                ),
            )

        except Exception as e:
            self.logger.error(f"Error executing data protection check: {str(e)}")
            return self.create_finding(
                status=CheckStatus.ERROR,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Failed to execute data protection check: {str(e)}",
                evidence={"error": str(e)},
            )
