"""
Telephony toll-fraud controls.

These close the gaps found by walking a real agent-initiated toll-fraud
incident against the catalog (see docs/design/improvement-backlog.md, A2-A5).
The attack chain was: a Connect-managed password with no MFA (covered by
``sec-federation-001``) -> sign-in from an arbitrary network -> an authenticated
CCP session -> agent-dialed calls to premium-rate international destinations
-> ten days before anyone noticed.

- sec-ip-access-001       : IP-based access control for agent sign-in (A2)
- sec-outbound-scope-001  : how widely "Make outbound calls" is granted (A3)
- sec-outbound-dest-001   : where outbound calls actually went (A4)
- sec-fraud-alerting-001  : whether a cost spike on Connect would alert anyone (A5)

All four are read-only and Manual Review: each reports configuration or
evidence a human must judge against the business's legitimate needs.

Data minimisation (sec-outbound-dest-001): dialed numbers are read from
contact records only to derive their country calling code. They are never
logged or stored; the report records aggregate counts per calling code.
"""

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext, _error_code
from .security_deep_checks import _paginate_connect

_FRAUD_PREVENTION_REF = RemediationReference(
    title="Service controls and fraud prevention in Amazon Connect",
    url="https://docs.aws.amazon.com/connect/latest/adminguide/fraud-prevention.html",
)


def _connect(factory, operation: str, **kwargs) -> Dict[str, Any]:
    return factory.call_api_with_resilience(
        factory.get_connect_client(), operation, "connect", **kwargs
    )


def _outbound_unknown(check: BaseCheck, instance, common: Dict[str, Any]):
    """SKIPPED when DescribeInstance did not report OutboundCallsEnabled.

    An unreported setting is not evidence that outbound calling is off, so it
    must not become "not applicable".
    """
    if instance.outbound_calls_enabled is not None:
        return None
    return check.create_finding(
        status=CheckStatus.SKIPPED,
        description=(
            f"Skipped: instance {instance.display_name} did not report whether outbound calling "
            "is enabled, so outbound exposure cannot be evaluated."
        ),
        evidence={"outbound_calls_enabled": None, "evidence_complete": False},
        **common,
    )


def _account_id_from_arn(arn: str) -> str:
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 4 else ""


# ---------------------------------------------------------------------------
# A2 — IP-based access control
# ---------------------------------------------------------------------------


def _feature_not_enabled(error: Exception) -> bool:
    """Authentication profiles are gated per account until AWS enables them.

    Verified live: ListAuthenticationProfiles returns InvalidRequestException
    "Account … is not allowed to use this feature. Please contact customer
    support." That is a finding (no IP control is possible), not an error.
    """
    return _error_code(
        error
    ) == "InvalidRequestException" and "not allowed to use this feature" in (str(error))


class IpAccessControlCheck(BaseCheck):
    """A2: is agent sign-in restricted to approved networks?"""

    def __init__(self):
        super().__init__(
            check_id="sec-ip-access-001",
            name="IP-Based Access Control for Agent Sign-In",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks whether the instance's default authentication profile restricts "
                "sign-in to approved IP ranges, so a stolen agent password cannot be used "
                "from an arbitrary network."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        # A stolen login is a toll-fraud path when the instance can dial out; an
        # unreported setting cannot rule that out.
        severity = Severity.MEDIUM if instance.outbound_calls_enabled is False else Severity.HIGH
        common = {
            "resource_id": instance.instance_id,
            "resource_type": "ConnectInstance",
            "severity": severity,
            "context": context,
        }

        try:
            summaries = _paginate_connect(
                lambda **kw: _connect(
                    factory,
                    "list_authentication_profiles",
                    InstanceId=instance.instance_id,
                    MaxResults=1000,
                    **kw,
                ),
                "AuthenticationProfileSummaryList",
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListAuthenticationProfiles")
            if _feature_not_enabled(e):
                return self.create_finding(
                    status=CheckStatus.FAIL,
                    description=(
                        f"Instance {instance.display_name} cannot restrict sign-in by IP "
                        "address: authentication profiles, which carry IP-based access "
                        "control, are not enabled for this AWS account. Any network can be "
                        "used with a valid agent password. AWS enables the feature on "
                        "request."
                    ),
                    evidence={"authentication_profiles_available": False},
                    structured_remediation=self._remediation(instance, feature_enabled=False),
                    **common,
                )
            raise

        profiles: List[Dict[str, Any]] = []
        for summary in summaries:
            try:
                profiles.append(
                    _connect(
                        factory,
                        "describe_authentication_profile",
                        InstanceId=instance.instance_id,
                        AuthenticationProfileId=summary["Id"],
                    ).get("AuthenticationProfile", {})
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(
                        context, "connect:DescribeAuthenticationProfile"
                    )
                raise

        # IP ranges themselves (corporate egress addresses) stay out of the
        # report; counts are enough to judge coverage.
        evidence = {
            "authentication_profiles_available": True,
            "profiles": [
                {
                    "name": p.get("Name"),
                    "is_default": bool(p.get("IsDefault")),
                    "allowed_ip_range_count": len(p.get("AllowedIps") or []),
                    "blocked_ip_range_count": len(p.get("BlockedIps") or []),
                    "session_inactivity_minutes": p.get("SessionInactivityDuration"),
                    "session_inactivity_logout_enabled": p.get("SessionInactivityHandlingEnabled"),
                    "max_session_minutes": p.get("MaxSessionDuration"),
                }
                for p in profiles
            ],
        }
        default = next((p for p in profiles if p.get("IsDefault")), None)
        if default is None:
            # Every instance has a default profile; without it the coverage of
            # most users is unknown, so no conclusion is drawn.
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    f"Skipped: no default authentication profile was returned for instance "
                    f"{instance.display_name}, so the restriction that applies to most users "
                    "is unknown."
                ),
                evidence={**evidence, "evidence_complete": False},
                **common,
            )
        restricted_others = [
            p.get("Name") or "" for p in profiles if not p.get("IsDefault") and p.get("AllowedIps")
        ]
        # AWS documents the default profile as applying to every user, and the
        # API exposes no profile-to-user assignment. So a non-default profile
        # without an allow list cannot be ruled out as covering some users:
        # PASS requires every profile to restrict.
        unrestricted_others = sorted(
            p.get("Name") or p.get("Id") or ""
            for p in profiles
            if not p.get("IsDefault") and not p.get("AllowedIps")
        )

        if default.get("AllowedIps") and not unrestricted_others:
            return self.create_finding(
                status=CheckStatus.PASS,
                description=(
                    f"Every authentication profile on instance {instance.display_name} allows "
                    "sign-in only from approved IP ranges; the default profile, which applies to "
                    f"all users, allows {len(default['AllowedIps'])} range(s)."
                ),
                evidence=evidence,
                **common,
            )

        if default.get("AllowedIps"):
            gap = (
                f"the default profile restricts sign-in, but profile(s) "
                f"{', '.join(unrestricted_others)} have no IP allow list, and the API does not "
                "show which users they apply to"
            )
        elif default.get("BlockedIps"):
            gap = (
                "the default authentication profile only blocks listed ranges, so every "
                "other network can still sign in"
            )
        elif restricted_others:
            gap = (
                f"only the non-default profile(s) {', '.join(sorted(restricted_others))} "
                "restrict IP ranges; users on the default profile can sign in from any network"
            )
        else:
            gap = "no authentication profile restricts sign-in by IP address"
        return self.create_finding(
            status=CheckStatus.FAIL,
            description=(
                f"Instance {instance.display_name}: {gap}. A stolen agent password can be "
                "used from any network unless your identity provider enforces network "
                "conditions."
            ),
            evidence=evidence,
            structured_remediation=self._remediation(instance, feature_enabled=True),
            **common,
        )

    @staticmethod
    def _remediation(instance, feature_enabled: bool) -> Remediation:
        steps = []
        if not feature_enabled:
            steps.append(
                RemediationStep(
                    order=1,
                    instruction=(
                        "Open an AWS Support case asking for authentication profiles to be "
                        "enabled for this account."
                    ),
                )
            )
        steps.extend(
            [
                RemediationStep(
                    order=len(steps) + 1,
                    instruction=(
                        "On the default authentication profile, add the IP ranges agents "
                        "legitimately sign in from (office egress, VPN, VDI) as allowed "
                        "ranges. An allow list restricts; a block list alone does not."
                    ),
                    console_path="Connect admin website -> Users -> Authentication profiles",
                ),
                RemediationStep(
                    order=len(steps) + 2,
                    instruction=(
                        "IP restrictions do not cover the emergency admin login: restrict "
                        "connect:AdminGetEmergencyAccessToken with a SourceIp condition in IAM."
                    ),
                ),
            ]
        )
        return Remediation(
            summary="Restrict agent sign-in to approved networks.",
            target_resources=[instance.instance_id],
            steps=steps,
            references=[
                RemediationReference(
                    title="Set IP address restrictions and session timeouts",
                    url="https://docs.aws.amazon.com/connect/latest/adminguide/authentication-profiles.html",  # noqa: E501
                ),
                _FRAUD_PREVENTION_REF,
            ],
        )


# ---------------------------------------------------------------------------
# A3 — who can dial out
# ---------------------------------------------------------------------------

# Security-profile permission behind CCP "Make outbound calls" (verified live).
OUTBOUND_CALL_PERMISSION = "OutboundCallAccess"

# Above this share of users, the permission has not been scoped to the agents
# who need it. Connect's default Agent profile grants it, so an unscoped
# instance typically sits at or near 100%.
_BROAD_OUTBOUND_SHARE = 0.5


class OutboundPermissionScopeCheck(BaseCheck):
    """A3: is "Make outbound calls" granted only to the users who need it?"""

    def __init__(self):
        super().__init__(
            check_id="sec-outbound-scope-001",
            name="Outbound Calling Permission Scope",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Inventories which security profiles grant outbound calling and how many "
                "users hold it. Every user who can dial out is an account a stolen password "
                "can turn into toll fraud."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        common = {
            "resource_id": instance.instance_id,
            "resource_type": "ConnectInstance",
            "context": context,
        }
        skipped = _outbound_unknown(self, instance, common)
        if skipped:
            return skipped
        if not instance.outbound_calls_enabled:
            return self.create_finding(
                status=CheckStatus.NOT_APPLICABLE,
                description=(
                    f"Outbound calling is disabled on instance {instance.display_name}, so "
                    "no user can dial out."
                ),
                evidence={"outbound_calls_enabled": False},
                **common,
            )

        try:
            profiles = _paginate_connect(
                lambda **kw: factory.list_security_profiles_resilient(instance.instance_id, **kw),
                "SecurityProfileSummaryList",
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListSecurityProfiles")
            raise

        outbound_profiles: Dict[str, str] = {}
        failures: List[Dict[str, str]] = []
        for profile in profiles:
            pid, name = profile.get("Id", ""), profile.get("Name", "")
            try:
                perms = _paginate_connect(
                    lambda pid=pid, **kw: factory.list_security_profile_permissions_resilient(
                        instance.instance_id, pid, **kw
                    ),
                    "Permissions",
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(
                        context, "connect:ListSecurityProfilePermissions"
                    )
                failures.append({"profile_name": name, "error_code": _error_code(e) or ""})
                continue
            if OUTBOUND_CALL_PERMISSION in perms:
                outbound_profiles[pid] = name

        try:
            users = _paginate_connect(
                lambda **kw: _connect(
                    factory, "search_users", InstanceId=instance.instance_id, MaxResults=500, **kw
                ),
                "Users",
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:SearchUsers")
            raise

        outbound_ids = set(outbound_profiles)
        holders = [u for u in users if outbound_ids.intersection(u.get("SecurityProfileIds") or [])]
        per_profile = {
            name: sum(1 for u in users if pid in (u.get("SecurityProfileIds") or []))
            for pid, name in outbound_profiles.items()
        }
        share = len(holders) / len(users) if users else 0.0
        evidence = {
            "outbound_calls_enabled": True,
            "user_count": len(users),
            "users_with_outbound_calling": len(holders),
            "share_with_outbound_calling": round(share, 3),
            "profiles_granting_outbound_calling": dict(sorted(per_profile.items())),
            "broad_threshold": _BROAD_OUTBOUND_SHARE,
            "source_failures": failures,
        }
        summary = (
            f"{len(holders)} of {len(users)} user(s) ({share:.0%}) can place outbound calls "
            f"through {len(outbound_profiles)} security profile(s)"
            + (f": {', '.join(sorted(per_profile))}" if per_profile else "")
        )

        if share > _BROAD_OUTBOUND_SHARE:
            return self.create_finding(
                status=CheckStatus.FAIL,
                description=(
                    f"On instance {instance.display_name}, {summary}. Outbound calling is "
                    "granted to most users rather than scoped to the agents who need it; "
                    "Connect's default Agent profile includes it."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Scope outbound calling to the users who need it.",
                    target_resources=sorted(per_profile),
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Remove 'Contact Control Panel (CCP) - Make outbound calls' "
                                "from broadly assigned profiles such as Agent."
                            ),
                            console_path="Connect admin website -> Users -> Security profiles",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Grant it through a dedicated outbound profile assigned only to "
                                "agents with an outbound role, and review that list regularly."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Security profile permissions for outbound communications",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/security-profile-outbound-communication.html",  # noqa: E501
                        ),
                        _FRAUD_PREVENTION_REF,
                    ],
                ),
                **common,
            )
        if failures:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    f"Skipped: {len(failures)} security profile permission read(s) failed, so "
                    "outbound calling scope could not be fully established."
                ),
                evidence={**evidence, "evidence_complete": False},
                **common,
            )
        return self.create_finding(
            status=CheckStatus.PASS,
            description=f"On instance {instance.display_name}, {summary}.",
            evidence=evidence,
            **common,
        )


# ---------------------------------------------------------------------------
# A4 — where outbound calls went
# ---------------------------------------------------------------------------

# E.164 country calling codes are prefix-free: 1 and 7 are one digit, the
# codes below are two digits, and every other code is three digits.
_TWO_DIGIT_CALLING_CODES = frozenset(
    "20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 "
    "60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98".split()
)

# Non-geographic codes repeatedly abused for toll fraud: Inmarsat (870),
# global mobile satellite (881), international networks (882, 883), and
# international premium-rate service (979).
HIGH_RISK_CALLING_CODES = {
    "870": "Inmarsat satellite",
    "881": "global mobile satellite service",
    "882": "international networks",
    "883": "international networks",
    "979": "international premium-rate service",
}

# Initiation methods where the destination is an outside number the instance
# dialed: agent-dialed (OUTBOUND), scheduled callbacks (the click-to-dial fraud
# vector), API-started, and EXTERNAL_OUTBOUND — an agent bringing an external
# participant onto a call through a quick connect or flow block.
#
# TRANSFER is deliberately excluded: AWS defines it as an agent-to-agent or
# agent-to-queue transfer, and its customer endpoint is the original caller,
# so an international inbound caller would be misreported as a destination.
_OUTBOUND_INITIATION_METHODS = ["OUTBOUND", "CALLBACK", "API", "EXTERNAL_OUTBOUND"]
_DESTINATION_LOOKBACK_DAYS = 14
_DESTINATION_SAMPLE_SIZE = 100

# North American Numbering Plan members other than the US and Canada. They
# share calling code +1 but are separate countries billed at international
# rates, and several (notably +1-876, +1-809, +1-284, +1-473, +1-649, +1-268)
# are frequent toll-fraud and one-ring-scam targets. US territories (+1-340,
# +1-670, +1-671, +1-684, +1-787, +1-939) are domestic and are not listed.
NANP_NON_US_CA_AREA_CODES = {
    "242": "Bahamas",
    "246": "Barbados",
    "264": "Anguilla",
    "268": "Antigua and Barbuda",
    "284": "British Virgin Islands",
    "345": "Cayman Islands",
    "441": "Bermuda",
    "473": "Grenada",
    "649": "Turks and Caicos Islands",
    "658": "Jamaica",
    "664": "Montserrat",
    "721": "Sint Maarten",
    "758": "Saint Lucia",
    "767": "Dominica",
    "784": "Saint Vincent and the Grenadines",
    "809": "Dominican Republic",
    "829": "Dominican Republic",
    "849": "Dominican Republic",
    "868": "Trinidad and Tobago",
    "869": "Saint Kitts and Nevis",
    "876": "Jamaica",
}


def calling_code(e164: str) -> Optional[str]:
    """Country calling code of an E.164 number, or None if it isn't one."""
    digits = (e164 or "").strip()
    if not digits.startswith("+"):
        return None
    digits = digits[1:]
    if not digits.isdigit():
        return None
    if digits[:1] in ("1", "7"):
        return digits[:1]
    if digits[:2] in _TWO_DIGIT_CALLING_CODES:
        return digits[:2]
    return digits[:3] or None


def destination_key(e164: str) -> Optional[str]:
    """Country identity of a number: its calling code, split within +1.

    ``+1`` is shared by the US, Canada and the Caribbean/Atlantic NANP
    members. Those members get their own key (``1-876``) so a Jamaican or
    Dominican number is not mistaken for a domestic call from a US or
    Canadian instance.
    """
    code = calling_code(e164)
    if code == "1":
        area = e164.strip()[2:5]
        if area in NANP_NON_US_CA_AREA_CODES:
            return f"1-{area}"
    return code


def _key_label(key: str) -> str:
    if key.startswith("1-"):
        return f"+{key} ({NANP_NON_US_CA_AREA_CODES[key[2:]]})"
    if key in HIGH_RISK_CALLING_CODES:
        return f"+{key} ({HIGH_RISK_CALLING_CODES[key]})"
    return f"+{key}"


class OutboundDestinationCheck(BaseCheck):
    """A4: did recent outbound calls go somewhere they should not?"""

    def __init__(self):
        super().__init__(
            check_id="sec-outbound-dest-001",
            name="Outbound Call Destination Review",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Samples recent agent-dialed, callback, API-started, and external-participant "
                "calls, and the instance's phone-number quick connects, and flags destinations "
                "outside the countries of the instance's own numbers or on non-geographic codes "
                "commonly used for toll fraud. The outbound country allowlist itself is managed "
                "by AWS and cannot be read through the API."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        common = {
            "resource_id": instance.instance_id,
            "resource_type": "ConnectInstance",
            "context": context,
        }
        skipped = _outbound_unknown(self, instance, common)
        if skipped:
            return skipped
        if not instance.outbound_calls_enabled:
            return self.create_finding(
                status=CheckStatus.NOT_APPLICABLE,
                description=f"Outbound calling is disabled on instance {instance.display_name}.",
                evidence={"outbound_calls_enabled": False},
                **common,
            )

        # Home destinations: the countries the instance holds numbers in.
        try:
            numbers = _paginate_connect(
                lambda **kw: _connect(
                    factory,
                    "list_phone_numbers_v2",
                    TargetArn=instance.instance_arn,
                    MaxResults=50,
                    **kw,
                ),
                "ListPhoneNumbersSummaryList",
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            raise
        home = sorted(
            {k for k in (destination_key(n.get("PhoneNumber", "")) for n in numbers) if k}
        )

        # Configured external destinations agents can transfer to, whether or
        # not anyone has dialed them yet. Names are recorded, numbers are not.
        quick_connect_keys: Dict[str, List[str]] = {}
        try:
            summaries = _paginate_connect(
                lambda **kw: _connect(
                    factory,
                    "list_quick_connects",
                    InstanceId=instance.instance_id,
                    QuickConnectTypes=["PHONE_NUMBER"],
                    MaxResults=1000,
                    **kw,
                ),
                "QuickConnectSummaryList",
            )
            for summary in summaries:
                detail = _connect(
                    factory,
                    "describe_quick_connect",
                    InstanceId=instance.instance_id,
                    QuickConnectId=summary["Id"],
                ).get("QuickConnect", {})
                config = (detail.get("QuickConnectConfig") or {}).get("PhoneConfig") or {}
                key = destination_key(config.get("PhoneNumber", ""))
                if key:
                    quick_connect_keys.setdefault(key, []).append(
                        detail.get("Name") or summary.get("Name") or summary["Id"]
                    )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(
                    context, "connect:ListQuickConnects, connect:DescribeQuickConnect"
                )
            raise

        end = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(second=0, microsecond=0)
        start = end - timedelta(days=_DESTINATION_LOOKBACK_DAYS)
        try:
            page = _connect(
                factory,
                "search_contacts",
                InstanceId=instance.instance_id,
                TimeRange={"Type": "INITIATION_TIMESTAMP", "StartTime": start, "EndTime": end},
                SearchCriteria={
                    "Channels": ["VOICE"],
                    "InitiationMethods": _OUTBOUND_INITIATION_METHODS,
                },
                Sort={"FieldName": "INITIATION_TIMESTAMP", "Order": "DESCENDING"},
                MaxResults=_DESTINATION_SAMPLE_SIZE,
            )
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:SearchContacts")
            raise
        contacts = page.get("Contacts") or []
        total = page.get("TotalCount", len(contacts))

        by_key: Dict[str, int] = {}
        by_method: Dict[str, int] = {}
        read_failures = 0  # DescribeContact errors: the sample is incomplete
        non_phone = 0  # VoIP, internal, or ARN endpoints: legitimately no number
        for contact in contacts:
            try:
                detail = _connect(
                    factory,
                    "describe_contact",
                    InstanceId=instance.instance_id,
                    ContactId=contact["Id"],
                ).get("Contact", {})
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(context, "connect:DescribeContact")
                read_failures += 1
                continue
            endpoint = detail.get("CustomerEndpoint") or {}
            # The number is reduced to its destination key here and never kept.
            key = (
                destination_key(endpoint.get("Address", ""))
                if endpoint.get("Type") == "TELEPHONE_NUMBER"
                else None
            )
            if key is None:
                non_phone += 1
                continue
            by_key[key] = by_key.get(key, 0) + 1
            method = detail.get("InitiationMethod") or contact.get("InitiationMethod") or "?"
            by_method[method] = by_method.get(method, 0) + 1

        def _flag(keys: Iterable[str]) -> Tuple[List[str], List[str]]:
            risky = sorted(k for k in keys if k in HIGH_RISK_CALLING_CODES)
            foreign = sorted(
                k for k in keys if home and k not in home and k not in HIGH_RISK_CALLING_CODES
            )
            return risky, foreign

        call_risky, call_foreign = _flag(by_key)
        qc_risky, qc_foreign = _flag(quick_connect_keys)
        evidence = {
            "outbound_calls_enabled": True,
            "lookback_days": _DESTINATION_LOOKBACK_DAYS,
            "initiation_methods_sampled": _OUTBOUND_INITIATION_METHODS,
            "outbound_contacts_in_window": total,
            "sampled_contacts": len(contacts),
            "destination_read_failures": read_failures,
            "non_telephone_endpoints": non_phone,
            "home_destinations": [_key_label(k) for k in home],
            "destinations_by_country": {_key_label(k): n for k, n in sorted(by_key.items())},
            "contacts_by_initiation_method": dict(sorted(by_method.items())),
            "quick_connect_destinations": {
                _key_label(k): sorted(v) for k, v in sorted(quick_connect_keys.items())
            },
            "country_allowlist_readable": False,
        }

        if call_risky or call_foreign or qc_risky or qc_foreign:
            parts = []
            if call_risky or call_foreign:
                parts.append(
                    f"of the {len(contacts)} most recent outbound calls ({total} in the last "
                    f"{_DESTINATION_LOOKBACK_DAYS} days), some went to "
                    + ", ".join(f"{_key_label(k)}: {by_key[k]}" for k in call_risky + call_foreign)
                )
            if qc_risky or qc_foreign:
                parts.append(
                    "phone-number quick connects point to "
                    + ", ".join(
                        f"{_key_label(k)} ({', '.join(sorted(quick_connect_keys[k]))})"
                        for k in qc_risky + qc_foreign
                    )
                )
            return self.create_finding(
                status=CheckStatus.FAIL,
                description=(
                    f"On instance {instance.display_name}, {'; and '.join(parts)}. These are "
                    "high-risk non-geographic codes or countries where the instance holds no "
                    "number. Confirm each is legitimate business; unexpected international or "
                    "premium-rate destinations are the signature of toll fraud."
                ),
                evidence=evidence,
                severity=Severity.HIGH if (call_risky or qc_risky) else Severity.MEDIUM,
                structured_remediation=Remediation(
                    summary="Verify unexpected outbound destinations and narrow the allowlist.",
                    target_resources=[instance.instance_id]
                    + sorted({n for k in qc_risky + qc_foreign for n in quick_connect_keys[k]}),
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Pull the contact records for the flagged destinations and "
                                "identify the agents, callbacks, API callers, or quick connects "
                                "behind them."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "If any were not legitimate, revoke the agent's sessions, reset "
                                "credentials, review the outbound permission scope, and remove "
                                "unneeded phone-number quick connects."
                            ),
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "Ask AWS Support to remove countries you do not call from the "
                                "instance's outbound allowlist; it is not configurable in the "
                                "console or API."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Countries you can call by default",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/country-code-allow-list.html",  # noqa: E501
                        ),
                        _FRAUD_PREVENTION_REF,
                    ],
                ),
                **common,
            )

        if read_failures:
            # A clean result on a partial sample would be a false PASS.
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    f"Skipped: {read_failures} of {len(contacts)} sampled outbound contact(s) "
                    f"from instance {instance.display_name} could not be read, so the "
                    "destination review is incomplete. No unexpected destination was seen in "
                    "the rest."
                ),
                evidence={**evidence, "evidence_complete": False},
                **common,
            )
        if not home and (by_key or quick_connect_keys):
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    f"Skipped: instance {instance.display_name} holds no phone numbers, so "
                    "outbound destinations cannot be compared with its home countries. No "
                    "high-risk non-geographic destination was seen."
                ),
                evidence={**evidence, "evidence_complete": False},
                **common,
            )
        if not contacts:
            description = (
                f"No outbound voice contacts were placed from instance {instance.display_name} "
                f"in the last {_DESTINATION_LOOKBACK_DAYS} days"
            )
        else:
            description = (
                f"All {sum(by_key.values())} readable outbound destination(s) among the "
                f"{len(contacts)} most recent calls from instance {instance.display_name} are in "
                "countries where it holds numbers"
            )
        description += (
            f", and none of its {sum(len(v) for v in quick_connect_keys.values())} phone-number "
            "quick connect(s) points to a high-risk or foreign destination. The outbound "
            "country allowlist is managed by AWS and cannot be read here."
        )
        return self.create_finding(
            status=CheckStatus.PASS, description=description, evidence=evidence, **common
        )


# ---------------------------------------------------------------------------
# A5 — would a fraud-driven cost spike alert anyone?
# ---------------------------------------------------------------------------

_TIMELY_FREQUENCIES = {"IMMEDIATE", "DAILY"}


def _monitor_covers_connect(monitor: Dict[str, Any], account_id: str) -> bool:
    """Whether a Cost Anomaly Detection monitor sees Amazon Connect spend.

    Dimensional SERVICE and LINKED_ACCOUNT monitors cover every service.
    A custom monitor counts when its expression names Amazon Connect or this
    account. Tag and cost-category monitors are not counted: they only see
    spend that carries the matching tag or category.
    """
    if monitor.get("MonitorType") == "DIMENSIONAL":
        return monitor.get("MonitorDimension") in ("SERVICE", "LINKED_ACCOUNT")
    spec = json.dumps(monitor.get("MonitorSpecification") or {})
    return "Amazon Connect" in spec or (bool(account_id) and account_id in spec)


def _partition_from_arn(arn: str) -> str:
    parts = (arn or "").split(":")
    return parts[1] if len(parts) > 1 and parts[1] else "aws"


def _billing_region(service: str, partition: str) -> Optional[str]:
    """Signing region of a partition-global billing service, or None if absent.

    Cost Explorer and Budgets are global per partition: us-east-1 in the
    standard partition, cn-northwest-1 in China, and absent in AWS GovCloud
    (US), whose billing lives in the associated standard account. Read from
    botocore's endpoint data rather than hardcoded.
    """
    import botocore.session

    data = botocore.session.get_session().get_data("endpoints")
    for entry in data.get("partitions", []):
        if entry.get("partition") != partition:
            continue
        svc = entry.get("services", {}).get(service)
        if not svc:
            return None
        endpoints = svc.get("endpoints", {})
        name = svc.get("partitionEndpoint") or next(iter(endpoints), None)
        if not name:
            return None
        return (endpoints.get(name, {}).get("credentialScope") or {}).get("region") or name
    return None


def _budget_covers_connect(budget: Dict[str, Any]) -> bool:
    """Connect-filtered budget, defined either way the Budgets API allows.

    Budgets carry the legacy ``CostFilters`` map or the newer
    ``FilterExpression``; checking only one would miss the other and report
    a Connect budget as absent.
    """
    services = (budget.get("CostFilters") or {}).get("Service") or []
    if any("Amazon Connect" in s for s in services):
        return True
    return "Amazon Connect" in json.dumps(budget.get("FilterExpression") or {})


class FraudCostAlertingCheck(BaseCheck):
    """A5: would a sudden rise in Amazon Connect spend alert someone quickly?"""

    def __init__(self):
        super().__init__(
            check_id="sec-fraud-alerting-001",
            name="Toll-Fraud Cost Alerting",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks for an AWS Cost Anomaly Detection monitor covering Amazon Connect "
                "with a daily or immediate alert, or a Connect-filtered AWS Budget. Toll "
                "fraud is expensive in proportion to how long it runs unnoticed."
            ),
        )
        self._locks_guard = threading.Lock()
        self._locks: Dict[Tuple[str, str], threading.Lock] = {}
        self._by_account: Dict[Tuple[str, str], Tuple[Dict[str, Any], List[str], List[str]]] = {}

    def _collect(self, factory, partition: str, account_id: str):
        """Account-level evidence, fetched once per account per run.

        The lock is per account: instances of the same account wait for the
        one fetch already in flight (rather than each repeating it), and other
        accounts are never blocked.
        """
        key = (partition, account_id)
        with self._locks_guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._by_account:
                self._by_account[key] = self._fetch(factory, partition, account_id)
            return self._by_account[key]

    @staticmethod
    def _fetch(factory, partition: str, account_id: str):
        denied: List[str] = []
        failures: List[str] = []

        def _client(service: str):
            region = _billing_region(service, partition)
            try:
                return factory.get_client(service, region_name=region)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{service} client: {_error_code(e) or type(e).__name__}")
                return None

        def _pages(client, service, op, key, permission, token_in, token_out, **base):
            items: List[Dict[str, Any]] = []
            token: Optional[str] = None
            try:
                for _ in range(50):
                    kwargs = {**base, **({token_in: token} if token else {})}
                    resp = factory.call_api_with_resilience(client, op, service, **kwargs)
                    items.extend(resp.get(key) or [])
                    token = resp.get(token_out)
                    if not token:
                        break
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    denied.append(permission)
                else:
                    failures.append(f"{op}: {_error_code(e) or type(e).__name__}")
            return items

        ce_client = _client("ce")
        monitors: List[Dict[str, Any]] = []
        subscriptions: List[Dict[str, Any]] = []
        if ce_client is not None:
            monitors = _pages(
                ce_client,
                "ce",
                "get_anomaly_monitors",
                "AnomalyMonitors",
                "ce:GetAnomalyMonitors",
                "NextPageToken",
                "NextPageToken",
            )
            subscriptions = _pages(
                ce_client,
                "ce",
                "get_anomaly_subscriptions",
                "AnomalySubscriptions",
                "ce:GetAnomalySubscriptions",
                "NextPageToken",
                "NextPageToken",
            )
        covering = {m["MonitorArn"] for m in monitors if _monitor_covers_connect(m, account_id)}
        covering_subs = [
            s for s in subscriptions if covering.intersection(s.get("MonitorArnList") or [])
        ]

        budgets_client = _client("budgets")
        budgets: List[Dict[str, Any]] = []
        notified: Dict[str, int] = {}
        if budgets_client is not None:
            budgets = _pages(
                budgets_client,
                "budgets",
                "describe_budgets",
                "Budgets",
                "budgets:ViewBudget",
                "NextToken",
                "NextToken",
                AccountId=account_id,
            )
            # A budget alerts no one without a notification; one account-wide
            # call returns them for every budget.
            if any(_budget_covers_connect(b) for b in budgets):
                for item in _pages(
                    budgets_client,
                    "budgets",
                    "describe_budget_notifications_for_account",
                    "BudgetNotificationsForAccount",
                    "budgets:ViewBudget",
                    "NextToken",
                    "NextToken",
                    AccountId=account_id,
                ):
                    notified[item.get("BudgetName", "")] = len(item.get("Notifications") or [])
        connect_budgets = [b for b in budgets if _budget_covers_connect(b)]

        evidence = {
            "anomaly_monitors": len(monitors),
            "monitors_covering_connect": len(covering),
            "alert_frequencies_for_connect": sorted(
                {s.get("Frequency", "") for s in covering_subs}
            ),
            # Recorded, not judged: a high threshold still alerts.
            "alert_thresholds_for_connect": [
                {
                    "frequency": s.get("Frequency"),
                    "threshold": s.get("Threshold"),
                    "threshold_expression": s.get("ThresholdExpression"),
                }
                for s in sorted(covering_subs, key=lambda s: s.get("SubscriptionArn", ""))
            ],
            "connect_budgets": sorted(
                b.get("BudgetName", "")
                for b in connect_budgets
                if notified.get(b.get("BudgetName", ""), 0) > 0
            ),
            "connect_budgets_without_alerts": sorted(
                b.get("BudgetName", "")
                for b in connect_budgets
                if notified.get(b.get("BudgetName", ""), 0) == 0
            ),
        }
        return evidence, sorted(set(denied)), failures

    def execute(self, context: CheckContext):
        instance = context.instance
        account_id = _account_id_from_arn(instance.instance_arn)
        partition = _partition_from_arn(instance.instance_arn)
        common = {
            "resource_id": instance.instance_id,
            "resource_type": "ConnectInstance",
            "context": context,
        }
        unavailable = [s for s in ("ce", "budgets") if _billing_region(s, partition) is None]
        if unavailable:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    f"Skipped: Cost Explorer and AWS Budgets are not available in the {partition} "
                    "partition. For AWS GovCloud (US), billing and cost alerting are managed from "
                    "the associated standard AWS account; run this control there."
                ),
                evidence={"partition": partition, "evidence_complete": False},
                **common,
            )
        evidence, denied, failures = self._collect(
            context.aws_client_factory, partition, account_id
        )
        evidence = {**evidence, "denied_permissions": denied, "source_failures": failures}
        timely = set(evidence["alert_frequencies_for_connect"]) & _TIMELY_FREQUENCIES
        if timely or evidence["connect_budgets"]:
            how = []
            if timely:
                how.append(f"a {'/'.join(sorted(timely)).lower()} cost anomaly alert")
            if evidence["connect_budgets"]:
                how.append(f"Connect budget(s) {', '.join(evidence['connect_budgets'])}")
            return self.create_finding(
                status=CheckStatus.PASS,
                description=(
                    "A sudden rise in Amazon Connect spend would raise " + " and ".join(how) + "."
                ),
                evidence=evidence,
                **common,
            )
        # Absence can only be claimed when every source was actually read:
        # either missing signal could be the one that alerts.
        if denied:
            return self.skipped_for_access_denied(context, ", ".join(sorted(set(denied))))
        if failures:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    "Skipped: cost alerting could not be fully read (" + "; ".join(failures) + ")."
                ),
                evidence={**evidence, "evidence_complete": False},
                **common,
            )

        org_note = (
            " If this account belongs to an AWS Organization, monitors in the management "
            "account are not visible here; confirm there before acting."
        )
        if evidence["monitors_covering_connect"]:
            frequencies = evidence["alert_frequencies_for_connect"]
            gap = (
                "Amazon Connect spend is monitored, but alerts are only sent weekly, so a "
                "toll-fraud run can last up to a week before anyone is told"
                if frequencies
                else "Amazon Connect spend is monitored, but no alert subscription is attached, "
                "so a detected anomaly notifies no one"
            )
            severity = Severity.MEDIUM
        else:
            gap = (
                "no Cost Anomaly Detection monitor or AWS Budget covers Amazon Connect spend, "
                "so a fraud-driven cost spike would surface only on the bill"
            )
            severity = Severity.HIGH
        if evidence["connect_budgets_without_alerts"]:
            gap += (
                "; Connect budget(s) "
                + ", ".join(evidence["connect_budgets_without_alerts"])
                + " have no notifications, so they alert no one"
            )
        return self.create_finding(
            status=CheckStatus.FAIL,
            description=gap[:1].upper() + gap[1:] + "." + org_note,
            evidence=evidence,
            severity=severity,
            structured_remediation=Remediation(
                summary="Alert on abnormal Amazon Connect spend within a day.",
                target_resources=[account_id or instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "In Cost Anomaly Detection, use an AWS services monitor (or a "
                            "custom monitor for Amazon Connect) and attach an IMMEDIATE or "
                            "DAILY alert subscription with a low dollar threshold."
                        ),
                        console_path="Billing and Cost Management -> Cost Anomaly Detection",
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Add an AWS Budget filtered to the Amazon Connect service with "
                            "actual and forecasted alerts, as a second, threshold-based signal."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Detecting unusual spend with AWS Cost Anomaly Detection",
                        url="https://docs.aws.amazon.com/cost-management/latest/userguide/manage-ad.html",
                    ),
                    _FRAUD_PREVENTION_REF,
                ],
            ),
            **common,
        )


def register_telephony_fraud_checks(registry) -> None:
    """Register the toll-fraud controls with the given registry."""
    for check in all_telephony_fraud_checks():
        registry.register_check(check)


def all_telephony_fraud_checks() -> Iterable[BaseCheck]:
    return [
        IpAccessControlCheck(),
        OutboundPermissionScopeCheck(),
        OutboundDestinationCheck(),
        FraudCostAlertingCheck(),
    ]


__all__ = [
    "FraudCostAlertingCheck",
    "HIGH_RISK_CALLING_CODES",
    "IpAccessControlCheck",
    "OUTBOUND_CALL_PERMISSION",
    "OutboundDestinationCheck",
    "OutboundPermissionScopeCheck",
    "all_telephony_fraud_checks",
    "register_telephony_fraud_checks",
    "calling_code",
]
