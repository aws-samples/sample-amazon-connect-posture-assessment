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
        # A stolen login is a toll-fraud path only when the instance can dial out.
        severity = Severity.HIGH if instance.outbound_calls_enabled else Severity.MEDIUM
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
        restricted_others = [
            p.get("Name") or "" for p in profiles if not p.get("IsDefault") and p.get("AllowedIps")
        ]

        if default and default.get("AllowedIps"):
            return self.create_finding(
                status=CheckStatus.PASS,
                description=(
                    f"Instance {instance.display_name}'s default authentication profile "
                    f"allows sign-in only from {len(default['AllowedIps'])} approved IP "
                    "range(s)."
                ),
                evidence=evidence,
                **common,
            )

        if default and default.get("BlockedIps"):
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

        holders = [
            u for u in users if set(u.get("SecurityProfileIds") or []) & set(outbound_profiles)
        ]
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

# Initiation methods where the instance chose the destination: agent-dialed,
# scheduled callbacks (the click-to-dial fraud vector), and API-started.
_OUTBOUND_INITIATION_METHODS = ["OUTBOUND", "CALLBACK", "API"]
_DESTINATION_LOOKBACK_DAYS = 14
_DESTINATION_SAMPLE_SIZE = 100


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


class OutboundDestinationCheck(BaseCheck):
    """A4: did recent outbound calls go somewhere they should not?"""

    def __init__(self):
        super().__init__(
            check_id="sec-outbound-dest-001",
            name="Outbound Call Destination Review",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Samples recent agent-dialed, callback, and API-started outbound calls and "
                "flags destinations outside the countries of the instance's own numbers, or "
                "on non-geographic codes commonly used for toll fraud. The outbound country "
                "allowlist itself is managed by AWS and cannot be read through the API."
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
        if not instance.outbound_calls_enabled:
            return self.create_finding(
                status=CheckStatus.NOT_APPLICABLE,
                description=f"Outbound calling is disabled on instance {instance.display_name}.",
                evidence={"outbound_calls_enabled": False},
                **common,
            )

        # Home calling codes: the countries the instance holds numbers in.
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
        home = sorted({c for c in (calling_code(n.get("PhoneNumber", "")) for n in numbers) if c})

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

        by_code: Dict[str, int] = {}
        by_method: Dict[str, int] = {}
        unreadable = 0
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
                unreadable += 1
                continue
            endpoint = detail.get("CustomerEndpoint") or {}
            # The number is reduced to its calling code here and never kept.
            code = (
                calling_code(endpoint.get("Address", ""))
                if endpoint.get("Type") == "TELEPHONE_NUMBER"
                else None
            )
            if code is None:
                unreadable += 1
                continue
            by_code[code] = by_code.get(code, 0) + 1
            method = detail.get("InitiationMethod") or contact.get("InitiationMethod") or "?"
            by_method[method] = by_method.get(method, 0) + 1

        high_risk = {c: n for c, n in by_code.items() if c in HIGH_RISK_CALLING_CODES}
        foreign = {
            c: n for c, n in by_code.items() if home and c not in home and c not in high_risk
        }
        evidence = {
            "outbound_calls_enabled": True,
            "lookback_days": _DESTINATION_LOOKBACK_DAYS,
            "outbound_contacts_in_window": total,
            "sampled_contacts": len(contacts),
            "unreadable_destinations": unreadable,
            "home_calling_codes": [f"+{c}" for c in home],
            "destinations_by_calling_code": {f"+{c}": n for c, n in sorted(by_code.items())},
            "contacts_by_initiation_method": dict(sorted(by_method.items())),
            "country_allowlist_readable": False,
        }

        if not contacts:
            return self.create_finding(
                status=CheckStatus.PASS,
                description=(
                    f"No outbound voice contacts were placed from instance "
                    f"{instance.display_name} in the last {_DESTINATION_LOOKBACK_DAYS} days. The "
                    "outbound country allowlist is managed by AWS and cannot be read here."
                ),
                evidence=evidence,
                **common,
            )

        if high_risk or foreign:
            parts = []
            if high_risk:
                parts.append(
                    "high-risk non-geographic codes "
                    + ", ".join(
                        f"+{c} ({HIGH_RISK_CALLING_CODES[c]}): {n}"
                        for c, n in sorted(high_risk.items())
                    )
                )
            if foreign:
                parts.append(
                    "countries where the instance holds no number "
                    + ", ".join(f"+{c}: {n}" for c, n in sorted(foreign.items()))
                )
            return self.create_finding(
                status=CheckStatus.FAIL,
                description=(
                    f"Of the {len(contacts)} most recent outbound calls from instance "
                    f"{instance.display_name} ({total} in the last {_DESTINATION_LOOKBACK_DAYS} "
                    f"days), some went to {'; and '.join(parts)}. Confirm each destination is "
                    "legitimate business; unexpected international or premium-rate calls are "
                    "the signature of toll fraud."
                ),
                evidence=evidence,
                severity=Severity.HIGH if high_risk else Severity.MEDIUM,
                structured_remediation=Remediation(
                    summary="Verify unexpected outbound destinations and narrow the allowlist.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Pull the contact records for the flagged calling codes and "
                                "identify the agents, callbacks, or API callers behind them."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "If any were not legitimate, revoke the agent's sessions, reset "
                                "credentials, and review the outbound permission scope."
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

        if not home:
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
        return self.create_finding(
            status=CheckStatus.PASS,
            description=(
                f"All {sum(by_code.values())} readable outbound destination(s) among the "
                f"{len(contacts)} most recent calls from instance {instance.display_name} are "
                "in countries where it holds numbers. The outbound country allowlist is managed "
                "by AWS and cannot be read here."
            ),
            evidence=evidence,
            **common,
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


def _budget_covers_connect(budget: Dict[str, Any]) -> bool:
    services = (budget.get("CostFilters") or {}).get("Service") or []
    return any("Amazon Connect" in s for s in services)


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
        self._lock = threading.Lock()
        self._by_account: Dict[str, Tuple[Dict[str, Any], List[str], List[str]]] = {}

    def _collect(self, factory, account_id: str):
        """Account-level evidence, fetched once per account per run."""
        with self._lock:
            if account_id in self._by_account:
                return self._by_account[account_id]
            evidence: Dict[str, Any] = {}
            denied: List[str] = []
            failures: List[str] = []

            ce = factory.get_client("ce", region_name="us-east-1")
            monitors: List[Dict[str, Any]] = []
            subscriptions: List[Dict[str, Any]] = []
            for op, key, sink in (
                ("get_anomaly_monitors", "AnomalyMonitors", monitors),
                ("get_anomaly_subscriptions", "AnomalySubscriptions", subscriptions),
            ):
                token: Optional[str] = None
                try:
                    for _ in range(50):
                        resp = factory.call_api_with_resilience(
                            ce, op, "ce", **({"NextPageToken": token} if token else {})
                        )
                        sink.extend(resp.get(key) or [])
                        token = resp.get("NextPageToken")
                        if not token:
                            break
                except Exception as e:  # noqa: BLE001
                    if factory.is_access_denied(e):
                        denied.append(
                            "ce:GetAnomalyMonitors"
                            if op == "get_anomaly_monitors"
                            else "ce:GetAnomalySubscriptions"
                        )
                    else:
                        failures.append(f"{op}: {_error_code(e) or type(e).__name__}")

            covering = {m["MonitorArn"] for m in monitors if _monitor_covers_connect(m, account_id)}
            frequencies = sorted(
                {
                    s.get("Frequency", "")
                    for s in subscriptions
                    if covering & set(s.get("MonitorArnList") or [])
                }
            )

            budgets: List[Dict[str, Any]] = []
            try:
                client = factory.get_client("budgets", region_name="us-east-1")
                token = None
                for _ in range(50):
                    kwargs: Dict[str, Any] = {"AccountId": account_id}
                    if token:
                        kwargs["NextToken"] = token
                    resp = factory.call_api_with_resilience(
                        client, "describe_budgets", "budgets", **kwargs
                    )
                    budgets.extend(resp.get("Budgets") or [])
                    token = resp.get("NextToken")
                    if not token:
                        break
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    denied.append("budgets:ViewBudget")
                else:
                    failures.append(f"describe_budgets: {_error_code(e) or type(e).__name__}")

            evidence.update(
                {
                    "anomaly_monitors": len(monitors),
                    "monitors_covering_connect": len(covering),
                    "alert_frequencies_for_connect": frequencies,
                    "connect_budgets": sorted(
                        b.get("BudgetName", "") for b in budgets if _budget_covers_connect(b)
                    ),
                }
            )
            self._by_account[account_id] = (evidence, denied, failures)
            return self._by_account[account_id]

    def execute(self, context: CheckContext):
        instance = context.instance
        account_id = _account_id_from_arn(instance.instance_arn)
        evidence, denied, failures = self._collect(context.aws_client_factory, account_id)
        evidence = {**evidence, "denied_permissions": denied, "source_failures": failures}
        common = {
            "resource_id": instance.instance_id,
            "resource_type": "ConnectInstance",
            "context": context,
        }
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
        # Absence can only be claimed when monitors were actually readable.
        monitors_unreadable = any(d.startswith("ce:") for d in denied) or any(
            f.startswith("get_anomaly") for f in failures
        )
        if monitors_unreadable and any(d.startswith("ce:") for d in denied):
            return self.skipped_for_access_denied(context, ", ".join(denied))
        if monitors_unreadable:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                description=(
                    "Skipped: cost alerting could not be read (" + "; ".join(failures) + ")."
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
