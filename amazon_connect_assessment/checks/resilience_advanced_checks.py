"""
Advanced resilience checks (Phase 3 / Task 7).

Deep-inspection checks for Connect resilience posture:

- res-acgr-config-001         : ACGR configuration discovery (informational)
- res-acgr-identity-001       : SAML identity required for ACGR agent failover
- res-acgr-tdg-status-001     : Traffic distribution group in ACTIVE status
- res-acgr-traffic-dist-001   : ACGR traffic distribution inventory
- res-acgr-failover-test-001  : Failover tested in the last 90 days
- res-acgr-numbers-001        : Phone numbers claimed against the TDG
- res-cloudwatch-001          : CloudWatch alarm coverage for critical metrics
- res-carrier-diversity-001   : Phone number carrier/country diversity
- res-hardcoded-routing-001   : Hardcoded routing values in contact flows

ACGR design note: the six res-acgr-* checks exist as a set because a
half-configured ACGR is worse than no ACGR — customers believe they have
DR and don't. `res-acgr-config-001` is the discovery probe: it always
returns PASS, records whether a TDG is present, and (per product decision)
never nags customers who don't need ACGR (~95% of deployments). The five
audit sub-checks each short-circuit to NOT_APPLICABLE when no TDG exists,
so they stay silent on those instances and only fire real findings when
ACGR is on and misconfigured.

Each check degrades to SKIPPED on AccessDenied and emits evidence-specific
structured remediation.
"""

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FindingDisposition,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser, is_default_sample_flow, reachable_from_entry
from .base import BaseCheck, CheckContext
from .security_deep_checks import _error_code

_PARSER = ContactFlowParser()

# Bounded page pull, mirroring engine.py's _list_phone_numbers_for_instance:
# 20 pages * 100 per page = 2000 numbers, comfortably above any single
# instance's or TDG's real phone number count while still bounding worst
# case API calls.
_MAX_PHONE_NUMBER_PAGES = 20
_PHONE_NUMBER_PAGE_SIZE = 100


def _list_all_phone_numbers(factory, target_arn: str) -> List[Dict[str, Any]]:
    """
    Paginate ``connect:ListPhoneNumbersV2`` for a single TargetArn (an
    instance ARN or a traffic distribution group ARN) and return every
    claimed number.

    A single unpaginated call with ``MaxResults=50`` silently truncates
    deployments with more than 50 numbers bound to a given target,
    undercounting (or in the worst case, zeroing out) the "numbers on
    this TDG" evidence used by ACGRPhoneNumberBindingCheck. Raises on
    error so callers can distinguish AccessDenied from "no numbers".
    """
    all_numbers: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    for _ in range(_MAX_PHONE_NUMBER_PAGES):
        kwargs: Dict[str, Any] = {
            "TargetArn": target_arn,
            "MaxResults": _PHONE_NUMBER_PAGE_SIZE,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            factory.get_connect_client(),
            "list_phone_numbers_v2",
            "connect",
            **kwargs,
        )
        all_numbers.extend(resp.get("ListPhoneNumbersSummaryList") or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return all_numbers


# Required instance-level voice metrics for this alarm-coverage control.
_REQUIRED_ALARM_METRICS = [
    "ConcurrentCalls",
    "ThrottledCalls",
    "MissedCalls",
    "CallsPerInterval",
]
_REQUIRED_ALARM_DIMENSIONS = {
    "InstanceId": None,
    "MetricGroup": "VoiceCalls",
}
_CLOUDWATCH_ALARM_PAGE_SIZE = 100
_MAX_CLOUDWATCH_ALARM_PAGES = 100

# CloudTrail pagination stays bounded in case a service or mock repeats tokens.
_CLOUDTRAIL_EVENT_PAGE_SIZE = 50
_MAX_CLOUDTRAIL_EVENT_PAGES = 100

# Transfer action types to check for hardcoded routing.
_ROUTING_ACTION_TYPES = {
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
    "TransferToQueue",
    "TransferContactToQueue",
    "TransferToFlow",
    "TransferContactToFlow",
}

# ACGR identity requirement: only SAML supports agent Global Sign-in
# across the paired regions. CONNECT_MANAGED and EXISTING_DIRECTORY do not.
_ACGR_ELIGIBLE_IDENTITY_TYPES = {"SAML"}

# CloudTrail lookback window for the failover-tested probe.
_FAILOVER_TEST_LOOKBACK_DAYS = 90


# ---------------------------------------------------------------------------
# ACGR context cache
#
# Six checks in this module all need the same TDG data. Rather than each
# check re-issuing list/describe/get calls, we memoize per instance the
# first time any ACGR check runs. The cache is keyed by instance_id and
# guarded by a lock because ParallelAssessmentEngine executes checks in a
# thread pool. Each field is Optional — we track separately whether the
# fetch succeeded, was denied, or has not been attempted, so downstream
# checks can degrade to SKIPPED individually rather than the whole set.
# ---------------------------------------------------------------------------


@dataclass
class _ACGRContext:
    """Cached ACGR-related API results for a single Connect instance."""

    tdgs: List[Dict[str, Any]] = field(default_factory=list)
    tdgs_denied: bool = False
    tdgs_error: bool = False
    tdgs_denied_permission: str = "connect:ListTrafficDistributionGroups"
    # Per-TDG details, keyed by TDG Id.
    tdg_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tdg_details_denied: bool = False
    tdg_detail_error_ids: List[str] = field(default_factory=list)
    tdg_details_denied_permission: str = "connect:DescribeTrafficDistributionGroup"
    # Traffic distribution per TDG, keyed by TDG Id.
    traffic_distributions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    traffic_denied: bool = False
    traffic_error_ids: List[str] = field(default_factory=list)
    traffic_denied_permission: str = "connect:GetTrafficDistribution"
    # True once every fetch step below has run to completion (successfully
    # or via a recorded denial) — distinguishes a fully-populated context
    # from a bare placeholder. Only contexts with fetch_complete=True are
    # ever placed into _acgr_cache; see _get_acgr_context.
    fetch_complete: bool = False


_acgr_cache: Dict[str, _ACGRContext] = {}
_acgr_cache_lock = threading.Lock()

# Per-instance locks used to serialize the *fetch* of ACGR data (not just
# the cache insertion). See _get_acgr_context for why a single global lock
# isn't sufficient here.
_acgr_fetch_locks: Dict[str, threading.Lock] = {}
_acgr_fetch_locks_guard = threading.Lock()


def _reset_acgr_cache() -> None:
    """Clear the ACGR cache and per-instance fetch locks. Called from tests to isolate cases."""
    with _acgr_cache_lock:
        _acgr_cache.clear()
    with _acgr_fetch_locks_guard:
        _acgr_fetch_locks.clear()


def _get_acgr_context(context: CheckContext) -> _ACGRContext:
    """
    Return a memoized ``_ACGRContext`` for this instance.

    The first ACGR check that runs for a given instance fetches all the
    ACGR-related API data once; subsequent checks reuse it. Errors are
    recorded on the context per-field so downstream checks can decide
    whether to skip or continue on their own.

    Concurrency note: under the parallel engine, multiple ACGR checks for
    the *same instance* can be scheduled onto different worker threads at
    roughly the same time. The original implementation inserted an empty
    ``_ACGRContext`` into ``_acgr_cache`` under the lock, released the
    lock, and *then* made the slow API calls to fill it in. A second
    thread arriving in that window found the (still-empty) cached context,
    read ``ctx.tdgs == []``, and concluded "ACGR not configured" — even
    though the first thread's fetch was still in flight and would have
    found real traffic distribution groups. That's a silent false
    negative on a real DR misconfiguration, and it was also an
    unsynchronized read/write race on the dataclass fields themselves.

    Fixed by giving each instance its own fetch lock: the winning thread
    holds that lock for the entire fetch (list + describe + traffic-dist
    calls), and any other thread for the same instance blocks until the
    fetch is complete and then returns the *fully populated* context —
    never a half-filled one. Different instances still fetch fully in
    parallel (separate per-instance locks), so this doesn't serialize the
    whole assessment, just concurrent ACGR checks on one instance.
    """
    instance = context.instance
    instance_id = instance.instance_id

    with _acgr_cache_lock:
        cached = _acgr_cache.get(instance_id)
        if cached is not None:
            return cached
        # Get (or create) this instance's dedicated fetch lock while still
        # holding the cache lock, so two threads can't each create their
        # own separate lock for the same instance_id.
        with _acgr_fetch_locks_guard:
            fetch_lock = _acgr_fetch_locks.setdefault(instance_id, threading.Lock())

    # Acquire the per-instance fetch lock OUTSIDE _acgr_cache_lock so other
    # instances' cache lookups aren't blocked while this instance's fetch
    # is in flight.
    with fetch_lock:
        # Re-check the cache: another thread may have finished the fetch
        # and populated it while we were waiting for fetch_lock.
        with _acgr_cache_lock:
            cached = _acgr_cache.get(instance_id)
            if cached is not None and cached.fetch_complete:
                return cached

        ctx = _ACGRContext()
        factory = context.aws_client_factory

        # Step 1: list TDGs.
        try:
            next_token: Optional[str] = None
            seen_tokens: set = set()
            while True:
                kwargs: Dict[str, Any] = {"MaxResults": 10}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = factory.call_api_with_resilience(
                    factory.get_connect_client(),
                    "list_traffic_distribution_groups",
                    "connect",
                    InstanceId=instance_id,
                    **kwargs,
                )
                ctx.tdgs.extend(resp.get("TrafficDistributionGroupSummaryList", []) or [])
                next_token = resp.get("NextToken")
                if not next_token:
                    break
                if next_token in seen_tokens:
                    raise ValueError("ListTrafficDistributionGroups returned a repeated NextToken")
                seen_tokens.add(next_token)
        except Exception as e:
            if factory.is_access_denied(e):
                ctx.tdgs_denied = True
            else:
                ctx.tdgs_error = True

        if ctx.tdgs:
            # Step 2: describe each TDG (Status field lives here).
            for tdg in ctx.tdgs:
                tdg_id = tdg.get("Id")
                if not tdg_id:
                    continue
                try:
                    resp = factory.call_api_with_resilience(
                        factory.get_connect_client(),
                        "describe_traffic_distribution_group",
                        "connect",
                        TrafficDistributionGroupId=tdg_id,
                    )
                    ctx.tdg_details[tdg_id] = resp.get("TrafficDistributionGroup", {}) or {}
                except Exception as e:
                    if factory.is_access_denied(e):
                        ctx.tdg_details_denied = True
                        break
                    ctx.tdg_detail_error_ids.append(tdg_id)

            # Step 3: get_traffic_distribution for each TDG.
            for tdg in ctx.tdgs:
                tdg_id = tdg.get("Id")
                if not tdg_id:
                    continue
                try:
                    resp = factory.call_api_with_resilience(
                        factory.get_connect_client(),
                        "get_traffic_distribution",
                        "connect",
                        Id=tdg_id,
                    )
                    ctx.traffic_distributions[tdg_id] = resp
                except Exception as e:
                    if factory.is_access_denied(e):
                        ctx.traffic_denied = True
                        break
                    ctx.traffic_error_ids.append(tdg_id)

        ctx.fetch_complete = True
        with _acgr_cache_lock:
            _acgr_cache[instance_id] = ctx
        return ctx


def _tdg_discovery_incomplete(check: BaseCheck, context: CheckContext):
    """SKIPPED finding for a failed ListTrafficDistributionGroups (never 'not configured')."""
    return check.create_finding(
        status=CheckStatus.SKIPPED,
        resource_id=context.instance.instance_id,
        resource_type="ConnectInstance",
        description=(
            "Skipped: traffic distribution group discovery did not complete, so "
            "ACGR applicability cannot be determined."
        ),
        evidence={"evidence_complete": False, "discovery_error": True},
        context=context,
    )


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _is_dynamic_reference(value) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith("$.") or value.startswith("$[")


def _mask_phone(number: str) -> str:
    """Partially mask a phone number for evidence (show last 4 digits)."""
    if not number or len(number) < 5:
        return number or ""
    return "***" + number[-4:]


def _instance_name(instance) -> str:
    """Return a human-friendly name.

    Thin wrapper around :attr:`ConnectInstance.display_name` — kept only so
    downstream call sites don't have to change all at once. New code should
    use ``instance.display_name`` directly.
    """
    return instance.display_name


# ---------------------------------------------------------------------------
# ACGR check set
#
# Together these six checks answer:
#   1. Is ACGR configured at all? (discovery — informational only)
#   2..6. If it is, is it configured correctly? (audit — HIGH severity)
#
# Customers who don't have ACGR (~95%) see only check #1 and no findings —
# by product decision we do not call ACGR absence out as a deficiency.
# Customers who do have ACGR see the audit checks light up any gaps.
# ---------------------------------------------------------------------------


_ACGR_DOCS_URL = (
    "https://docs.aws.amazon.com/connect/latest/adminguide/setup-connect-global-resiliency.html"
)

_ACGR_REALITY_CHECK = (
    "**Before treating any `res-acgr-*` finding as a quick fix:** ACGR is "
    "not a self-service toggle, it requires ongoing replica capacity, and "
    "it does not automatically replicate every dependency. Lex resiliency, "
    "matching Lambda deployments, region-aware resource references, Customer "
    "Profiles, Cases, and S3 recording storage require separate review and "
    "configuration."
)


class ACGRConfigurationCheck(BaseCheck):
    """Discover whether ACGR is configured; always informational."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-config-001",
            name="Amazon Connect Global Resiliency Configuration",
            pillar=Pillar.RESILIENCE,
            # Discovery-only. This never fails, and doesn't nag customers who
            # don't need Regional resilience (roughly 95% of deployments).
            severity=Severity.LOW,
            description=(
                "Reports whether the Connect instance is associated with a "
                "traffic distribution group (Amazon Connect Global Resiliency). "
                "ACGR is an optional capability for Regional (cross-region) "
                "resilience and is not required for every deployment. When "
                "ACGR is configured, the res-acgr-* audit checks verify it "
                "is set up per AWS guidance."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return _tdg_discovery_incomplete(self, context)

        evidence: Dict[str, Any] = {
            "traffic_distribution_groups": len(acgr.tdgs),
            "instance_id": instance.instance_id,
        }

        if not acgr.tdgs:
            # ACGR absence is not a deficiency — it's an architectural choice
            # that ~95% of deployments legitimately don't need. Emit
            # NOT_APPLICABLE so instances without ACGR see nothing about
            # ACGR at all in the report (the audit sub-checks
            # res-acgr-identity-001, res-acgr-tdg-status-001, etc. do the
            # same). Users who want to know whether their instance has
            # ACGR configured can check the evidence dict.
            return self.not_applicable(
                context,
                reason=(
                    "Amazon Connect Global Resiliency (ACGR) is not configured "
                    "on this instance. ACGR is an optional cross-region "
                    "resilience capability and is not required for every "
                    "deployment; if this workload does need Regional "
                    "resilience, engage your AWS account team — ACGR is not "
                    "a self-service configuration."
                ),
                evidence=evidence,
            )

        evidence["tdg_names"] = [t.get("Name") for t in acgr.tdgs]
        evidence["tdg_ids"] = [t.get("Id") for t in acgr.tdgs]
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Amazon Connect Global Resiliency (ACGR) is configured for "
                f"instance {_instance_name(instance)} with {len(acgr.tdgs)} traffic "
                "distribution group(s). The `res-acgr-*` audit checks verify each "
                "aspect of the configuration.\n\n"
                f"{_ACGR_REALITY_CHECK}"
            ),
            evidence=evidence,
        )


class ACGRIdentityManagementCheck(BaseCheck):
    """Verify SAML identity when ACGR is configured (agent Global Sign-in)."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-identity-001",
            name="ACGR Identity Management (SAML required)",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies the Connect instance uses "
                "SAML 2.0 identity management. Agents can only fail over "
                "between paired regions via Global Sign-in, which requires "
                "SAML — CONNECT_MANAGED and EXISTING_DIRECTORY identity types "
                "leave agents stranded when the primary region is unavailable."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return _tdg_discovery_incomplete(self, context)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        idm = instance.identity_management_type or ""
        evidence = {
            "identity_management_type": idm,
            "traffic_distribution_groups": len(acgr.tdgs),
        }

        if not idm:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Skipped: the instance identity management type was not returned, "
                    "so SAML eligibility for ACGR cannot be evaluated."
                ),
                evidence={**evidence, "evidence_complete": False},
                context=context,
            )

        if idm in _ACGR_ELIGIBLE_IDENTITY_TYPES:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Instance {_instance_name(instance)} uses SAML identity "
                    "management, which supports ACGR agent Global Sign-in."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Instance {_instance_name(instance)} has ACGR configured but "
                f"uses '{idm}' identity management. ACGR agent failover "
                "requires SAML 2.0 — with the current identity type, agents "
                "cannot sign in to the standby region and calls will route "
                "to a region with no available workforce.\n\n"
                "This identity migration is a significant, non-self-service "
                "change; review the enablement, cost, and dependency context "
                "in `res-acgr-config-001` before planning it."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Migrate the instance to SAML 2.0 identity management "
                    "before relying on ACGR for agent failover."
                ),
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Identity management type is set at instance "
                            "creation and cannot be changed in place. Plan a "
                            "migration: create a new instance with SAML 2.0, "
                            "re-provision resources (flows, queues, routing "
                            "profiles, users) into it, then repoint the TDG "
                            "and phone numbers. Engage your AWS account team "
                            "to plan the cutover — this is a significant "
                            "change and warrants specialist support."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency prerequisites",
                        url=_ACGR_DOCS_URL,
                    ),
                    RemediationReference(
                        title="Configure SAML with IAM for Amazon Connect",
                        url="https://docs.aws.amazon.com/connect/latest/adminguide/configure-saml.html",
                    ),
                ],
            ),
        )


class ACGRTrafficDistributionGroupStatusCheck(BaseCheck):
    """Verify each TDG is in ACTIVE status."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-tdg-status-001",
            name="ACGR Traffic Distribution Group Status",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies each traffic distribution "
                "group is in ACTIVE status. A TDG in CREATION_IN_PROGRESS, "
                "CREATION_FAILED, UPDATE_IN_PROGRESS, or PENDING_DELETION "
                "cannot serve failover traffic."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return _tdg_discovery_incomplete(self, context)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )
        if acgr.tdg_details_denied and not acgr.tdg_details:
            return self.skipped_for_access_denied(context, acgr.tdg_details_denied_permission)

        # Prefer the detailed Status from DescribeTrafficDistributionGroup;
        # fall back to the summary Status if Describe wasn't available.
        tdg_status_map: Dict[str, str] = {}
        for tdg in acgr.tdgs:
            tdg_id = tdg.get("Id")
            detail = acgr.tdg_details.get(tdg_id) if tdg_id else None
            status = (detail or {}).get("Status") or tdg.get("Status") or "UNKNOWN"
            tdg_status_map[tdg.get("Name") or tdg_id or "unnamed"] = status

        unknown = sorted(name for name, status in tdg_status_map.items() if status == "UNKNOWN")
        non_active = {
            name: status
            for name, status in tdg_status_map.items()
            if status not in ("ACTIVE", "UNKNOWN")
        }
        evidence = {
            "tdg_status": tdg_status_map,
            "non_active_tdgs": non_active,
            "unknown_status_tdgs": unknown,
            "describe_error_tdg_ids": list(acgr.tdg_detail_error_ids),
        }

        if unknown and not non_active:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Skipped: status could not be determined for {len(unknown)} traffic "
                    "distribution group(s) (DescribeTrafficDistributionGroup failed or "
                    "returned no status), so a clean result cannot be reported."
                ),
                evidence={**evidence, "evidence_complete": False},
                context=context,
            )

        if not non_active:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"All {len(tdg_status_map)} traffic distribution group(s) "
                    "for this instance are in ACTIVE status."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="TrafficDistributionGroup",
            description=(
                f"{len(non_active)} traffic distribution group(s) are not in "
                f"ACTIVE status: "
                + ", ".join(f"'{n}' ({s})" for n, s in non_active.items())
                + ". Failover through these TDGs will not work until they "
                "reach ACTIVE. Review `res-acgr-config-001` for the remaining "
                "dependency and coverage requirements; ACTIVE status alone "
                "does not prove end-to-end failover readiness."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary="Resolve the non-ACTIVE TDG state(s).",
                target_resources=list(non_active.keys()),
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "For CREATION_IN_PROGRESS or UPDATE_IN_PROGRESS: "
                            "wait for the operation to complete and re-run "
                            "the assessment. For CREATION_FAILED: delete the "
                            "failed TDG and recreate it, then repoint phone "
                            "numbers. For PENDING_DELETION: confirm the "
                            "deletion is intended; if not, recreate the TDG."
                        ),
                        console_path=(
                            "Connect console -> Instance -> Global "
                            "resiliency -> Traffic distribution groups"
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency",
                        url=_ACGR_DOCS_URL,
                    )
                ],
            ),
        )


class ACGRTrafficDistributionCheck(BaseCheck):
    """Inventory ACGR telephony traffic distribution without prescribing a policy."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-traffic-dist-001",
            name="ACGR Traffic Distribution Inventory",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "Inventories the configured regional telephony percentages for each ACGR "
                "traffic distribution group. Hot-standby, single-region, and multi-region "
                "distributions are valid architecture evidence; this informational check "
                "does not prescribe an active-active policy."
            ),
            disposition=FindingDisposition.INFORMATIONAL,
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Skipped: traffic distribution group discovery did not complete, so "
                    "ACGR applicability and distribution evidence are incomplete."
                ),
                evidence={"evidence_complete": False, "discovery_error": True},
                context=context,
            )
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )
        if acgr.traffic_denied:
            return self.skipped_for_access_denied(context, acgr.traffic_denied_permission)

        distribution_summary: Dict[str, Any] = {}
        distribution_modes: Dict[str, str] = {}
        incomplete_tdgs: List[Dict[str, str]] = []

        for tdg in acgr.tdgs:
            tdg_id = tdg.get("Id")
            tdg_name = tdg.get("Name") or tdg_id or "unknown"
            if not isinstance(tdg_id, str) or not tdg_id.strip():
                incomplete_tdgs.append(
                    {"tdg_name": str(tdg_name), "reason": "missing TDG identifier"}
                )
                continue
            if tdg_id in acgr.traffic_error_ids:
                incomplete_tdgs.append(
                    {"tdg_name": str(tdg_name), "reason": "traffic distribution read failed"}
                )
                continue

            dist = acgr.traffic_distributions.get(tdg_id)
            telephony_config = dist.get("TelephonyConfig") if isinstance(dist, dict) else None
            telephony = (
                telephony_config.get("Distributions")
                if isinstance(telephony_config, dict)
                else None
            )
            if not isinstance(telephony, list) or not telephony:
                incomplete_tdgs.append(
                    {"tdg_name": str(tdg_name), "reason": "missing telephony distributions"}
                )
                continue

            per_region: Dict[str, float] = {}
            valid_entries = True
            for entry in telephony:
                if not isinstance(entry, dict):
                    valid_entries = False
                    break
                region = entry.get("Region")
                percentage = entry.get("Percentage")
                if (
                    not isinstance(region, str)
                    or not region.strip()
                    or isinstance(percentage, bool)
                    or not isinstance(percentage, (int, float))
                    or percentage < 0
                    or percentage > 100
                    or region in per_region
                ):
                    valid_entries = False
                    break
                per_region[region] = percentage

            if not valid_entries or abs(sum(per_region.values()) - 100) > 0.001:
                incomplete_tdgs.append(
                    {
                        "tdg_name": str(tdg_name),
                        "reason": "malformed or incomplete regional percentages",
                    }
                )
                continue

            distribution_summary[str(tdg_name)] = per_region
            percentages = list(per_region.values())
            if len(percentages) == 1:
                distribution_modes[str(tdg_name)] = "single-region"
            elif 100 in percentages and all(value in {0, 100} for value in percentages):
                distribution_modes[str(tdg_name)] = "hot-standby"
            else:
                distribution_modes[str(tdg_name)] = "multi-region"

        evidence = {
            "evidence_complete": not incomplete_tdgs,
            "traffic_distribution_group_count": len(acgr.tdgs),
            "evaluated_tdg_count": len(distribution_summary),
            "incomplete_tdg_count": len(incomplete_tdgs),
            "incomplete_tdgs": incomplete_tdgs,
            "distribution_by_tdg": distribution_summary,
            "distribution_mode_by_tdg": distribution_modes,
        }

        if incomplete_tdgs:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="TrafficDistributionGroup",
                description=(
                    "Skipped: complete telephony distribution evidence was not collected "
                    f"for {len(incomplete_tdgs)} of {len(acgr.tdgs)} ACGR traffic "
                    "distribution group(s)."
                ),
                evidence=evidence,
                context=context,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="TrafficDistributionGroup",
            description=(
                "Complete ACGR telephony distribution inventory was collected for every "
                "assessed traffic distribution group. The configured percentages are "
                "reported as architecture evidence without treating hot-standby, "
                "single-region, or multi-region routing as a defect."
            ),
            evidence=evidence,
            context=context,
        )


def _mapping_value_case_insensitive(mapping: Any, key: str) -> Any:
    """Read a mapping value while accepting CloudTrail JSON key-casing differences."""
    if not isinstance(mapping, dict):
        return None
    expected = key.casefold()
    for candidate_key, value in mapping.items():
        if isinstance(candidate_key, str) and candidate_key.casefold() == expected:
            return value
    return None


def _cloudtrail_event_tdg_identifiers(event: Any) -> set[str]:
    """Extract TDG IDs or ARNs from a LookupEvents event without trusting its JSON shape."""
    if not isinstance(event, dict):
        return set()

    identifiers: set[str] = set()
    raw_event = _mapping_value_case_insensitive(event, "CloudTrailEvent")
    if isinstance(raw_event, str):
        try:
            parsed_event = json.loads(raw_event)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_event = None
        request_parameters = _mapping_value_case_insensitive(parsed_event, "requestParameters")
        request_id = _mapping_value_case_insensitive(request_parameters, "id")
        if isinstance(request_id, str) and request_id.strip():
            identifiers.add(request_id.strip())

    resources = _mapping_value_case_insensitive(event, "Resources")
    if isinstance(resources, list):
        for resource in resources:
            resource_name = _mapping_value_case_insensitive(resource, "ResourceName")
            if isinstance(resource_name, str) and resource_name.strip():
                identifiers.add(resource_name.strip())

    return identifiers


def _cloudtrail_event_outcome(event: Any) -> dict[str, Any]:
    """Classify a LookupEvents record without exposing its error message."""
    raw_event = _mapping_value_case_insensitive(event, "CloudTrailEvent")
    if not isinstance(raw_event, str):
        return {
            "outcome": "unknown",
            "error_code": None,
            "error_message_present": False,
            "reason": "CloudTrailEvent payload is missing",
        }
    try:
        parsed_event = json.loads(raw_event)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {
            "outcome": "unknown",
            "error_code": None,
            "error_message_present": False,
            "reason": "CloudTrailEvent payload is malformed",
        }
    if not isinstance(parsed_event, dict):
        return {
            "outcome": "unknown",
            "error_code": None,
            "error_message_present": False,
            "reason": "CloudTrailEvent payload is not an object",
        }

    raw_error_code = _mapping_value_case_insensitive(parsed_event, "errorCode")
    raw_error_message = _mapping_value_case_insensitive(parsed_event, "errorMessage")
    error_code_present = raw_error_code not in (None, "")
    error_message_present = raw_error_message not in (None, "")
    if error_code_present or error_message_present:
        return {
            "outcome": "failed",
            "error_code": str(raw_error_code) if error_code_present else None,
            "error_message_present": error_message_present,
            "reason": "CloudTrailEvent records an API error",
        }
    return {
        "outcome": "successful",
        "error_code": None,
        "error_message_present": False,
        "reason": None,
    }


class ACGRFailoverTestCheck(BaseCheck):
    """Find recent UpdateTrafficDistribution evidence scoped to an assessed TDG."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-failover-test-001",
            name="ACGR Failover Testing Evidence",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, searches the last "
                f"{_FAILOVER_TEST_LOOKBACK_DAYS} days for "
                "UpdateTrafficDistribution CloudTrail events whose request Id or resource "
                "identity matches an assessed traffic distribution group."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Skipped: traffic distribution group discovery did not complete, so "
                    "CloudTrail events cannot be scoped to the assessed deployment."
                ),
                evidence={"evidence_complete": False, "discovery_error": True},
                context=context,
            )
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        identifier_to_tdg: Dict[str, str] = {}
        unidentifiable_tdgs: List[str] = []
        for tdg in acgr.tdgs:
            tdg_id = tdg.get("Id")
            tdg_arn = tdg.get("Arn")
            canonical_identity = tdg_id or tdg_arn
            if not isinstance(canonical_identity, str) or not canonical_identity.strip():
                unidentifiable_tdgs.append(str(tdg.get("Name") or "unknown"))
                continue
            for identifier in (tdg_id, tdg_arn):
                if isinstance(identifier, str) and identifier.strip():
                    identifier_to_tdg[identifier.strip()] = canonical_identity.strip()

        if unidentifiable_tdgs:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="TrafficDistributionGroup",
                description=(
                    "Skipped: one or more assessed traffic distribution groups lacked an ID "
                    "or ARN required to scope CloudTrail evidence."
                ),
                evidence={
                    "evidence_complete": False,
                    "unidentifiable_tdgs": unidentifiable_tdgs,
                },
                context=context,
            )

        start_time = datetime.now(timezone.utc) - timedelta(days=_FAILOVER_TEST_LOOKBACK_DAYS)
        events: List[Any] = []
        next_token: Optional[str] = None
        seen_tokens: set[str] = set()
        pagination_complete = False
        pages_scanned = 0

        try:
            for _ in range(_MAX_CLOUDTRAIL_EVENT_PAGES):
                kwargs: Dict[str, Any] = {
                    "LookupAttributes": [
                        {
                            "AttributeKey": "EventName",
                            "AttributeValue": "UpdateTrafficDistribution",
                        },
                    ],
                    "StartTime": start_time,
                    "MaxResults": _CLOUDTRAIL_EVENT_PAGE_SIZE,
                }
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = factory.call_api_with_resilience(
                    factory.get_cloudtrail_client(),
                    "lookup_events",
                    "cloudtrail",
                    **kwargs,
                )
                pages_scanned += 1
                events.extend(resp.get("Events") or [])
                returned_token = resp.get("NextToken")
                if not returned_token:
                    pagination_complete = True
                    break
                if not isinstance(returned_token, str) or returned_token in seen_tokens:
                    break
                seen_tokens.add(returned_token)
                next_token = returned_token
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudtrail:LookupEvents")
            raise

        matched_events: List[Dict[str, Any]] = []
        successful_matched_events: List[Dict[str, Any]] = []
        failed_matched_events: List[Dict[str, Any]] = []
        malformed_matched_events: List[Dict[str, Any]] = []
        matched_tdgs: set[str] = set()
        successful_matched_tdgs: set[str] = set()
        unrelated_count = 0
        malformed_count = 0

        for event in events:
            identifiers = _cloudtrail_event_tdg_identifiers(event)
            matching_identifiers = identifiers.intersection(identifier_to_tdg)
            if matching_identifiers:
                matched_events.append(event)
                event_tdgs = {identifier_to_tdg[value] for value in matching_identifiers}
                matched_tdgs.update(event_tdgs)
                outcome = _cloudtrail_event_outcome(event)
                observation = {
                    "event_time": str(event.get("EventTime", "")),
                    "matched_tdgs": sorted(event_tdgs),
                    "error_code": outcome["error_code"],
                    "error_message_present": outcome["error_message_present"],
                }
                if outcome["outcome"] == "successful":
                    successful_matched_events.append(event)
                    successful_matched_tdgs.update(event_tdgs)
                elif outcome["outcome"] == "failed":
                    failed_matched_events.append(observation)
                else:
                    malformed_matched_events.append({**observation, "reason": outcome["reason"]})
            elif identifiers:
                unrelated_count += 1
            else:
                malformed_count += 1

        limitations = []
        if not pagination_complete:
            limitations.append(
                "CloudTrail LookupEvents pagination did not complete within the bounded scan"
            )
        evidence = {
            "evidence_complete": pagination_complete,
            "pagination_complete": pagination_complete,
            "pages_scanned": pages_scanned,
            "limitations": limitations,
            "lookback_days": _FAILOVER_TEST_LOOKBACK_DAYS,
            "assessed_tdg_identifiers": sorted(identifier_to_tdg),
            "candidate_event_count": len(events),
            "matched_event_count": len(matched_events),
            "successful_matched_event_count": len(successful_matched_events),
            "failed_matched_event_count": len(failed_matched_events),
            "malformed_matched_event_count": len(malformed_matched_events),
            "failed_matched_events": failed_matched_events,
            "malformed_matched_events": malformed_matched_events,
            "unrelated_event_count": unrelated_count,
            "malformed_event_count": malformed_count,
            "matched_tdgs": sorted(matched_tdgs),
            "successful_matched_tdgs": sorted(successful_matched_tdgs),
            "update_traffic_distribution_event_count": len(events),
        }

        if successful_matched_events:
            evidence["most_recent_matched_event_time"] = str(
                successful_matched_events[0].get("EventTime", "")
            )
            limitation_note = (
                " LookupEvents pagination was incomplete, but the observed successful event "
                "is sufficient positive evidence."
                if not pagination_complete
                else ""
            )
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Found {len(successful_matched_events)} successful "
                    "UpdateTrafficDistribution CloudTrail event(s) scoped to "
                    f"{len(successful_matched_tdgs)} assessed traffic distribution group(s) "
                    f"in the last {_FAILOVER_TEST_LOOKBACK_DAYS} days. The event proves a "
                    "configured traffic-distribution change, not successful end-to-end "
                    f"failover.{limitation_note}"
                ),
                evidence=evidence,
                context=context,
            )

        if not pagination_complete:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Skipped: CloudTrail LookupEvents pagination did not complete, and no "
                    "successful scoped event was observed in the partial evidence."
                ),
                evidence=evidence,
                context=context,
            )

        failed_attempt_note = (
            f" {len(failed_matched_events)} scoped attempt(s) recorded API errors and "
            f"{len(malformed_matched_events)} scoped observation(s) had malformed or missing "
            "CloudTrailEvent payloads; neither is successful evidence."
            if failed_matched_events or malformed_matched_events
            else ""
        )
        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "ACGR is configured but no successful UpdateTrafficDistribution CloudTrail "
                "event could be matched to an assessed traffic distribution group in the last "
                f"{_FAILOVER_TEST_LOOKBACK_DAYS} days. Unrelated or unscopable events do not "
                f"demonstrate that this deployment exercised traffic movement.{failed_attempt_note}"
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary="Schedule and document a controlled failover exercise at least quarterly.",
                target_resources=sorted(set(identifier_to_tdg.values())),
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Plan a controlled traffic shift for an assessed TDG, verify calls "
                            "route and agents handle them, then restore the intended distribution."
                        ),
                        command=(
                            "aws connect update-traffic-distribution --id <tdg-id-or-arn> "
                            "--telephony-config '<distribution-json>'"
                        ),
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Retain the operational test record for call routing, agent access, "
                            "and regional dependencies; CloudTrail records only the API change."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency",
                        url=_ACGR_DOCS_URL,
                    )
                ],
                placeholders=["<tdg-id-or-arn>", "<distribution-json>"],
            ),
            context=context,
        )


class ACGRPhoneNumberBindingCheck(BaseCheck):
    """Verify phone numbers are claimed against the TDG (not just the instance)."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-numbers-001",
            name="ACGR Phone Number Binding",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies inbound phone numbers "
                "are claimed against a traffic distribution group ARN "
                "rather than the instance ARN. Numbers bound directly to "
                "the instance do not fail over — they continue routing to "
                "the primary region even when the TDG has shifted traffic."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if acgr.tdgs_error:
            return _tdg_discovery_incomplete(self, context)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        # Count numbers claimed against each TDG and against the instance.
        try:
            instance_numbers = _list_all_phone_numbers(factory, instance.instance_arn)
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            instance_numbers = []

        tdg_number_counts: Dict[str, int] = {}
        tdgs_denied = False
        for tdg in acgr.tdgs:
            tdg_arn = tdg.get("Arn")
            tdg_name = tdg.get("Name") or tdg.get("Id") or "unnamed"
            if not tdg_arn:
                continue
            try:
                tdg_number_counts[tdg_name] = len(_list_all_phone_numbers(factory, tdg_arn))
            except Exception as e:
                if factory.is_access_denied(e):
                    tdgs_denied = True
                    break
                tdg_number_counts[tdg_name] = 0

        if tdgs_denied and not tdg_number_counts:
            return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")

        total_on_tdgs = sum(tdg_number_counts.values())
        instance_direct = len(instance_numbers)

        evidence = {
            "numbers_on_tdgs": tdg_number_counts,
            "total_numbers_on_tdgs": total_on_tdgs,
            "numbers_directly_on_instance": instance_direct,
        }

        # Case 1: TDG has no numbers at all — ACGR won't route anything.
        if total_on_tdgs == 0:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "ACGR is configured but no phone numbers are claimed "
                    "against any traffic distribution group. Inbound calls "
                    "will not benefit from failover — they route to whichever "
                    "target the number is bound to, which is not the TDG.\n\n"
                    "Phone-number binding is necessary but not sufficient; "
                    "review `res-acgr-config-001` for dependencies ACGR does "
                    "not replicate automatically."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Repoint inbound phone numbers from the instance ARN "
                        "to the TDG ARN so failover routing takes effect."
                    ),
                    target_resources=[t.get("Name") for t in acgr.tdgs if t.get("Name")],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each inbound number that should benefit "
                                "from failover, update its TargetArn to point "
                                "at the TDG."
                            ),
                            command=(
                                "aws connect update-phone-number "
                                "--phone-number-id <number-id> "
                                "--target-arn <tdg-arn>"
                            ),
                            console_path=(
                                "Connect console -> Telephony -> Phone numbers -> <number> -> Edit"
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Associating phone numbers with a TDG",
                            url=_ACGR_DOCS_URL,
                        )
                    ],
                    placeholders=["<number-id>", "<tdg-arn>"],
                ),
            )

        # Case 2: Some numbers on TDG, but some still directly on the instance
        # — the ones on the instance won't fail over.
        if instance_direct > 0:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"{instance_direct} phone number(s) are claimed directly "
                    f"against the instance rather than a TDG ({total_on_tdgs} "
                    "are on TDGs). Numbers bound to the instance will not "
                    "fail over when the TDG shifts traffic — those calls "
                    "will keep going to the primary region.\n\n"
                    "Phone-number binding is necessary but not sufficient; "
                    "review `res-acgr-config-001` for dependencies ACGR does "
                    "not replicate automatically."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Repoint the instance-bound numbers to a TDG so all "
                        "inbound traffic benefits from failover."
                    ),
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Enumerate the instance-bound numbers and, "
                                "for any that should participate in failover, "
                                "update their TargetArn to a TDG ARN."
                            ),
                            command=(
                                "aws connect list-phone-numbers-v2 "
                                f"--target-arn {instance.instance_arn} "
                                "&& aws connect update-phone-number "
                                "--phone-number-id <number-id> "
                                "--target-arn <tdg-arn>"
                            ),
                        ),
                    ],
                    applies_if=(
                        "the instance-bound numbers are intended to failover. "
                        "Some numbers may be region-specific by design (e.g. "
                        "an in-region test line) — those can stay on the "
                        "instance."
                    ),
                    placeholders=["<number-id>", "<tdg-arn>"],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"All {total_on_tdgs} inbound phone number(s) are claimed "
                "against a traffic distribution group and will benefit from "
                "ACGR failover routing."
            ),
            evidence=evidence,
        )


class CloudWatchAlarmMonitoringCheck(BaseCheck):
    """Verify actionable, instance-specific alarms cover required Connect metrics."""

    def __init__(self):
        super().__init__(
            check_id="res-cloudwatch-001",
            name="CloudWatch Alarm Coverage",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "Verifies that enabled CloudWatch metric alarms with configured actions "
                "cover required Amazon Connect voice metrics for the assessed instance."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        all_alarms: List[Dict[str, Any]] = []
        composite_alarm_count = 0
        next_token: Optional[str] = None
        seen_tokens: set[str] = set()
        pagination_complete = False

        try:
            for _ in range(_MAX_CLOUDWATCH_ALARM_PAGES):
                kwargs: Dict[str, Any] = {"MaxRecords": _CLOUDWATCH_ALARM_PAGE_SIZE}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = factory.describe_alarms_resilient(**kwargs)
                all_alarms.extend(resp.get("MetricAlarms") or [])
                composite_alarm_count += len(resp.get("CompositeAlarms") or [])
                returned_token = resp.get("NextToken")
                if not returned_token:
                    pagination_complete = True
                    break
                if not isinstance(returned_token, str) or returned_token in seen_tokens:
                    break
                seen_tokens.add(returned_token)
                next_token = returned_token
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudwatch:DescribeAlarms")
            raise

        if not pagination_complete:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Skipped: CloudWatch DescribeAlarms pagination did not complete, so "
                    "alarm coverage evidence is incomplete."
                ),
                evidence={
                    "evidence_complete": False,
                    "metric_alarm_count": len(all_alarms),
                    "composite_alarm_count": composite_alarm_count,
                },
                context=context,
            )

        connect_alarms = [alarm for alarm in all_alarms if alarm.get("Namespace") == "AWS/Connect"]
        required_candidates = [
            alarm for alarm in connect_alarms if alarm.get("MetricName") in _REQUIRED_ALARM_METRICS
        ]
        rejection_candidates: Dict[str, List[Dict[str, str]]] = {
            "wrong_instance": [],
            "missing_or_wrong_dimension": [],
            "disabled": [],
            "no_action": [],
        }
        covered_metrics: set[str] = set()

        for alarm in required_candidates:
            metric_name = str(alarm.get("MetricName"))
            candidate = {
                "alarm_name": str(alarm.get("AlarmName") or "unnamed"),
                "metric_name": metric_name,
            }
            dimensions = alarm.get("Dimensions")
            dimension_values: Dict[str, List[Any]] = {}
            if isinstance(dimensions, list):
                for dimension in dimensions:
                    if not isinstance(dimension, dict):
                        continue
                    name = dimension.get("Name")
                    if isinstance(name, str):
                        dimension_values.setdefault(name, []).append(dimension.get("Value"))

            rejected = False
            instance_values = dimension_values.get("InstanceId", [])
            wrong_instance = bool(instance_values) and instance.instance_id not in instance_values
            dimension_issue = instance_values != [instance.instance_id] or dimension_values.get(
                "MetricGroup", []
            ) != [_REQUIRED_ALARM_DIMENSIONS["MetricGroup"]]
            if wrong_instance:
                rejection_candidates["wrong_instance"].append(candidate)
                rejected = True
            elif dimension_issue:
                rejection_candidates["missing_or_wrong_dimension"].append(candidate)
                rejected = True

            if alarm.get("ActionsEnabled") is False:
                rejection_candidates["disabled"].append(candidate)
                rejected = True

            alarm_actions = alarm.get("AlarmActions")
            has_action = isinstance(alarm_actions, list) and any(
                isinstance(action, str) and action.strip() for action in alarm_actions
            )
            if not has_action:
                rejection_candidates["no_action"].append(candidate)
                rejected = True

            if not rejected:
                covered_metrics.add(metric_name)

        missing = [metric for metric in _REQUIRED_ALARM_METRICS if metric not in covered_metrics]
        evidence = {
            "evidence_complete": True,
            "metric_alarm_count": len(all_alarms),
            "composite_alarm_count": composite_alarm_count,
            "connect_alarm_count": len(connect_alarms),
            "required_metric_candidate_count": len(required_candidates),
            "valid_alarm_count": len(covered_metrics),
            "covered_metrics": sorted(covered_metrics),
            "missing_metrics": missing,
            "wrong_instance_candidates": rejection_candidates["wrong_instance"],
            "wrong_instance_candidate_count": len(rejection_candidates["wrong_instance"]),
            "missing_or_wrong_dimension_candidates": rejection_candidates[
                "missing_or_wrong_dimension"
            ],
            "missing_or_wrong_dimension_candidate_count": len(
                rejection_candidates["missing_or_wrong_dimension"]
            ),
            "disabled_candidates": rejection_candidates["disabled"],
            "disabled_candidate_count": len(rejection_candidates["disabled"]),
            "no_action_candidates": rejection_candidates["no_action"],
            "no_action_candidate_count": len(rejection_candidates["no_action"]),
        }
        metric_impact = {
            "ConcurrentCalls": "concurrent-call quota consumption",
            "ThrottledCalls": "calls rejected because call rate exceeded the supported quota",
            "MissedCalls": "voice calls that agents did not answer",
            "CallsPerInterval": "unexpected voice-call volume spikes or drops",
        }

        if missing:
            missing_lines = "\n".join(
                f"* **{metric}** — {metric_impact[metric]}" for metric in missing
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Enabled, actionable AWS/Connect metric alarms cover "
                    f"{len(covered_metrics)} of {len(_REQUIRED_ALARM_METRICS)} required voice "
                    f"metrics for {instance.display_name}. Missing coverage:\n\n{missing_lines}\n\n"
                    "An alarm counts only when its InstanceId matches this instance, its "
                    "MetricGroup is VoiceCalls, actions are enabled, and at least one "
                    "nonblank alarm action is configured."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=f"Add valid alarms for missing metrics: {', '.join(missing)}.",
                    target_resources=[instance.instance_id] + missing,
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                f"Create AWS/Connect metric alarms for {', '.join(missing)} "
                                f"with InstanceId={instance.instance_id}, "
                                "MetricGroup=VoiceCalls, enabled actions, and at least one "
                                "owned notification or automation target."
                            ),
                            console_path="CloudWatch console -> Alarms -> Create alarm",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Monitoring Connect with CloudWatch",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/monitoring-cloudwatch.html",  # noqa: E501
                        )
                    ],
                ),
                context=context,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Enabled AWS/Connect metric alarms with nonblank configured actions cover "
                f"all {len(_REQUIRED_ALARM_METRICS)} required voice metrics for "
                f"{instance.display_name}. This configuration evidence does not prove that "
                "notifications or automated actions are delivered successfully at runtime."
            ),
            evidence=evidence,
            context=context,
        )


class CarrierDiversityCheck(BaseCheck):
    """Assess phone number geographic / carrier diversity (Req 19)."""

    def __init__(self):
        super().__init__(
            check_id="res-carrier-diversity-001",
            name="Phone Number Carrier Diversity",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            description=(
                "Checks phone number distribution by country; flags "
                "single-country deployments without a traffic distribution group."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "list_phone_numbers_v2",
                "connect",
                TargetArn=instance.instance_arn,
                MaxResults=50,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            # Fallback: API may not exist pre-2022; treat as no numbers.
            resp = {"ListPhoneNumbersSummaryList": []}

        numbers = resp.get("ListPhoneNumbersSummaryList", []) or []
        if not numbers:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="No phone numbers claimed; carrier diversity N/A.",
                evidence={"phone_number_count": 0},
            )

        # Count by country code.
        country_counts: dict = {}
        for num in numbers:
            cc = num.get("PhoneNumberCountryCode", "UNKNOWN")
            country_counts[cc] = country_counts.get(cc, 0) + 1

        evidence = {
            "phone_number_count": len(numbers),
            "country_distribution": country_counts,
        }

        if len(country_counts) == 1:
            only_country = next(iter(country_counts))
            return self.not_applicable(
                context,
                reason=(
                    f"All {len(numbers)} phone number(s) on "
                    f"{instance.display_name} are claimed in a single country "
                    f"({only_country}). This is the expected shape for a "
                    "domestic-only operation, so there is nothing to fix by "
                    "default.\n\n"
                    "Additional country numbers are relevant only when the "
                    "business directly serves callers in those countries. "
                    "Region-level failover is a separate concern addressed by "
                    "Traffic Distribution Groups and Amazon Connect Global "
                    "Resiliency (`res-acgr-*`); adding countries does not prove "
                    "regional resilience."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Phone numbers on {instance.display_name} span "
                f"{len(country_counts)} countries "
                f"({', '.join(sorted(country_counts))}). This provides local "
                "number presence where those countries are intentionally served; "
                "it does not by itself establish regional failover."
            ),
            evidence=evidence,
        )


class HardcodedRoutingCheck(BaseCheck):
    """Inventory literal routing values in customer-authored contact flows."""

    def __init__(self):
        super().__init__(
            check_id="res-hardcoded-routing-001",
            name="Hardcoded Routing Configuration",
            pillar=Pillar.RESILIENCE,
            severity=Severity.LOW,
            description=(
                "Notes contact flows that use literal phone numbers, queue "
                "ARNs, or flow ARNs instead of a contact attribute reference. "
                "Hardcoded destinations are a normal, common pattern in "
                "contact center flows — this is an observation to help you "
                "decide whether externalizing a specific destination is "
                "worth it for your operation, not a defect to fix."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        hardcoded_all = []
        skipped_flows = []
        # AWS's built-in sample flows (see is_default_sample_flow) ship
        # with literal phone numbers and ARNs by design — they are demo
        # content, not the customer's production routing configuration.
        # Reviewer feedback: including them here just reports on AWS's
        # own flows back to the customer, which is noise. Only look at
        # flows the customer actually authored.
        customer_flows = [f for f in instance.contact_flows if not is_default_sample_flow(f)]

        for flow in customer_flows:
            graph = _parse_flow(flow)
            if not graph:
                skipped_flows.append({"flow": flow.name, "flow_id": flow.id})
                continue
            for action in graph.actions.values():
                if action.action_type not in _ROUTING_ACTION_TYPES:
                    continue
                params = action.parameters or {}
                dest = (
                    params.get("PhoneNumber")
                    or params.get("QueueId")
                    or params.get("ContactFlowId")
                    or (params.get("Endpoint", {}) or {}).get("Address")
                )
                if dest and not _is_dynamic_reference(dest):
                    hardcoded_all.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "action_type": action.action_type,
                            "hardcoded_value": (
                                _mask_phone(dest) if "Phone" in action.action_type else dest[:60]
                            ),
                        }
                    )

        evidence = {
            "hardcoded_count": len(hardcoded_all),
            "hardcoded_details": hardcoded_all[:10],
            "flows_discovered": len(customer_flows),
            "flows_analyzed": len(customer_flows) - len(skipped_flows),
            "flows_unanalyzed": len(skipped_flows),
            "unanalyzed_flows": skipped_flows[:10],
            "analysis_complete": not skipped_flows,
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
        }

        analyzed = evidence["flows_analyzed"]
        hardcoded = len(hardcoded_all)
        sample_note = (
            f" {evidence['sample_flows_excluded']} AWS default sample flow(s) were "
            "excluded from this inventory."
            if evidence["sample_flows_excluded"]
            else ""
        )

        if skipped_flows:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"Hardcoded routing inventory was incomplete: {len(skipped_flows)} "
                    "customer-authored flow(s) could not be parsed. Literal destinations "
                    f"found in the {analyzed} analyzed flow(s) remain in the evidence."
                    f"{sample_note}"
                ),
                evidence=evidence,
            )

        if hardcoded == 0:
            description = (
                f"No literal phone numbers, queue ARNs, or flow ARNs were observed in "
                f"transfer actions across {analyzed} customer-authored flow(s)."
                f"{sample_note} This is configuration inventory, not a requirement to "
                "externalize routing destinations."
            )
        else:
            description = (
                f"{hardcoded} literal routing destination(s) were observed across "
                f"{analyzed} customer-authored flow(s).{sample_note} Literal destinations "
                "are valid configuration. Review a destination only when it needs to vary "
                "across environments or change independently of flow publication."
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=description,
            evidence=evidence,
        )


def _static_lambda_reference(parameters: Dict[str, Any]) -> Optional[str]:
    """Resolve a static Lambda ARN or name from supported Connect export shapes."""
    value: Any = None
    for name in ("FunctionArn", "LambdaFunctionARN"):
        if name in parameters:
            value = parameters[name]
            break

    while isinstance(value, dict):
        if "Value" in value:
            value = value["Value"]
            continue
        if "StaticValue" in value:
            value = value["StaticValue"]
            continue
        return None

    if not isinstance(value, str) or not value.strip():
        return None
    reference = value.strip()
    if reference.startswith("$.") or reference.startswith("$["):
        return None
    return reference


class LambdaDependencyRiskCheck(BaseCheck):
    """Find reachable Lambda call sites without an error fallback."""

    def __init__(self):
        super().__init__(
            check_id="res-lambda-dependency-001",
            name="Lambda Error Routing Completeness",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            description=(
                "Checks every reachable, customer-authored Lambda call site for an explicit "
                "Error transition; Lambda configuration only enriches the finding."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        customer_flows = sorted(
            (flow for flow in instance.contact_flows if not is_default_sample_flow(flow)),
            key=lambda flow: ((flow.name or "").casefold(), flow.id),
        )
        call_sites_by_reference: Dict[str, List[Dict[str, Any]]] = {}
        seen_call_sites: set[tuple[str, str, str]] = set()
        unresolved_call_sites: List[Dict[str, Any]] = []
        missing_call_sites: List[Dict[str, Any]] = []
        skipped_flows: List[Dict[str, str]] = []
        flows_analyzed = 0
        authored_lambda_blocks = 0
        unreachable_lambda_blocks = 0

        for flow in customer_flows:
            if not flow.content or not isinstance(flow.content, dict):
                skipped_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content unavailable"}
                )
                continue
            graph = _parse_flow(flow)
            if graph is None:
                skipped_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content parse failed"}
                )
                continue
            if graph.actions and graph.entry_point_id not in graph.actions:
                skipped_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "reason": "entry action is missing or invalid",
                    }
                )
                continue

            flows_analyzed += 1
            reachable = reachable_from_entry(graph)
            lambda_actions = sorted(
                (
                    action
                    for action in graph.actions.values()
                    if action.action_type == "InvokeLambdaFunction"
                ),
                key=lambda action: action.action_id,
            )
            authored_lambda_blocks += len(lambda_actions)
            unreachable_lambda_blocks += sum(
                action.action_id not in reachable for action in lambda_actions
            )

            for action in lambda_actions:
                if action.action_id not in reachable:
                    continue
                call_site = {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "action_id": action.action_id,
                    "has_error_branch": bool(action.error_transitions),
                    "error_targets": sorted(
                        transition.target_action_id for transition in action.error_transitions
                    ),
                }
                reference = _static_lambda_reference(action.parameters or {})
                key = (flow.id, action.action_id, reference or "<unresolved>")
                if key in seen_call_sites:
                    continue
                seen_call_sites.add(key)
                if reference is None:
                    call_site.update(
                        {
                            "function_reference": None,
                            "reason": "Lambda reference is missing or dynamic",
                        }
                    )
                    unresolved_call_sites.append(call_site)
                    if not call_site["has_error_branch"]:
                        missing_call_sites.append(call_site)
                    continue
                call_site["function_reference"] = reference
                if not call_site["has_error_branch"]:
                    missing_call_sites.append(call_site)
                call_sites_by_reference.setdefault(reference, []).append(call_site)

        for call_sites in call_sites_by_reference.values():
            call_sites.sort(
                key=lambda row: (
                    str(row["flow"]).casefold(),
                    str(row["flow_id"]),
                    str(row["action_id"]),
                )
            )
        unresolved_call_sites.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
                str(row["action_id"]),
            )
        )

        checked_functions = 0
        denied_functions: List[str] = []
        lookup_failures: List[Dict[str, str]] = []

        for reference in sorted(call_sites_by_reference):
            try:
                response = factory.get_lambda_function_resilient(reference)
            except Exception as error:  # noqa: BLE001
                if factory.is_access_denied(error):
                    denied_functions.append(reference)
                else:
                    lookup_failures.append(
                        {
                            "function_reference": reference,
                            "error_type": type(error).__name__,
                            "error_code": _error_code(error),
                        }
                    )
                continue

            checked_functions += 1
            configuration = response.get("Configuration") or {}
            vpc_config = configuration.get("VpcConfig") or {}
            subnet_ids = sorted(vpc_config.get("SubnetIds") or [])
            security_group_ids = sorted(vpc_config.get("SecurityGroupIds") or [])
            is_vpc_attached = bool(vpc_config.get("VpcId") or subnet_ids or security_group_ids)

            for call_site in call_sites_by_reference[reference]:
                call_site.update(
                    {
                        "function_name": configuration.get("FunctionName") or reference,
                        "vpc_attached": is_vpc_attached,
                        "vpc_id": vpc_config.get("VpcId") or "",
                        "subnet_ids": subnet_ids,
                        "security_group_ids": security_group_ids,
                    }
                )

        missing_call_sites.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
                str(row["action_id"]),
                str(row.get("function_reference") or ""),
            )
        )
        analysis_limitations = []
        if skipped_flows:
            analysis_limitations.append(f"{len(skipped_flows)} flow(s) could not be analyzed")
        enrichment_limitations = []
        if unresolved_call_sites:
            enrichment_limitations.append(
                f"{len(unresolved_call_sites)} reachable call site(s) use an unresolved reference"
            )
        if denied_functions:
            enrichment_limitations.append(
                f"lambda:GetFunction was denied for {len(denied_functions)} function(s)"
            )
        if lookup_failures:
            enrichment_limitations.append(f"{len(lookup_failures)} function lookup(s) failed")
        limitations = analysis_limitations + enrichment_limitations

        reachable_call_sites = sum(len(sites) for sites in call_sites_by_reference.values()) + len(
            unresolved_call_sites
        )
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "customer_flows_discovered": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
            "flows_analyzed": flows_analyzed,
            "flows_skipped": len(skipped_flows),
            "skipped_flow_details": skipped_flows,
            "authored_lambda_blocks": authored_lambda_blocks,
            "unreachable_lambda_blocks": unreachable_lambda_blocks,
            "reachable_lambda_call_sites": reachable_call_sites,
            "lambda_call_sites_without_error_branch": len(missing_call_sites),
            "lambda_functions_invoked": len(call_sites_by_reference),
            "lambda_functions_checked": checked_functions,
            "lambda_functions_access_denied": denied_functions,
            "lambda_function_lookup_failures": lookup_failures,
            "unresolved_call_sites": unresolved_call_sites,
            "vpc_attached_missing_error_branches": sum(
                row.get("vpc_attached") is True for row in missing_call_sites
            ),
            "analysis_complete": not analysis_limitations,
            "enrichment_complete": not enrichment_limitations,
            "analysis_limitations": analysis_limitations,
            "enrichment_limitations": enrichment_limitations,
            "limitations": limitations,
        }

        if missing_call_sites:
            evidence["details"] = missing_call_sites[:20]
            limitation_note = (
                " Evidence enrichment or flow coverage is also limited because "
                + "; ".join(limitations)
                + "."
                if limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    f"**{len(missing_call_sites)} reachable Lambda call site(s) have no "
                    "explicit Error transition.** Each listed action is direct structural "
                    "evidence of an unhandled invocation-error route; target resolution, "
                    "GetFunction access, and VPC attachment do not determine this outcome."
                    f"{limitation_note}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Wire a caller-safe Error fallback on every listed Lambda call site.",
                    target_resources=[
                        f"{row['flow_id']}:{row['action_id']}" for row in missing_call_sites[:20]
                    ],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Open each listed Lambda action and connect its Error output to a "
                                "tested apology, fallback queue, alternate path, or intentional "
                                "disconnect outcome."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Test timeout, throttle, network, malformed-response, and function "
                                "error cases and confirm each contact reaches the intended fallback."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Invoke Lambda from a contact flow",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-lambda-functions.html",  # noqa: E501
                        )
                    ],
                ),
            )

        if analysis_limitations:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    "Lambda error-routing analysis was incomplete and cannot report PASS: "
                    + "; ".join(analysis_limitations)
                    + "."
                ),
                evidence=evidence,
            )

        if reachable_call_sites == 0:
            return self.not_applicable(
                context,
                reason=(
                    "Complete flow analysis found no reachable, customer-authored Lambda "
                    "call sites to evaluate."
                ),
                evidence=evidence,
            )

        enrichment_note = (
            " Lambda metadata enrichment was limited because "
            + "; ".join(enrichment_limitations)
            + "; this does not change the Error-transition result."
            if enrichment_limitations
            else ""
        )
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="LambdaFunction",
            description=(
                f"All {reachable_call_sites} reachable Lambda call site(s) across "
                f"{flows_analyzed} customer-authored flow(s) have explicit Error transitions."
                f"{enrichment_note}"
            ),
            evidence=evidence,
        )


def register_advanced_resilience_checks(registry, *, include_flow_checks: bool = True) -> None:
    """Register all advanced resilience checks."""
    # ACGR set — discovery + five audit sub-checks.
    registry.register_check(ACGRConfigurationCheck())
    registry.register_check(ACGRIdentityManagementCheck())
    registry.register_check(ACGRTrafficDistributionGroupStatusCheck())
    registry.register_check(ACGRTrafficDistributionCheck())
    registry.register_check(ACGRFailoverTestCheck())
    registry.register_check(ACGRPhoneNumberBindingCheck())
    # Other resilience checks.
    registry.register_check(CloudWatchAlarmMonitoringCheck())
    registry.register_check(CarrierDiversityCheck())
    registry.register_check(HardcodedRoutingCheck())
    if include_flow_checks:
        registry.register_check(LambdaDependencyRiskCheck())
