"""
Telephony topology resolution for Caller Journey Mapping.

Discovers which phone numbers (DID + toll-free) map to which contact flows
and classifies all flows into three tiers for scoping:

* tier 1 — statically reachable from an inbound phone number. These are the
  only flows the journey pipeline stitches and enumerates.
* tier 2 — not phone-reachable, but observed handling contacts (any channel)
  in the traffic lookback window. Proven in use through some non-phone entry
  point, so not dormant; *not* enumerated, because chat/task/email entry
  points and channel-appropriate scoring do not exist yet.
* tier 3 — not phone-reachable and no observed contacts (or usage metrics
  were unavailable). These are the dormant-flow review candidates.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..aws_client_factory import AWSClientFactory
from ..models import ContactFlowGraph
from .models import PhoneNumberEntry, TierAssignment

logger = logging.getLogger("journey.topology")

# Transfer action types that indicate cross-flow reachability.
_TRANSFER_ACTIONS = {
    "TransferToFlow",
    "TransferContactToFlow",
    "InvokeFlowModule",
}


@dataclass
class ChannelTraffic:
    """Per-flow observed contact counts and whether they can be trusted.

    ``status`` is ``"complete"`` when every request succeeded, otherwise a
    reason the counts are unavailable. Counts are never partial: if any
    request fails, ``by_flow`` is emptied, because ranking or classifying on
    a subset of flows silently mislabels the rest as unused.
    """

    by_flow: Dict[str, Dict[str, int]] = field(default_factory=dict)
    status: str = "not_requested"
    window_days: int = 0

    @property
    def available(self) -> bool:
        return self.status == "complete"


def resolve_topology(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
    config: Dict[str, Any],
) -> Tuple[List[PhoneNumberEntry], List[TierAssignment], ChannelTraffic]:
    """
    Resolve the full telephony topology: phone numbers → flows → tiers.

    Returns:
        (phone_entries, tier_assignments, channel_traffic)
    """
    # Step 1: List all phone numbers.
    phone_entries = _list_phone_numbers(instance_id, instance_arn, factory, parsed_flows)
    logger.info(f"Discovered {len(phone_entries)} phone numbers")

    # Step 2: Build transitive reachability from phone-anchored flows.
    phone_flow_ids = {e.contact_flow_id for e in phone_entries if e.contact_flow_id}
    reachable = _compute_transitive_reachability(phone_flow_ids, parsed_flows)

    # Step 3: Observed per-flow, per-channel usage. This is what separates
    # flows used through a non-phone entry point (chat/task/email) from
    # genuinely dormant ones. Fails safe: unavailable metrics leave every
    # unreachable flow in tier 3, exactly the pre-metrics behaviour.
    journey_cfg = config.get("journey_map", {}) or {}
    channel_traffic = _resolve_flow_channel_traffic(
        instance_arn=instance_arn,
        factory=factory,
        flow_ids=sorted(parsed_flows.keys()),
        lookback_days=_traffic_lookback_days(journey_cfg),
    )

    # Step 4: Classify tiers.
    tier_assignments = _classify_tiers(
        phone_entries,
        parsed_flows,
        reachable,
        channel_traffic=channel_traffic,
    )

    return phone_entries, tier_assignments, channel_traffic


def _list_phone_numbers(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
) -> List[PhoneNumberEntry]:
    """
    Paginate ListPhoneNumbersV2 to get all DIDs + toll-free numbers, then
    resolve each number's assigned flow via ListFlowAssociations.

    ListPhoneNumbersV2's ``TargetArn`` is documented by AWS as "the ARN
    for Connect instances or traffic distribution groups that phone
    number inbound traffic is routed through" — it is always an
    instance/TDG ARN, never a contact-flow ARN, regardless of what flow
    is assigned to the number in the console. The number -> flow mapping
    instead comes from ``connect:ListFlowAssociations`` with
    ``ResourceType=VOICE_PHONE_NUMBER``, matched here by ``PhoneNumberArn``.
    """
    entries: List[PhoneNumberEntry] = []
    client = factory.get_connect_client()

    flow_id_by_phone_arn = _list_voice_flow_associations(instance_id, factory)

    next_token: Optional[str] = None
    try:
        while True:
            kwargs: Dict[str, Any] = {
                "TargetArn": instance_arn,
                "MaxResults": 50,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = factory.call_api_with_resilience(
                client, "list_phone_numbers_v2", "connect", **kwargs
            )
            for num in resp.get("ListPhoneNumbersSummaryList", []):
                flow_id = flow_id_by_phone_arn.get(num.get("PhoneNumberArn", ""))
                flow_name = None
                if flow_id and flow_id in parsed_flows:
                    flow_name = parsed_flows[flow_id].flow_name

                entries.append(
                    PhoneNumberEntry(
                        phone_number=num.get("PhoneNumber", ""),
                        number_type=num.get("PhoneNumberType", "DID"),
                        country_code=num.get("PhoneNumberCountryCode", ""),
                        contact_flow_id=flow_id,
                        contact_flow_name=flow_name,
                        target_arn=num.get("TargetArn"),
                    )
                )

            next_token = resp.get("NextToken")
            if not next_token:
                break

    except Exception as e:
        if factory.is_access_denied(e):
            logger.warning("Access denied for ListPhoneNumbersV2; topology will be empty")
        else:
            logger.error(f"Failed to list phone numbers: {e}")

    return entries


# Only VOICE_PHONE_NUMBER is queried, deliberately.
#
# The resulting map is keyed by ``ListPhoneNumbersV2``'s ``PhoneNumberArn``,
# which is always a Connect-claimed voice number
# (``arn:aws:connect:…:phone-number/…``). The messaging resource types are
# keyed by *AWS End User Messaging* ARNs instead — ``arn:aws:sms-voice:…``
# for SMS and ``arn:aws:social-messaging:…`` for WhatsApp — so their
# ResourceIds can never match a key in this map.
#
# ``SMS_PHONE_NUMBER`` is also absent from the SDK's documented
# ListFlowAssociations ResourceType enum (it is documented only for
# ``GetFlowAssociation``). The service does currently accept it — verified
# live, it returns SMS associations — but those can never match here for the
# ARN reason above, so querying it only cost an API call per assessment.
#
# Enumerating SMS/WhatsApp/email entry points needs a different seeding path
# (End User Messaging DescribePhoneNumbers + GetFlowAssociation for SMS;
# SearchEmailAddresses + ListFlowAssociations(INBOUND_EMAIL) for email) and a
# channel-aware entry-point model. See docs/design/improvement-backlog.md (B).
FLOW_ASSOCIATION_RESOURCE_TYPE = "VOICE_PHONE_NUMBER"

# Bounded page pull: 20 pages x 1000 = 20,000 associations, which also guards
# against a service returning a repeating NextToken.
_FLOW_ASSOCIATION_MAX_PAGES = 20


def list_voice_flow_associations(instance_id: str, factory: AWSClientFactory) -> Dict[str, str]:
    """
    Paginate ``connect:ListFlowAssociations`` for voice phone numbers and
    return a mapping of phone number ARN -> contact flow ID.

    This is the single implementation shared by the journey pipeline and
    ``AssessmentEngine._list_flow_associations_for_instance``; each caller
    decides its own error policy. **Any API error propagates.**

    ``FlowId`` in the response is a full flow ARN (``…/contact-flow/{id}``);
    only the trailing ID is returned so callers can look it up directly.
    """
    client = factory.get_connect_client()
    flow_id_by_phone_arn: Dict[str, str] = {}
    next_token: Optional[str] = None
    for _ in range(_FLOW_ASSOCIATION_MAX_PAGES):
        kwargs: Dict[str, Any] = {
            "InstanceId": instance_id,
            "ResourceType": FLOW_ASSOCIATION_RESOURCE_TYPE,
            "MaxResults": 1000,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            client, "list_flow_associations", "connect", **kwargs
        )
        for assoc in resp.get("FlowAssociationSummaryList") or []:
            phone_arn = assoc.get("ResourceId") or ""
            flow_arn = assoc.get("FlowId") or ""
            if phone_arn and flow_arn:
                flow_id_by_phone_arn[phone_arn] = flow_arn.rsplit("/", 1)[-1]
        next_token = resp.get("NextToken")
        if not next_token:
            break
    else:
        logger.warning(
            f"ListFlowAssociations stopped after {_FLOW_ASSOCIATION_MAX_PAGES} pages; "
            "phone-number flow associations may be incomplete"
        )
    return flow_id_by_phone_arn


def _list_voice_flow_associations(instance_id: str, factory: AWSClientFactory) -> Dict[str, str]:
    """Journey-pipeline wrapper: fail open to an empty mapping on any error.

    A missing permission or API failure degrades to "no flow association
    found" rather than aborting topology resolution.
    """
    try:
        return list_voice_flow_associations(instance_id, factory)
    except Exception as e:  # noqa: BLE001
        if factory.is_access_denied(e):
            logger.warning("Access denied for ListFlowAssociations; topology will be empty")
        else:
            logger.error(f"Failed to list flow associations: {e}")
        return {}


# Channel filter values GetMetricDataV2 accepts. They do not count toward
# the 100-filter-value limit.
_METRIC_CHANNELS = ("VOICE", "CHAT", "TASK", "EMAIL")

# GetMetricDataV2 allows up to 100 filter values across all filter keys
# (CHANNEL values excluded), so flow IDs are sent in batches of 100.
_METRIC_FILTER_BATCH = 100

_TRAFFIC_LOOKBACK_DAYS_DEFAULT = 30

# With IntervalPeriod TOTAL, GetMetricDataV2 requires EndTime - StartTime to be
# *less than* 35 days. A 90-day window is rejected outright ("The time range
# specified is too long for the interval selected").
_TRAFFIC_LOOKBACK_DAYS_MAX = 34


def _traffic_lookback_days(journey_cfg: Dict[str, Any]) -> int:
    """Validate ``journey_map.traffic_lookback_days``; never raise.

    Invalid values (non-integers, booleans, null, out of range) fall back to
    the default or are clamped, with a warning, so a config typo cannot
    abort journey mapping or silently disable usage classification.
    """
    raw = journey_cfg.get("traffic_lookback_days", _TRAFFIC_LOOKBACK_DAYS_DEFAULT)
    if isinstance(raw, bool) or not isinstance(raw, int):
        logger.warning(
            f"journey_map.traffic_lookback_days must be an integer; got {raw!r}. "
            f"Using {_TRAFFIC_LOOKBACK_DAYS_DEFAULT}."
        )
        return _TRAFFIC_LOOKBACK_DAYS_DEFAULT
    clamped = min(max(raw, 1), _TRAFFIC_LOOKBACK_DAYS_MAX)
    if clamped != raw:
        logger.warning(
            f"journey_map.traffic_lookback_days={raw} is outside 1-"
            f"{_TRAFFIC_LOOKBACK_DAYS_MAX} (GetMetricDataV2 TOTAL-interval limit); "
            f"using {clamped}."
        )
    return clamped


def _resolve_flow_channel_traffic(
    instance_arn: str,
    factory: AWSClientFactory,
    flow_ids: List[str],
    lookback_days: int = _TRAFFIC_LOOKBACK_DAYS_DEFAULT,
) -> ChannelTraffic:
    """
    Resolve observed contacts per flow, per channel.

    A flow's own metadata cannot tell you its channel: ``ContactFlowType`` is
    a *position* in the contact lifecycle (CONTACT_FLOW, CUSTOMER_QUEUE,
    AGENT_WHISPER, …) with no channel dimension, and one flow can serve
    voice, chat and task at once. ``GetMetricDataV2`` ``FLOWS_STARTED``,
    filtered by flow and grouped by flow and channel, gives the real mix.

    Request shape verified against a live instance: ``FLOWS_RESOURCE_ID``
    satisfies the API's resource-filter requirement (a ``CHANNEL``-only
    filter is rejected), grouping by ``CHANNEL`` is supported, and the
    ``FLOWS_RESOURCE_ID`` dimension is a bare flow ID, with the ARN in a
    separate ``FLOWS_RESOURCE_ID_ARN`` key.

    Never returns partial data: any failure yields an empty result with a
    non-``complete`` status, so callers fall back to reachability-only
    tiering instead of classifying on a subset of flows.
    """
    traffic = ChannelTraffic(window_days=lookback_days)
    if not flow_ids:
        traffic.status = "complete"
        return traffic

    # Align to midnight UTC so the window is well-defined and stable.
    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=lookback_days)
    client = factory.get_connect_client()
    collected: Dict[str, Dict[str, int]] = {}

    try:
        for i in range(0, len(flow_ids), _METRIC_FILTER_BATCH):
            batch = flow_ids[i : i + _METRIC_FILTER_BATCH]
            next_token: Optional[str] = None
            while True:
                kwargs: Dict[str, Any] = {
                    "ResourceArn": instance_arn,
                    "StartTime": start,
                    "EndTime": end,
                    "Interval": {"IntervalPeriod": "TOTAL"},
                    "Filters": [
                        {"FilterKey": "FLOWS_RESOURCE_ID", "FilterValues": batch},
                        {"FilterKey": "CHANNEL", "FilterValues": list(_METRIC_CHANNELS)},
                    ],
                    "Groupings": ["FLOWS_RESOURCE_ID", "CHANNEL"],
                    "Metrics": [{"Name": "FLOWS_STARTED"}],
                    "MaxResults": 100,
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                resp = factory.call_api_with_resilience(
                    client, "get_metric_data_v2", "connect", **kwargs
                )
                for res in resp.get("MetricResults") or []:
                    dims = res.get("Dimensions") or {}
                    flow_id = _flow_id_from_dimensions(dims)
                    channel = dims.get("CHANNEL")
                    if not flow_id or not channel:
                        continue
                    for coll in res.get("Collections") or []:
                        value = coll.get("Value")
                        if value and int(value) > 0:
                            collected.setdefault(flow_id, {})[channel] = int(value)

                next_token = resp.get("NextToken")
                if not next_token:
                    break
    except Exception as e:  # noqa: BLE001
        if factory.is_access_denied(e):
            traffic.status = "access_denied"
            logger.warning(
                "Access denied for GetMetricDataV2; flow usage classification is "
                "unavailable and dormant-flow labels are reachability-only"
            )
        else:
            traffic.status = "error"
            logger.warning(
                f"GetMetricDataV2 failed ({e}); discarding partial flow usage data. "
                "Dormant-flow labels are reachability-only for this run."
            )
        return traffic

    traffic.by_flow = collected
    traffic.status = "complete"
    logger.info(f"Resolved channel usage for {len(collected)} flow(s) over {lookback_days} days")
    return traffic


def _flow_id_from_dimensions(dims: Dict[str, Any]) -> Optional[str]:
    """Bare flow ID from a metric result, tolerating an ARN in either key."""
    raw = dims.get("FLOWS_RESOURCE_ID") or dims.get("FLOWS_RESOURCE_ID_ARN")
    if not raw:
        return None
    return str(raw).rsplit("/", 1)[-1]


def _compute_transitive_reachability(
    seed_flow_ids: Set[str],
    parsed_flows: Dict[str, ContactFlowGraph],
) -> Set[str]:
    """
    From a set of seed flows, walk all transfer edges to find all
    transitively reachable flows (the closure).
    """
    reachable: Set[str] = set()
    stack = list(seed_flow_ids)

    while stack:
        flow_id = stack.pop()
        if flow_id in reachable:
            continue
        if flow_id not in parsed_flows:
            continue
        reachable.add(flow_id)

        graph = parsed_flows[flow_id]
        for action in graph.actions.values():
            if action.action_type in _TRANSFER_ACTIONS:
                target = _resolve_static_transfer(action, parsed_flows)
                if target and target not in reachable:
                    stack.append(target)

    return reachable


def _resolve_static_transfer(action, parsed_flows: Dict[str, ContactFlowGraph]) -> Optional[str]:
    """Resolve a static transfer target flow ID from action parameters."""
    params = action.parameters or {}

    # Try ContactFlowId
    flow_ref = params.get("ContactFlowId")
    if isinstance(flow_ref, str) and flow_ref in parsed_flows:
        return flow_ref
    if isinstance(flow_ref, dict):
        val = flow_ref.get("Value", "")
        if val in parsed_flows:
            return val

    # Try FlowModuleId
    module_ref = params.get("FlowModuleId") or params.get("ContactFlowModuleId")
    if isinstance(module_ref, str) and module_ref in parsed_flows:
        return module_ref

    return None


def _classify_tiers(
    phone_entries: List[PhoneNumberEntry],
    parsed_flows: Dict[str, ContactFlowGraph],
    reachable: Set[str],
    channel_traffic: Optional[ChannelTraffic] = None,
) -> List[TierAssignment]:
    """
    Three-tier classification for all flows (see the module docstring).

    Output is sorted by flow ID so identical inputs always produce identical
    reports — this feeds ``findings_diff`` comparisons between runs.
    """
    traffic = channel_traffic or ChannelTraffic()
    usage = traffic.by_flow if traffic.available else {}
    window = traffic.window_days
    assignments: List[TierAssignment] = []

    def _assignment(flow_id: str, tier: str, rationale: str) -> TierAssignment:
        mix = dict(usage.get(flow_id) or {})
        return TierAssignment(
            flow_id=flow_id,
            flow_name=parsed_flows[flow_id].flow_name,
            tier=tier,
            rationale=_append_channel_mix(rationale, mix),
            observed_contact_count=sum(mix.values()) if traffic.available else None,
            observed_window_days=window if traffic.available else None,
            channel_mix=mix,
        )

    for flow_id in sorted(parsed_flows):
        if flow_id in reachable:
            anchor = next((e for e in phone_entries if e.contact_flow_id == flow_id), None)
            if anchor:
                tier = "tier1_tollfree" if anchor.number_type == "TOLL_FREE" else "tier1_did"
                rationale = f"Reachable from {anchor.phone_number} [{anchor.number_type}]"
            else:
                tier = "tier1_did"
                rationale = "Sub-flow reachable from phone-anchored flow"
            assignments.append(_assignment(flow_id, tier, rationale))
        elif sum((usage.get(flow_id) or {}).values()) > 0:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier2_traffic",
                    f"Not phone-reachable, but handled contacts in the last {window} days",
                )
            )
        elif traffic.available:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier3_dormant",
                    f"Not reachable from any phone number and no contacts in the last "
                    f"{window} days",
                )
            )
        else:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier3_dormant",
                    "Not reachable from any phone number (usage metrics unavailable)",
                )
            )

    return assignments


def _append_channel_mix(rationale: str, mix: Dict[str, int]) -> str:
    """Append an observed per-channel contact breakdown to a rationale."""
    if not mix:
        return rationale
    parts = ", ".join(f"{channel} {count}" for channel, count in sorted(mix.items()))
    return f"{rationale} (observed: {parts})"
