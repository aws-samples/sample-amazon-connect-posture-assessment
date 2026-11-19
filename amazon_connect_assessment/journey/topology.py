"""
Entry-point topology for Customer Journey Mapping.

Discovers every place a customer contact enters the instance, on every
channel, and the contact flow each one starts:

* voice phone numbers (DID / toll-free)  -> VOICE
* SMS and WhatsApp numbers               -> CHAT (Connect reports them as chat)
* inbound email addresses                -> EMAIL
* traffic-observed entry flows           -> any channel. Web chat, tasks and
  API-started contacts have no control-plane association to discover
  (``StartChatContact`` takes the flow ID from the caller), so a contact flow
  that starts contacts on a channel without being reachable from that
  channel's associations is treated as an entry point for it.

Flows are then tiered:

* tier 1 — reachable from an entry point; stitched and enumerated as journeys
  (``tier1_did`` / ``tier1_tollfree`` / ``tier1_messaging`` / ``tier1_email`` /
  ``tier1_observed``, by the first entry that reaches the flow)
* tier 2 — observed starting contacts but not reachable from any entry point:
  typically queue, hold and whisper flows, or dynamically invoked sub-flows.
  In use, so not dormant.
* tier 3 — not reachable and no observed contacts (or usage metrics were
  unavailable). These are the dormant-flow review candidates.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..aws_client_factory import AWSClientFactory
from ..models import ContactFlowGraph
from .models import CHANNELS, EntryPoint, PhoneNumberEntry, TierAssignment

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


@dataclass
class EntryDiscovery:
    """Everything topology resolution found for one instance."""

    entry_points: List[EntryPoint] = field(default_factory=list)
    # Every claimed phone number with its voice flow, if any (pre-multichannel
    # shape, kept for the voice-only consumers).
    phone_entries: List[PhoneNumberEntry] = field(default_factory=list)
    tier_assignments: List[TierAssignment] = field(default_factory=list)
    channel_traffic: "ChannelTraffic" = field(default_factory=lambda: ChannelTraffic())
    # Human-readable discovery gaps, and the channels each gap leaves
    # incompletely covered.
    limitations: List[str] = field(default_factory=list)
    incomplete_channels: Set[str] = field(default_factory=set)
    denied_permissions: List[str] = field(default_factory=list)


def discover_entry_points(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
    config: Dict[str, Any],
) -> EntryDiscovery:
    """Discover entry points on every channel, then tier every flow.

    Every source fails open: a denied permission or API error narrows
    coverage for the channels that source feeds, and is recorded, but never
    aborts journey mapping.
    """
    found = EntryDiscovery()

    def _gap(source: str, permission: str, channels: Iterable[str], error: Exception) -> None:
        if factory.is_access_denied(error):
            found.denied_permissions.append(permission)
            found.limitations.append(f"{source}: access denied ({permission})")
        else:
            found.limitations.append(f"{source}: {error}")
        found.incomplete_channels.update(channels)
        logger.warning(f"Entry discovery: {found.limitations[-1]}")

    # Phone numbers back voice, SMS and WhatsApp entries.
    try:
        raw_numbers = _list_raw_phone_numbers(instance_arn, factory)
    except Exception as e:  # noqa: BLE001
        raw_numbers = []
        _gap("ListPhoneNumbersV2", "connect:ListPhoneNumbersV2", ("VOICE", "CHAT"), e)
    numbers_by_arn = {n["PhoneNumberArn"]: n for n in raw_numbers if n.get("PhoneNumberArn")}

    associations: Dict[str, Dict[str, str]] = {}
    for resource_type, (channel, _) in ENTRY_ASSOCIATION_TYPES.items():
        try:
            associations[resource_type] = list_flow_associations(
                instance_id, factory, resource_type
            )
        except Exception as e:  # noqa: BLE001
            associations[resource_type] = {}
            _gap(
                f"ListFlowAssociations {resource_type}",
                "connect:ListFlowAssociations",
                (channel,),
                e,
            )

    email_by_arn: Dict[str, Dict[str, Any]] = {}
    if associations.get("INBOUND_EMAIL"):
        try:
            email_by_arn = _list_email_addresses(instance_id, factory)
        except Exception as e:  # noqa: BLE001
            # Entries are still created, labelled by address ID instead.
            _gap("SearchEmailAddresses", "connect:SearchEmailAddresses", (), e)

    def _add(entry: EntryPoint) -> None:
        if entry.contact_flow_id not in parsed_flows:
            found.limitations.append(
                f"{entry.channel} {entry.entry_type} entry targets flow "
                f"{entry.contact_flow_id}, which is unavailable or unparseable"
            )
            found.incomplete_channels.add(entry.channel)
            return
        entry.contact_flow_name = parsed_flows[entry.contact_flow_id].flow_name
        found.entry_points.append(entry)

    voice = associations.get("VOICE_PHONE_NUMBER", {})
    for num in raw_numbers:
        arn = num.get("PhoneNumberArn", "")
        flow_id = voice.get(arn)
        found.phone_entries.append(
            PhoneNumberEntry(
                phone_number=num.get("PhoneNumber", ""),
                number_type=num.get("PhoneNumberType", "DID"),
                country_code=num.get("PhoneNumberCountryCode", ""),
                contact_flow_id=flow_id,
                contact_flow_name=(
                    parsed_flows[flow_id].flow_name if flow_id in parsed_flows else None
                ),
                target_arn=num.get("TargetArn"),
            )
        )
        if flow_id:
            _add(
                EntryPoint(
                    channel="VOICE",
                    entry_type=num.get("PhoneNumberType", "DID") or "DID",
                    identifier=num.get("PhoneNumber", ""),
                    contact_flow_id=flow_id,
                    source="ListFlowAssociations:VOICE_PHONE_NUMBER",
                    country_code=num.get("PhoneNumberCountryCode", "") or "",
                    description=num.get("PhoneNumberDescription", "") or "",
                )
            )

    for resource_type in ("SMS_PHONE_NUMBER", "WHATSAPP_MESSAGING_PHONE_NUMBER"):
        channel, entry_type = ENTRY_ASSOCIATION_TYPES[resource_type]
        for arn, flow_id in sorted(associations.get(resource_type, {}).items()):
            num = numbers_by_arn.get(arn)
            _add(
                EntryPoint(
                    channel=channel,
                    entry_type=entry_type,
                    # Connect-claimed numbers resolve to E.164. A number held
                    # only in AWS End User Messaging keeps its ARN's ID.
                    identifier=(
                        num.get("PhoneNumber", "")
                        if num
                        else f"{entry_type.lower()}:{arn.rsplit('/', 1)[-1]}"
                    ),
                    contact_flow_id=flow_id,
                    source=f"ListFlowAssociations:{resource_type}",
                    country_code=(num or {}).get("PhoneNumberCountryCode", "") or "",
                    description=(num or {}).get("PhoneNumberDescription", "") or "",
                )
            )

    for arn, flow_id in sorted(associations.get("INBOUND_EMAIL", {}).items()):
        item = email_by_arn.get(arn) or {}
        _add(
            EntryPoint(
                channel="EMAIL",
                entry_type="EMAIL_ADDRESS",
                identifier=item.get("EmailAddress") or f"email:{arn.rsplit('/', 1)[-1]}",
                contact_flow_id=flow_id,
                source="ListFlowAssociations:INBOUND_EMAIL",
                description=item.get("DisplayName") or item.get("Description") or "",
            )
        )

    journey_cfg = config.get("journey_map", {}) or {}
    found.channel_traffic = _resolve_flow_channel_traffic(
        instance_arn=instance_arn,
        factory=factory,
        flow_ids=sorted(parsed_flows.keys()),
        lookback_days=_traffic_lookback_days(journey_cfg),
    )
    if not found.channel_traffic.available:
        # An optional discovery signal: without it, flows used only via web
        # chat, tasks or the API cannot be found, but association-based
        # coverage is unaffected, so this is recorded rather than marking
        # channels incomplete.
        found.limitations.append(
            f"usage metrics unavailable ({found.channel_traffic.status}): entry flows "
            "with no association (web chat, tasks, API-started contacts) could not be "
            "discovered"
        )
        if found.channel_traffic.status == "access_denied":
            found.denied_permissions.append("connect:GetMetricDataV2")

    found.entry_points.extend(
        _observed_entry_points(found.entry_points, parsed_flows, found.channel_traffic)
    )
    found.entry_points.sort(key=_entry_sort_key)
    found.tier_assignments = _classify_tiers(
        found.entry_points, parsed_flows, found.channel_traffic
    )
    found.limitations = list(dict.fromkeys(found.limitations))
    found.denied_permissions = list(dict.fromkeys(found.denied_permissions))
    logger.info(
        "Discovered %d entry point(s): %s",
        len(found.entry_points),
        {c: sum(1 for e in found.entry_points if e.channel == c) for c in CHANNELS},
    )
    return found


def resolve_topology(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
    config: Dict[str, Any],
) -> Tuple[List[PhoneNumberEntry], List[TierAssignment], "ChannelTraffic"]:
    """Voice-era wrapper around :func:`discover_entry_points`."""
    found = discover_entry_points(instance_id, instance_arn, factory, parsed_flows, config)
    return found.phone_entries, found.tier_assignments, found.channel_traffic


_CHANNEL_ORDER = {channel: i for i, channel in enumerate(CHANNELS)}
_ENTRY_TYPE_ORDER = {
    "DID": 0,
    "TOLL_FREE": 0,
    "SMS": 1,
    "WHATSAPP": 1,
    "EMAIL_ADDRESS": 2,
    "OBSERVED_FLOW": 3,
}


def _entry_sort_key(entry: EntryPoint) -> Tuple[int, int, str]:
    return (
        _CHANNEL_ORDER.get(entry.channel, len(CHANNELS)),
        _ENTRY_TYPE_ORDER.get(entry.entry_type, 9),
        entry.identifier,
    )


# Flow types that can start an inbound contact. Queue, hold, whisper and
# transfer flows also start contacts (FLOWS_STARTED counts them) but are
# never where a customer enters, so they can only ever be tier 2.
_ENTRY_CAPABLE_FLOW_TYPES = {"CONTACT_FLOW", ""}


def _observed_entry_points(
    anchored: List[EntryPoint],
    parsed_flows: Dict[str, ContactFlowGraph],
    traffic: "ChannelTraffic",
) -> List[EntryPoint]:
    """Entry flows a channel's traffic reveals but its associations don't explain.

    Per channel, a flow is an observed entry when it started contacts on that
    channel, can start an inbound contact, and is not reachable from that
    channel's existing entries. Reachability is checked per channel: a voice
    IVR transferring to a flow says nothing about chat customers who start
    there directly. Candidates are taken busiest first, and each one's own
    reachable sub-flows are then excluded, so a sub-flow is not double-counted
    as its own entry.
    """
    if not traffic.available:
        return []
    observed: List[EntryPoint] = []
    for channel in CHANNELS:
        seeds = {e.contact_flow_id for e in anchored if e.channel == channel}
        covered = _compute_transitive_reachability(seeds, parsed_flows)
        candidates = sorted(
            (
                flow_id
                for flow_id, mix in traffic.by_flow.items()
                if mix.get(channel, 0) > 0
                and flow_id in parsed_flows
                and (parsed_flows[flow_id].flow_type or "") in _ENTRY_CAPABLE_FLOW_TYPES
            ),
            key=lambda f: (-traffic.by_flow[f][channel], f),
        )
        for flow_id in candidates:
            if flow_id in covered:
                continue
            observed.append(
                EntryPoint(
                    channel=channel,
                    entry_type="OBSERVED_FLOW",
                    identifier=parsed_flows[flow_id].flow_name or flow_id,
                    contact_flow_id=flow_id,
                    contact_flow_name=parsed_flows[flow_id].flow_name,
                    source="GetMetricDataV2:FLOWS_STARTED",
                    observed_contact_count=traffic.by_flow[flow_id][channel],
                )
            )
            covered |= _compute_transitive_reachability({flow_id}, parsed_flows)
    return observed


def _list_raw_phone_numbers(instance_arn: str, factory: AWSClientFactory) -> List[Dict[str, Any]]:
    """Paginate ListPhoneNumbersV2 for the instance. Errors propagate.

    ``TargetArn`` on each number is the instance/TDG it is claimed to, never
    its flow; the number -> flow mapping comes from ListFlowAssociations.
    """
    client = factory.get_connect_client()
    numbers: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    for _ in range(_FLOW_ASSOCIATION_MAX_PAGES * 20):
        kwargs: Dict[str, Any] = {"TargetArn": instance_arn, "MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            client, "list_phone_numbers_v2", "connect", **kwargs
        )
        numbers.extend(resp.get("ListPhoneNumbersSummaryList") or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return numbers


def _list_email_addresses(instance_id: str, factory: AWSClientFactory) -> Dict[str, Dict[str, Any]]:
    """Email address ARN -> SearchEmailAddresses item. Errors propagate."""
    client = factory.get_connect_client()
    by_arn: Dict[str, Dict[str, Any]] = {}
    next_token: Optional[str] = None
    for _ in range(_FLOW_ASSOCIATION_MAX_PAGES):
        kwargs: Dict[str, Any] = {"InstanceId": instance_id, "MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            client, "search_email_addresses", "connect", **kwargs
        )
        for item in resp.get("EmailAddresses") or []:
            if item.get("EmailAddressArn"):
                by_arn[item["EmailAddressArn"]] = item
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return by_arn


# ListFlowAssociations resource types that are customer entry points, and the
# channel their contacts arrive on (entry type None = taken from the number).
#
# Each type is kept separate and keyed by (channel, resource). Two earlier
# behaviours were wrong in opposite directions:
#   * merging SMS/WhatsApp into the voice map keyed only by number ARN meant a
#     number with both a voice and an SMS flow had its voice journey
#     overwritten by the SMS flow;
#   * dropping SMS on the premise that its associations are keyed by AWS End
#     User Messaging ARNs lost real entries. Verified live: a Connect-claimed
#     toll-free number's SMS association uses the same arn:aws:connect
#     phone-number ARN as ListPhoneNumbersV2.
# SMS_PHONE_NUMBER is absent from the SDK's documented ListFlowAssociations
# enum but accepted by the service; if that ever changes, the failure is
# recorded as a CHAT coverage gap rather than breaking discovery.
ENTRY_ASSOCIATION_TYPES: Dict[str, Tuple[str, Optional[str]]] = {
    "VOICE_PHONE_NUMBER": ("VOICE", None),
    "SMS_PHONE_NUMBER": ("CHAT", "SMS"),
    "WHATSAPP_MESSAGING_PHONE_NUMBER": ("CHAT", "WHATSAPP"),
    "INBOUND_EMAIL": ("EMAIL", "EMAIL_ADDRESS"),
}

FLOW_ASSOCIATION_RESOURCE_TYPE = "VOICE_PHONE_NUMBER"

# Bounded page pull: 20 pages x 1000 = 20,000 associations, which also guards
# against a service returning a repeating NextToken.
_FLOW_ASSOCIATION_MAX_PAGES = 20


def list_flow_associations(
    instance_id: str,
    factory: AWSClientFactory,
    resource_type: str = FLOW_ASSOCIATION_RESOURCE_TYPE,
) -> Dict[str, str]:
    """
    Paginate ``connect:ListFlowAssociations`` for one resource type and
    return resource ARN -> contact flow ID. **Any API error propagates**;
    each caller owns its error policy.

    ``FlowId`` in the response is a full flow ARN (``…/contact-flow/{id}``);
    only the trailing ID is returned.
    """
    client = factory.get_connect_client()
    flow_id_by_resource: Dict[str, str] = {}
    next_token: Optional[str] = None
    for _ in range(_FLOW_ASSOCIATION_MAX_PAGES):
        kwargs: Dict[str, Any] = {
            "InstanceId": instance_id,
            "ResourceType": resource_type,
            "MaxResults": 1000,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            client, "list_flow_associations", "connect", **kwargs
        )
        for assoc in resp.get("FlowAssociationSummaryList") or []:
            resource = assoc.get("ResourceId") or ""
            flow_arn = assoc.get("FlowId") or ""
            if resource and flow_arn:
                flow_id_by_resource[resource] = flow_arn.rsplit("/", 1)[-1]
        next_token = resp.get("NextToken")
        if not next_token:
            break
    else:
        logger.warning(
            f"ListFlowAssociations {resource_type} stopped after "
            f"{_FLOW_ASSOCIATION_MAX_PAGES} pages; associations may be incomplete"
        )
    return flow_id_by_resource


def list_voice_flow_associations(instance_id: str, factory: AWSClientFactory) -> Dict[str, str]:
    """Voice phone number ARN -> flow ID (used by the HTML journey map fallback)."""
    return list_flow_associations(instance_id, factory, "VOICE_PHONE_NUMBER")


def _list_voice_flow_associations(instance_id: str, factory: AWSClientFactory) -> Dict[str, str]:
    """Fail-open wrapper: an empty mapping on any error."""
    try:
        return list_voice_flow_associations(instance_id, factory)
    except Exception as e:  # noqa: BLE001
        if factory.is_access_denied(e):
            logger.warning("Access denied for ListFlowAssociations; topology will be empty")
        else:
            logger.error(f"Failed to list flow associations: {e}")
        return {}


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


def _tier_for(entry: EntryPoint) -> str:
    if entry.entry_type == "TOLL_FREE":
        return "tier1_tollfree"
    if entry.entry_type in ("SMS", "WHATSAPP"):
        return "tier1_messaging"
    if entry.entry_type == "EMAIL_ADDRESS":
        return "tier1_email"
    if entry.entry_type == "OBSERVED_FLOW":
        return "tier1_observed"
    return "tier1_did"


def _entry_label(entry: EntryPoint) -> str:
    if entry.entry_type == "OBSERVED_FLOW":
        return f"observed {entry.channel} entry flow"
    return f"{entry.identifier} [{entry.entry_type}]"


def _classify_tiers(
    entry_points: List[EntryPoint],
    parsed_flows: Dict[str, ContactFlowGraph],
    channel_traffic: Optional["ChannelTraffic"] = None,
) -> List[TierAssignment]:
    """
    Three-tier classification for all flows (see the module docstring).

    A flow reached by several entries takes the tier of the highest-priority
    one (phone, then messaging, then email, then observed). Output is sorted
    by flow ID so identical inputs always produce identical reports.
    """
    traffic = channel_traffic or ChannelTraffic()
    usage = traffic.by_flow if traffic.available else {}
    window = traffic.window_days

    reached_by: Dict[str, EntryPoint] = {}
    for entry in sorted(entry_points, key=_entry_sort_key):
        for flow_id in _compute_transitive_reachability({entry.contact_flow_id}, parsed_flows):
            reached_by.setdefault(flow_id, entry)

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

    assignments: List[TierAssignment] = []
    for flow_id in sorted(parsed_flows):
        entry = reached_by.get(flow_id)
        if entry is not None:
            if flow_id == entry.contact_flow_id:
                rationale = f"Entry flow for {_entry_label(entry)}"
            else:
                rationale = f"Sub-flow reachable from {_entry_label(entry)}"
            assignments.append(_assignment(flow_id, _tier_for(entry), rationale))
        elif sum((usage.get(flow_id) or {}).values()) > 0:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier2_traffic",
                    f"Not reachable from any entry point, but started contacts in the last "
                    f"{window} days (typically a queue, hold, or whisper flow, or a "
                    "dynamically invoked sub-flow)",
                )
            )
        elif traffic.available:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier3_dormant",
                    f"Not reachable from any entry point and no contacts in the last {window} days",
                )
            )
        else:
            assignments.append(
                _assignment(
                    flow_id,
                    "tier3_dormant",
                    "Not reachable from any entry point (usage metrics unavailable)",
                )
            )
    return assignments


def _append_channel_mix(rationale: str, mix: Dict[str, int]) -> str:
    """Append an observed per-channel contact breakdown to a rationale."""
    if not mix:
        return rationale
    parts = ", ".join(f"{channel} {count}" for channel, count in sorted(mix.items()))
    return f"{rationale} (observed: {parts})"
