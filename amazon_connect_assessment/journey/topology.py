"""
Telephony topology resolution for Caller Journey Mapping.

Discovers which phone numbers (DID + toll-free) map to which contact flows
and classifies all flows into three tiers for scoping.
"""

import logging
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


def resolve_topology(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
    config: Dict[str, Any],
) -> Tuple[List[PhoneNumberEntry], List[TierAssignment]]:
    """
    Resolve the full telephony topology: phone numbers → flows → tiers.

    Returns:
        (phone_entries, tier_assignments)
    """
    # Step 1: List all phone numbers.
    phone_entries = _list_phone_numbers(instance_id, instance_arn, factory, parsed_flows)
    logger.info(f"Discovered {len(phone_entries)} phone numbers")

    # Step 2: Build transitive reachability from phone-anchored flows.
    phone_flow_ids = {e.contact_flow_id for e in phone_entries if e.contact_flow_id}
    reachable = _compute_transitive_reachability(phone_flow_ids, parsed_flows)

    # Step 3: Classify each flow's channel usage from observed traffic. This
    # is what surfaces chat/task/email-only flows, which have no phone
    # number to be reachable from. Fails open to {} without metrics access.
    journey_cfg = config.get("journey_map", {}) or {}
    lookback_days = journey_cfg.get("traffic_lookback_days", _TRAFFIC_LOOKBACK_DAYS_DEFAULT)
    channel_traffic = _resolve_flow_channel_traffic(
        instance_arn=instance_arn,
        factory=factory,
        flow_ids=sorted(parsed_flows.keys()),
        lookback_days=lookback_days,
    )

    # Step 4: Classify tiers.
    max_traffic_flows = journey_cfg.get("max_traffic_flows", 10)
    tier_assignments = _classify_tiers(
        phone_entries,
        parsed_flows,
        reachable,
        max_traffic_flows,
        channel_traffic=channel_traffic,
    )

    return phone_entries, tier_assignments


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


# Only VOICE_PHONE_NUMBER is queried here, deliberately.
#
# This mapping is keyed by ``ListPhoneNumbersV2``'s ``PhoneNumberArn``,
# which is always a Connect-claimed voice number
# (``arn:aws:connect:…:phone-number/…``). The other messaging resource
# types ListFlowAssociations accepts are keyed by *AWS End User
# Messaging* ARNs instead — ``arn:aws:sms-voice:…`` for SMS and
# ``arn:aws:social-messaging:…`` for WhatsApp — so their ResourceIds can
# never match a key in this map. Querying them only burned an API call
# per assessment and merged entries nothing could look up.
#
# ``SMS_PHONE_NUMBER`` was additionally never a valid ResourceType for
# ListFlowAssociations at all: its enum is VOICE_PHONE_NUMBER |
# WHATSAPP_MESSAGING_PHONE_NUMBER | INBOUND_EMAIL | OUTBOUND_EMAIL |
# ANALYTICS_CONNECTOR. Only the singular ``GetFlowAssociation`` accepts
# SMS_PHONE_NUMBER. Since botocore does not validate enum values
# client-side, that call reached the service and came back as a
# ValidationException.
#
# Enumerating true SMS/WhatsApp/email entry points needs a different
# seeding path (End User Messaging DescribePhoneNumbers +
# GetFlowAssociation for SMS; SearchEmailAddresses +
# ListFlowAssociations(INBOUND_EMAIL) for email) and a channel-aware
# entry-point model. See ``_resolve_flow_channel_traffic`` below for the
# traffic-derived channel classification that covers those flows today.
_FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES = ("VOICE_PHONE_NUMBER",)


def _list_voice_flow_associations(
    instance_id: str,
    factory: AWSClientFactory,
) -> Dict[str, str]:
    """
    Paginate ListFlowAssociations for voice phone numbers and return a
    mapping of phone number ARN -> contact flow ID.

    ``FlowId`` in the response is a full flow ARN
    (``…/contact-flow/{id}``); this returns just the trailing ID.
    Fails open (returns an empty mapping) on any error, including
    access denied, so a missing permission degrades to "no flow
    association found" rather than crashing topology resolution.
    """
    flow_id_by_phone_arn: Dict[str, str] = {}
    client = factory.get_connect_client()

    for resource_type in _FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES:
        next_token: Optional[str] = None
        try:
            while True:
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
                for assoc in resp.get("FlowAssociationSummaryList", []):
                    phone_arn = assoc.get("ResourceId") or ""
                    flow_arn = assoc.get("FlowId") or ""
                    if phone_arn and flow_arn:
                        flow_id_by_phone_arn[phone_arn] = flow_arn.rsplit("/", 1)[-1]

                next_token = resp.get("NextToken")
                if not next_token:
                    break

        except Exception as e:
            if factory.is_access_denied(e):
                logger.warning("Access denied for ListFlowAssociations; topology will be empty")
            else:
                logger.error(f"Failed to list flow associations: {e}")

    return flow_id_by_phone_arn


# Channels GetMetricDataV2 can filter flow metrics by. Matches the
# SearchContacts Channels enum.
_METRIC_CHANNELS = ("VOICE", "CHAT", "TASK", "EMAIL")

# GetMetricDataV2 caps FilterValues at 100 entries per filter.
_METRIC_FILTER_BATCH = 100

_TRAFFIC_LOOKBACK_DAYS_DEFAULT = 30


def _resolve_flow_channel_traffic(
    instance_arn: str,
    factory: AWSClientFactory,
    flow_ids: List[str],
    lookback_days: int = _TRAFFIC_LOOKBACK_DAYS_DEFAULT,
) -> Dict[str, Dict[str, int]]:
    """
    Classify each flow's channel usage from observed traffic.

    Returns flow ID -> {channel: contacts started}, omitting channels with
    no contacts and flows with no traffic at all.

    A flow's own metadata cannot tell you its channel: ``ContactFlowType``
    is a *position* in the contact lifecycle (CONTACT_FLOW, CUSTOMER_QUEUE,
    AGENT_WHISPER, …) with no channel dimension, and one flow legitimately
    serves voice, chat and task at once. So channel is resolved empirically
    instead — ``GetMetricDataV2`` can filter flow metrics by channel, giving
    a real per-channel contact count per flow.

    This is queried per channel (filtered) rather than grouped by channel,
    because CHANNEL is documented as a filter dimension for flow metrics
    while grouping support is not guaranteed.

    Fails open: returns whatever it collected (possibly ``{}``) on any
    error, including a missing ``connect:GetMetricDataV2`` permission, so
    callers degrade to reachability-only tiering rather than failing.
    """
    traffic: Dict[str, Dict[str, int]] = {}
    if not flow_ids:
        return traffic

    from datetime import datetime, timedelta, timezone

    # Align to midnight UTC so the window is well-defined and stable.
    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=lookback_days)

    client = factory.get_connect_client()
    batches = [
        flow_ids[i : i + _METRIC_FILTER_BATCH]
        for i in range(0, len(flow_ids), _METRIC_FILTER_BATCH)
    ]

    for channel in _METRIC_CHANNELS:
        for batch in batches:
            next_token: Optional[str] = None
            try:
                while True:
                    kwargs: Dict[str, Any] = {
                        "ResourceArn": instance_arn,
                        "StartTime": start,
                        "EndTime": end,
                        "Interval": {"IntervalPeriod": "TOTAL"},
                        "Filters": [
                            {"FilterKey": "FLOWS_RESOURCE_ID", "FilterValues": batch},
                            {"FilterKey": "CHANNEL", "FilterValues": [channel]},
                        ],
                        "Groupings": ["FLOWS_RESOURCE_ID"],
                        "Metrics": [{"Name": "FLOWS_STARTED"}],
                    }
                    if next_token:
                        kwargs["NextToken"] = next_token

                    resp = factory.call_api_with_resilience(
                        client, "get_metric_data_v2", "connect", **kwargs
                    )
                    for res in resp.get("MetricResults", []) or []:
                        flow_id = (res.get("Dimensions") or {}).get("FLOWS_RESOURCE_ID")
                        if not flow_id:
                            continue
                        for coll in res.get("Collections", []) or []:
                            value = coll.get("Value")
                            if not value:
                                continue
                            count = int(value)
                            if count > 0:
                                traffic.setdefault(flow_id, {})[channel] = count

                    next_token = resp.get("NextToken")
                    if not next_token:
                        break

            except Exception as e:
                if factory.is_access_denied(e):
                    logger.warning(
                        "Access denied for GetMetricDataV2; flow channel classification "
                        "and tier 2 traffic promotion are unavailable"
                    )
                    return traffic
                logger.warning(f"Failed to resolve {channel} flow traffic: {e}")
                break

    logger.info(f"Resolved channel traffic for {len(traffic)} flow(s)")
    return traffic


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
    max_traffic_flows: int,
    channel_traffic: Optional[Dict[str, Dict[str, int]]] = None,
) -> List[TierAssignment]:
    """
    Three-tier classification for all flows.

    ``channel_traffic`` maps flow ID -> {channel: contacts}. When supplied
    it promotes non-phone-reachable flows that still carry real traffic out
    of ``tier3_dormant`` and into ``tier2_traffic``, highest-volume first,
    capped at ``max_traffic_flows``. When it is empty or None (no metrics
    permission, or metrics unavailable) every unreachable flow stays
    dormant, preserving the previous behaviour.
    """
    assignments: List[TierAssignment] = []
    remaining = set(parsed_flows.keys()) - reachable
    channel_traffic = channel_traffic or {}

    # Tier 1: phone-reachable
    for flow_id in reachable:
        # Find which number anchors this flow (if directly associated).
        anchor = next((e for e in phone_entries if e.contact_flow_id == flow_id), None)
        if anchor:
            tier = "tier1_tollfree" if anchor.number_type == "TOLL_FREE" else "tier1_did"
            rationale = f"Reachable from {anchor.phone_number} [{anchor.number_type}]"
        else:
            tier = "tier1_did"
            rationale = "Sub-flow reachable from phone-anchored flow"

        mix = channel_traffic.get(flow_id) or {}
        assignments.append(
            TierAssignment(
                flow_id=flow_id,
                flow_name=parsed_flows[flow_id].flow_name,
                tier=tier,
                rationale=_append_channel_mix(rationale, mix),
                contact_count_30d=sum(mix.values()) if mix else None,
                channel_mix=dict(mix),
            )
        )

    # Tier 2: not phone-reachable, but observed carrying contacts. This is
    # the only way a chat/task/email-only flow becomes visible to the
    # journey pipeline — chat has no control-plane entry point to seed from
    # (StartChatContact takes the flow ID from the caller), so observed
    # traffic is the sole signal. Ranked by volume so the cap keeps the
    # busiest flows.
    ranked = sorted(
        (f for f in remaining if sum((channel_traffic.get(f) or {}).values()) > 0),
        key=lambda f: sum(channel_traffic[f].values()),
        reverse=True,
    )
    tier2_ids = set(ranked[:max_traffic_flows])

    for flow_id in tier2_ids:
        mix = channel_traffic[flow_id]
        total = sum(mix.values())
        assignments.append(
            TierAssignment(
                flow_id=flow_id,
                flow_name=parsed_flows[flow_id].flow_name,
                tier="tier2_traffic",
                rationale=_append_channel_mix(
                    f"Not phone-reachable, but handled {total} contact(s) "
                    f"in the last {_TRAFFIC_LOOKBACK_DAYS_DEFAULT} days",
                    mix,
                ),
                contact_count_30d=total,
                channel_mix=dict(mix),
            )
        )

    # Tier 3: everything else.
    for flow_id in remaining - tier2_ids:
        mix = channel_traffic.get(flow_id) or {}
        total = sum(mix.values())
        if total > 0:
            rationale = (
                f"Not phone-reachable; {total} contact(s) observed but outside "
                f"the top {max_traffic_flows} by volume"
            )
        else:
            rationale = "Not reachable from any phone number"
        assignments.append(
            TierAssignment(
                flow_id=flow_id,
                flow_name=parsed_flows[flow_id].flow_name,
                tier="tier3_dormant",
                rationale=rationale,
                contact_count_30d=total if mix else None,
                channel_mix=dict(mix),
            )
        )

    return assignments


def _append_channel_mix(rationale: str, mix: Dict[str, int]) -> str:
    """Append an observed per-channel contact breakdown to a rationale."""
    if not mix:
        return rationale
    parts = ", ".join(f"{channel} {count}" for channel, count in sorted(mix.items()))
    return f"{rationale} (observed: {parts})"
