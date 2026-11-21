"""
Tests for per-flow channel classification and traffic-based tiering.

Guarded here:

1. ``ListFlowAssociations`` is only ever asked for ``VOICE_PHONE_NUMBER``,
   through one shared helper. SMS and WhatsApp associations are keyed by
   End User Messaging ARNs, which can never match the ``PhoneNumberArn``
   keys this map is looked up by, so querying them was wasted calls.

2. Channel usage comes from ``GetMetricDataV2``, in one request per
   100-flow batch, and is never partial: any failure discards everything
   collected so ranking/classification never runs on a subset.

3. Tier 2 ("in use, not phone-reachable") flows are *reported*, not
   enumerated: they stay out of the super graph, out of the dormant list,
   and appear in ``journey-scope-001`` instead of disappearing from both.

The request shape asserted below was verified against a live Connect
instance: ``FLOWS_RESOURCE_ID`` satisfies the API's resource-filter
requirement, ``CHANNEL`` is a valid grouping, and the returned
``FLOWS_RESOURCE_ID`` dimension is a bare flow ID.
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from amazon_connect_assessment.journey.journey_scorer import generate_journey_findings
from amazon_connect_assessment.journey.models import (
    EntryPoint,
    JourneyMapResult,
    TierAssignment,
)
from amazon_connect_assessment.journey.super_graph import build_super_graph
from amazon_connect_assessment.journey.topology import (
    ChannelTraffic,
    _classify_tiers,
    _list_voice_flow_associations,
    _resolve_flow_channel_traffic,
    _traffic_lookback_days,
    list_voice_flow_associations,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlowGraph, FlowAction

INSTANCE_ID = "11111111-2222-3333-4444-555555555555"
INSTANCE_ARN = f"arn:aws:connect:us-east-1:123456789012:instance/{INSTANCE_ID}"


def _flow(flow_id: str) -> ContactFlowGraph:
    return ContactFlowGraph(flow_id=flow_id, flow_name=flow_id, flow_type="CONTACT_FLOW")


def _flows(*ids: str) -> Dict[str, ContactFlowGraph]:
    return {flow_id: _flow(flow_id) for flow_id in ids}


def _factory(dispatch, access_denied: bool = False) -> MagicMock:
    factory = MagicMock()
    factory.get_connect_client.return_value = MagicMock()
    factory.call_api_with_resilience.side_effect = dispatch
    factory.is_access_denied.return_value = access_denied
    return factory


def _metric(flow_id: str, channel: str, value: Any, arn_only: bool = False) -> Dict[str, Any]:
    dims: Dict[str, Any] = {"CHANNEL": channel}
    arn = f"{INSTANCE_ARN}/contact-flow/{flow_id}"
    if arn_only:
        dims["FLOWS_RESOURCE_ID_ARN"] = arn
    else:
        dims["FLOWS_RESOURCE_ID"] = flow_id
        dims["FLOWS_RESOURCE_ID_ARN"] = arn
    return {
        "Dimensions": dims,
        "Collections": [{"Metric": {"Name": "FLOWS_STARTED"}, "Value": value}],
    }


def _traffic(by_flow: Dict[str, Dict[str, int]], window: int = 30) -> ChannelTraffic:
    return ChannelTraffic(by_flow=by_flow, status="complete", window_days=window)


# --- Flow associations -----------------------------------------------------


class TestFlowAssociations:
    def test_only_voice_phone_number_is_queried(self):
        seen: List[str] = []

        def _dispatch(_c, operation_name, _s=None, **kwargs):
            assert operation_name == "list_flow_associations"
            seen.append(kwargs["ResourceType"])
            return {"FlowAssociationSummaryList": [], "NextToken": None}

        list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch))
        assert seen == ["VOICE_PHONE_NUMBER"]

    def test_shared_helper_propagates_errors(self):
        # Each caller owns its error policy, so the shared helper must not
        # swallow anything.
        def _dispatch(*_a, **_k):
            raise RuntimeError("ValidationException")

        with pytest.raises(RuntimeError):
            list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch))

    def test_journey_wrapper_fails_open(self):
        def _dispatch(*_a, **_k):
            raise RuntimeError("ValidationException")

        assert _list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch)) == {}

    def test_page_cap_stops_a_repeating_token(self):
        calls: List[int] = []

        def _dispatch(*_a, **_k):
            calls.append(1)
            return {"FlowAssociationSummaryList": [], "NextToken": "same-token"}

        list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch))
        assert len(calls) == 20


# --- Usage metrics ---------------------------------------------------------


class TestResolveFlowChannelTraffic:
    def test_one_request_per_batch_grouped_by_flow_and_channel(self):
        requests: List[Dict[str, Any]] = []

        def _dispatch(_c, operation_name, _s=None, **kwargs):
            assert operation_name == "get_metric_data_v2"
            requests.append(kwargs)
            return {
                "MetricResults": [
                    _metric("flow-ivr", "VOICE", 1200),
                    _metric("flow-ivr", "CHAT", 40),
                    _metric("flow-webchat", "CHAT", 310),
                ]
            }

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-ivr", "flow-webchat"]
        )

        assert traffic.status == "complete"
        assert traffic.by_flow == {
            "flow-ivr": {"VOICE": 1200, "CHAT": 40},
            "flow-webchat": {"CHAT": 310},
        }
        (request,) = requests  # one call, not one per channel
        assert request["Groupings"] == ["FLOWS_RESOURCE_ID", "CHANNEL"]
        filters = {f["FilterKey"]: f["FilterValues"] for f in request["Filters"]}
        assert filters["FLOWS_RESOURCE_ID"] == ["flow-ivr", "flow-webchat"]
        assert filters["CHANNEL"] == ["VOICE", "CHAT", "TASK", "EMAIL"]
        assert request["Interval"] == {"IntervalPeriod": "TOTAL"}

    def test_flows_are_batched_by_one_hundred(self):
        batch_sizes: List[int] = []

        def _dispatch(_c, _op, _s=None, **kwargs):
            values = next(
                f["FilterValues"]
                for f in kwargs["Filters"]
                if f["FilterKey"] == "FLOWS_RESOURCE_ID"
            )
            batch_sizes.append(len(values))
            return {"MetricResults": []}

        flow_ids = [f"flow-{i:03d}" for i in range(150)]
        _resolve_flow_channel_traffic(INSTANCE_ARN, _factory(_dispatch), flow_ids)
        assert batch_sizes == [100, 50]

    def test_arn_only_dimension_is_tolerated(self):
        def _dispatch(*_a, **_k):
            return {"MetricResults": [_metric("flow-a", "TASK", 3, arn_only=True)]}

        traffic = _resolve_flow_channel_traffic(INSTANCE_ARN, _factory(_dispatch), ["flow-a"])
        assert traffic.by_flow == {"flow-a": {"TASK": 3}}

    def test_zero_and_null_values_are_omitted(self):
        def _dispatch(*_a, **_k):
            return {
                "MetricResults": [_metric("flow-a", "VOICE", 0), _metric("flow-b", "CHAT", None)]
            }

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-a", "flow-b"]
        )
        assert traffic.status == "complete"
        assert traffic.by_flow == {}

    def test_pagination_is_followed(self):
        def _dispatch(_c, _op, _s=None, **kwargs):
            if not kwargs.get("NextToken"):
                return {"MetricResults": [_metric("flow-a", "VOICE", 5)], "NextToken": "c1"}
            return {"MetricResults": [_metric("flow-b", "EMAIL", 7)]}

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-a", "flow-b"]
        )
        assert traffic.by_flow == {"flow-a": {"VOICE": 5}, "flow-b": {"EMAIL": 7}}

    def test_failure_on_a_later_batch_discards_everything(self):
        # Review finding: one throttled batch used to leave earlier batches'
        # counts in place, so ranking ran on partial data.
        calls: List[int] = []

        def _dispatch(*_a, **_k):
            calls.append(1)
            if len(calls) == 1:
                return {"MetricResults": [_metric("flow-000", "CHAT", 9)]}
            raise RuntimeError("ThrottlingException")

        flow_ids = [f"flow-{i:03d}" for i in range(150)]
        traffic = _resolve_flow_channel_traffic(INSTANCE_ARN, _factory(_dispatch), flow_ids)
        assert traffic.status == "error"
        assert traffic.by_flow == {}
        assert not traffic.available

    def test_access_denied_is_reported_distinctly(self):
        def _dispatch(*_a, **_k):
            raise RuntimeError("AccessDeniedException")

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch, access_denied=True), ["flow-a"]
        )
        assert traffic.status == "access_denied"
        assert traffic.by_flow == {}

    def test_no_flows_makes_no_api_calls(self):
        def _dispatch(*_a, **_k):
            raise AssertionError("should not be called")

        traffic = _resolve_flow_channel_traffic(INSTANCE_ARN, _factory(_dispatch), [])
        assert traffic.status == "complete"


class TestLookbackValidation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (14, 14),
            (34, 34),
            (90, 34),  # API rejects >= 35 days for a TOTAL interval
            (0, 1),
            (-5, 1),
            ("30", 30),  # quoted string: default, not TypeError
            (None, 30),
            (True, 30),  # bool is an int subclass; reject it
            (7.5, 30),
        ],
    )
    def test_values_are_validated_and_clamped(self, raw, expected):
        assert _traffic_lookback_days({"traffic_lookback_days": raw}) == expected

    def test_missing_key_uses_default(self):
        assert _traffic_lookback_days({}) == 30


# --- Tiering ---------------------------------------------------------------


def _entry(
    flow_id: str, channel: str = "VOICE", entry_type: str = "DID", ident: str = "+18005550001"
):
    return EntryPoint(
        channel=channel, entry_type=entry_type, identifier=ident, contact_flow_id=flow_id
    )


class TestTrafficBasedTiering:
    def test_every_in_use_unreachable_flow_is_tier2(self):
        # No volume cap: a quiet-but-used flow must not be labelled dormant.
        assignments = _classify_tiers(
            [],
            _flows("flow-busy", "flow-quiet"),
            _traffic({"flow-busy": {"CHAT": 900}, "flow-quiet": {"TASK": 1}}),
        )
        assert {a.flow_id: a.tier for a in assignments} == {
            "flow-busy": "tier2_traffic",
            "flow-quiet": "tier2_traffic",
        }

    def test_rationale_and_counts_use_the_configured_window(self):
        (assignment,) = _classify_tiers(
            [], _flows("flow-q"), _traffic({"flow-q": {"VOICE": 310}}, window=14)
        )
        assert "last 14 days" in assignment.rationale
        assert assignment.observed_contact_count == 310
        assert assignment.observed_window_days == 14

    def test_dormant_with_metrics_records_an_observed_zero(self):
        (assignment,) = _classify_tiers([], _flows("flow-old"), _traffic({}, window=21))
        assert assignment.tier == "tier3_dormant"
        assert assignment.observed_contact_count == 0
        assert "no contacts in the last 21 days" in assignment.rationale

    def test_without_metrics_counts_are_unknown_not_zero(self):
        (assignment,) = _classify_tiers(
            [], _flows("flow-old"), ChannelTraffic(status="access_denied", window_days=30)
        )
        assert assignment.tier == "tier3_dormant"
        assert assignment.observed_contact_count is None
        assert "usage metrics unavailable" in assignment.rationale

    @pytest.mark.parametrize(
        ("channel", "entry_type", "tier"),
        [
            ("VOICE", "DID", "tier1_did"),
            ("VOICE", "TOLL_FREE", "tier1_tollfree"),
            ("CHAT", "SMS", "tier1_messaging"),
            ("CHAT", "WHATSAPP", "tier1_messaging"),
            ("EMAIL", "EMAIL_ADDRESS", "tier1_email"),
            ("CHAT", "OBSERVED_FLOW", "tier1_observed"),
        ],
    )
    def test_entry_flows_are_tier1_by_entry_type(self, channel, entry_type, tier):
        (assignment,) = _classify_tiers(
            [_entry("flow-a", channel, entry_type)], _flows("flow-a"), _traffic({})
        )
        assert assignment.tier == tier
        assert assignment.rationale.startswith("Entry flow for")

    def test_phone_entry_wins_over_messaging_for_a_shared_flow(self):
        entries = [
            _entry("flow-a", "CHAT", "SMS", "+18005550002"),
            _entry("flow-a", "VOICE", "DID", "+18005550001"),
        ]
        (assignment,) = _classify_tiers(entries, _flows("flow-a"), _traffic({}))
        assert assignment.tier == "tier1_did"

    def test_output_order_is_deterministic(self):
        ids = [f"flow-{i}" for i in (5, 1, 9, 3, 7)]
        runs = {
            tuple(a.flow_id for a in _classify_tiers([], _flows(*ids), _traffic({})))
            for _ in range(5)
        }
        assert runs == {tuple(sorted(ids))}


class TestSuperGraphScope:
    def test_tier2_flows_are_not_stitched(self):
        # Stitching tier 2 added no journeys, and a dynamic reference inside a
        # chat flow would mark *voice* enumeration incomplete.
        def _with_action(flow_id: str) -> ContactFlowGraph:
            graph = _flow(flow_id)
            graph.actions = {"a1": FlowAction(action_id="a1", action_type="DisconnectParticipant")}
            graph.entry_point_id = "a1"
            return graph

        flows = {f: _with_action(f) for f in ("flow-ivr", "flow-webchat")}
        assignments = [
            TierAssignment("flow-ivr", "flow-ivr", "tier1_did", "phone"),
            TierAssignment("flow-webchat", "flow-webchat", "tier2_traffic", "chat"),
        ]
        graph = build_super_graph(flows, assignments)
        stitched = {node.flow_id for node in graph.nodes.values()}
        assert "flow-ivr" in stitched  # guards against a vacuous pass
        assert "flow-webchat" not in stitched


# --- journey-scope-001 -------------------------------------------------------


def _scope_finding(result: JourneyMapResult):
    (finding,) = generate_journey_findings(
        result, instance_id=INSTANCE_ID, selected_control_ids=["journey-scope-001"]
    )
    return finding


class TestDormantFlowControl:
    def test_in_use_flows_are_reported_not_hidden(self):
        # Review finding: tier 2 flows left the dormant list but appeared
        # nowhere, and the description claimed every flow was in the
        # phone-anchored closure.
        result = JourneyMapResult(
            tier_assignments=[
                TierAssignment(
                    "flow-webchat",
                    "flow-webchat",
                    "tier2_traffic",
                    "chat",
                    channel_mix={"CHAT": 310},
                )
            ],
            traffic_observed_flows=["flow-webchat"],
            usage_metrics_status="complete",
            usage_window_days=30,
        )
        finding = _scope_finding(result)
        assert finding.status == CheckStatus.PASS
        assert "phone-anchored static closure" not in finding.description
        assert "rather than enumerated as journeys" in finding.description
        assert finding.evidence["traffic_observed_flow_ids"] == ["flow-webchat"]
        assert finding.evidence["traffic_observed_channel_mix"] == {"flow-webchat": {"CHAT": 310}}

    def test_dormant_description_states_the_usage_window(self):
        result = JourneyMapResult(
            tier_assignments=[TierAssignment("flow-old", "flow-old", "tier3_dormant", "x")],
            dormant_flows=["flow-old"],
            usage_metrics_status="complete",
            usage_window_days=21,
        )
        finding = _scope_finding(result)
        assert finding.status == CheckStatus.FAIL
        assert "last 21 days" in finding.description

    def test_reachability_only_labels_say_so(self):
        result = JourneyMapResult(
            tier_assignments=[TierAssignment("flow-old", "flow-old", "tier3_dormant", "x")],
            dormant_flows=["flow-old"],
            usage_metrics_status="access_denied",
        )
        finding = _scope_finding(result)
        assert finding.status == CheckStatus.FAIL
        assert "Usage metrics were unavailable" in finding.description
        assert finding.evidence["usage_window_days"] is None
