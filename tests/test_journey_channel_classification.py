"""
Tests for per-flow channel classification and traffic-based tiering.

Two things are guarded here.

1. ``ListFlowAssociations`` must only ever be asked for
   ``VOICE_PHONE_NUMBER``. An earlier version also asked for
   ``SMS_PHONE_NUMBER`` and ``WHATSAPP_MESSAGING_PHONE_NUMBER``.
   ``SMS_PHONE_NUMBER`` is not in that operation's ResourceType enum at
   all (only the singular ``GetFlowAssociation`` accepts it), and because
   botocore does not validate enum values client-side the request reached
   the service and came back as a ValidationException. In
   ``journey/topology.py`` that was swallowed by a broad ``except``; in
   ``engine._list_flow_associations_for_instance`` non-access-denied
   errors re-raise, so it broke journey mapping outright on live
   instances. Both messaging types were pointless regardless: they are
   keyed by AWS End User Messaging ARNs, which can never match a
   ``ListPhoneNumbersV2`` ``PhoneNumberArn``.

2. Channel is resolved from observed traffic, not flow metadata.
   ``ContactFlowType`` has no channel dimension, and one flow can serve
   voice, chat and task at once, so ``GetMetricDataV2`` per-channel
   contact counts are the only reliable signal — and the only way a
   chat-only flow (which has no phone number to be reachable from)
   becomes visible to the journey pipeline at all.
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock

from amazon_connect_assessment.journey.models import PhoneNumberEntry
from amazon_connect_assessment.journey.topology import (
    _classify_tiers,
    _list_voice_flow_associations,
    _resolve_flow_channel_traffic,
)
from amazon_connect_assessment.models import ContactFlowGraph

INSTANCE_ID = "11111111-2222-3333-4444-555555555555"
INSTANCE_ARN = f"arn:aws:connect:us-east-1:123456789012:instance/{INSTANCE_ID}"


def _flow(flow_id: str, name: str = "") -> ContactFlowGraph:
    return ContactFlowGraph(
        flow_id=flow_id,
        flow_name=name or flow_id,
        flow_type="CONTACT_FLOW",
    )


def _factory(dispatch, access_denied: bool = False) -> MagicMock:
    factory = MagicMock()
    factory.get_connect_client.return_value = MagicMock()
    factory.call_api_with_resilience.side_effect = dispatch
    factory.is_access_denied.return_value = access_denied
    return factory


def _metric_result(flow_id: str, value: float) -> Dict[str, Any]:
    return {
        "Dimensions": {"FLOWS_RESOURCE_ID": flow_id},
        "Collections": [{"Metric": {"Name": "FLOWS_STARTED"}, "Value": value}],
    }


class TestFlowAssociationResourceTypes:
    def test_only_voice_phone_number_is_queried(self):
        seen: List[str] = []

        def _dispatch(_client, operation_name, _service=None, **kwargs):
            assert operation_name == "list_flow_associations"
            seen.append(kwargs["ResourceType"])
            return {"FlowAssociationSummaryList": [], "NextToken": None}

        _list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch))

        assert seen == ["VOICE_PHONE_NUMBER"]
        assert "SMS_PHONE_NUMBER" not in seen

    def test_validation_exception_does_not_propagate(self):
        # Fails open to an empty mapping rather than aborting topology.
        def _dispatch(*_args, **_kwargs):
            raise RuntimeError("ValidationException: unsupported ResourceType")

        assert _list_voice_flow_associations(INSTANCE_ID, _factory(_dispatch)) == {}


class TestResolveFlowChannelTraffic:
    def test_builds_per_channel_contact_counts(self):
        def _dispatch(_client, operation_name, _service=None, **kwargs):
            assert operation_name == "get_metric_data_v2"
            assert kwargs["ResourceArn"] == INSTANCE_ARN
            assert kwargs["Metrics"] == [{"Name": "FLOWS_STARTED"}]
            channel = next(
                f["FilterValues"][0] for f in kwargs["Filters"] if f["FilterKey"] == "CHANNEL"
            )
            if channel == "VOICE":
                return {"MetricResults": [_metric_result("flow-ivr", 1200)]}
            if channel == "CHAT":
                return {
                    "MetricResults": [
                        _metric_result("flow-ivr", 40),
                        _metric_result("flow-webchat", 310),
                    ]
                }
            return {"MetricResults": []}

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-ivr", "flow-webchat"]
        )

        # A single flow can serve more than one channel.
        assert traffic["flow-ivr"] == {"VOICE": 1200, "CHAT": 40}
        # A chat-only flow is discovered with no phone number involved.
        assert traffic["flow-webchat"] == {"CHAT": 310}

    def test_zero_and_null_values_are_omitted(self):
        def _dispatch(_client, _operation, _service=None, **kwargs):
            return {
                "MetricResults": [
                    _metric_result("flow-quiet", 0),
                    {
                        "Dimensions": {"FLOWS_RESOURCE_ID": "flow-null"},
                        "Collections": [{"Metric": {"Name": "FLOWS_STARTED"}, "Value": None}],
                    },
                ]
            }

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-quiet", "flow-null"]
        )
        assert traffic == {}

    def test_pagination_is_followed(self):
        def _dispatch(_client, _operation, _service=None, **kwargs):
            channel = next(
                f["FilterValues"][0] for f in kwargs["Filters"] if f["FilterKey"] == "CHANNEL"
            )
            if channel != "VOICE":
                return {"MetricResults": []}
            if not kwargs.get("NextToken"):
                return {"MetricResults": [_metric_result("flow-a", 5)], "NextToken": "cursor-1"}
            return {"MetricResults": [_metric_result("flow-b", 7)]}

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch), ["flow-a", "flow-b"]
        )
        assert traffic == {"flow-a": {"VOICE": 5}, "flow-b": {"VOICE": 7}}

    def test_access_denied_fails_open(self):
        calls: List[int] = []

        def _dispatch(*_args, **_kwargs):
            calls.append(1)
            raise RuntimeError("AccessDeniedException")

        traffic = _resolve_flow_channel_traffic(
            INSTANCE_ARN, _factory(_dispatch, access_denied=True), ["flow-a"]
        )
        assert traffic == {}
        # Bails out on the first denial instead of retrying all 4 channels.
        assert len(calls) == 1

    def test_no_flows_makes_no_api_calls(self):
        def _dispatch(*_args, **_kwargs):
            raise AssertionError("should not be called")

        assert _resolve_flow_channel_traffic(INSTANCE_ARN, _factory(_dispatch), []) == {}


class TestTrafficBasedTiering:
    def _flows(self, *ids: str) -> Dict[str, ContactFlowGraph]:
        return {flow_id: _flow(flow_id) for flow_id in ids}

    def test_unreachable_flow_with_traffic_becomes_tier2(self):
        assignments = _classify_tiers(
            phone_entries=[],
            parsed_flows=self._flows("flow-webchat"),
            reachable=set(),
            max_traffic_flows=10,
            channel_traffic={"flow-webchat": {"CHAT": 310}},
        )
        (assignment,) = assignments
        assert assignment.tier == "tier2_traffic"
        assert assignment.contact_count_30d == 310
        assert assignment.channel_mix == {"CHAT": 310}
        assert "CHAT 310" in assignment.rationale

    def test_unreachable_flow_without_traffic_stays_dormant(self):
        assignments = _classify_tiers(
            phone_entries=[],
            parsed_flows=self._flows("flow-old"),
            reachable=set(),
            max_traffic_flows=10,
            channel_traffic={},
        )
        (assignment,) = assignments
        assert assignment.tier == "tier3_dormant"
        assert assignment.channel_mix == {}

    def test_cap_keeps_the_busiest_flows(self):
        traffic = {
            "flow-busy": {"CHAT": 900},
            "flow-mid": {"EMAIL": 500},
            "flow-quiet": {"TASK": 10},
        }
        assignments = _classify_tiers(
            phone_entries=[],
            parsed_flows=self._flows("flow-busy", "flow-mid", "flow-quiet"),
            reachable=set(),
            max_traffic_flows=2,
            channel_traffic=traffic,
        )
        by_tier = {a.flow_id: a.tier for a in assignments}
        assert by_tier["flow-busy"] == "tier2_traffic"
        assert by_tier["flow-mid"] == "tier2_traffic"
        # Over the cap, so dormant — but its real volume is still recorded.
        assert by_tier["flow-quiet"] == "tier3_dormant"
        quiet = next(a for a in assignments if a.flow_id == "flow-quiet")
        assert quiet.contact_count_30d == 10
        assert "outside the top 2" in quiet.rationale

    def test_tier1_records_channel_mix(self):
        entry = PhoneNumberEntry(
            phone_number="+18005550001",
            number_type="TOLL_FREE",
            country_code="US",
            contact_flow_id="flow-ivr",
        )
        assignments = _classify_tiers(
            phone_entries=[entry],
            parsed_flows=self._flows("flow-ivr"),
            reachable={"flow-ivr"},
            max_traffic_flows=10,
            channel_traffic={"flow-ivr": {"VOICE": 1200, "CHAT": 40}},
        )
        (assignment,) = assignments
        assert assignment.tier == "tier1_tollfree"
        assert assignment.channel_mix == {"VOICE": 1200, "CHAT": 40}
        assert assignment.contact_count_30d == 1240

    def test_missing_traffic_preserves_previous_behaviour(self):
        # No metrics access: tiering falls back to reachability only.
        assignments = _classify_tiers(
            phone_entries=[],
            parsed_flows=self._flows("flow-a", "flow-b"),
            reachable={"flow-a"},
            max_traffic_flows=10,
            channel_traffic=None,
        )
        by_tier = {a.flow_id: a.tier for a in assignments}
        assert by_tier == {"flow-a": "tier1_did", "flow-b": "tier3_dormant"}
        assert all(a.contact_count_30d is None for a in assignments)
