"""
Multichannel journey mapping: entry points on every channel (B4) scored with
channel-appropriate rules (B5).

Regressions guarded here, each found on a live instance or in review:

* A Connect-claimed toll-free number's SMS association uses the same
  ``arn:aws:connect`` phone-number ARN as ``ListPhoneNumbersV2``. Merging it
  into the voice map (the original code) overwrote the number's voice
  journey with its SMS flow; dropping SMS (the first revision of PR #22)
  lost the SMS entry entirely. Both are wrong: each association is its own
  entry, keyed by channel and resource.
* Web chat and tasks have no control-plane association, so they are
  discovered from traffic — per channel, so a voice IVR reaching a flow does
  not hide chat customers who start there directly.
* Voice-only rules (callback, pre-agent authentication, menu containment)
  must not score email or tasks, and a gap on one channel must not mark
  another channel's coverage incomplete.
"""

import hashlib
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from amazon_connect_assessment.journey import run_journey_mapping
from amazon_connect_assessment.journey.channels import CHANNEL_RULES, rules_for
from amazon_connect_assessment.journey.journey_scorer import (
    _score_single_path,
    generate_journey_findings,
)
from amazon_connect_assessment.journey.models import (
    EntryPoint,
    JourneyMapResult,
    JourneyNode,
    JourneyPath,
    JourneyScore,
)
from amazon_connect_assessment.journey.topology import discover_entry_points
from amazon_connect_assessment.models import (
    CheckStatus,
    ConnectInstance,
    ContactFlowGraph,
    FlowAction,
    FlowTransition,
)

IID = "11111111-2222-3333-4444-555555555555"
INSTANCE_ARN = f"arn:aws:connect:us-east-1:123456789012:instance/{IID}"


def _num_arn(n: str) -> str:
    return f"arn:aws:connect:us-east-1:123456789012:phone-number/{n}"


def _flow_arn(flow_id: str) -> str:
    return f"{INSTANCE_ARN}/contact-flow/{flow_id}"


EMAIL_ARN = f"{INSTANCE_ARN}/email-address/ea-1"
WHATSAPP_ARN = "arn:aws:social-messaging:us-east-1:123456789012:phone-number-id/wa123"


def _graph(flow_id: str, steps: List[str], flow_type: str = "CONTACT_FLOW", params=None):
    """Linear flow: steps[0] -> steps[1] -> ... (action types)."""
    actions = {}
    for i, action_type in enumerate(steps):
        transitions = (
            [FlowTransition(source_action_id=f"a{i}", target_action_id=f"a{i + 1}")]
            if i + 1 < len(steps)
            else []
        )
        actions[f"a{i}"] = FlowAction(
            action_id=f"a{i}",
            action_type=action_type,
            parameters=(params or {}).get(i, {}),
            transitions=transitions,
        )
    return ContactFlowGraph(
        flow_id=flow_id,
        flow_name=f"{flow_id} name",
        flow_type=flow_type,
        actions=actions,
        entry_point_id="a0",
    )


def _transfer_to(target: str):
    return {"ContactFlowId": target}


def _flows() -> Dict[str, ContactFlowGraph]:
    flows = {
        "flow-ivr": _graph("flow-ivr", ["MessageParticipant", "TransferContactToQueue"]),
        "flow-sms": _graph("flow-sms", ["MessageParticipant", "TransferContactToQueue"]),
        "flow-wa": _graph("flow-wa", ["MessageParticipant", "DisconnectParticipant"]),
        "flow-email": _graph("flow-email", ["UpdateContactAttributes", "TransferContactToQueue"]),
        "flow-webchat": _graph(
            "flow-webchat",
            ["MessageParticipant", "TransferToFlow"],
            params={1: _transfer_to("flow-sub")},
        ),
        "flow-sub": _graph("flow-sub", ["MessageParticipant", "TransferContactToQueue"]),
        "flow-task": _graph("flow-task", ["UpdateContactAttributes", "MessageParticipant"]),
        "flow-queue": _graph("flow-queue", ["MessageParticipant"], flow_type="CUSTOMER_QUEUE"),
        "flow-old": _graph("flow-old", ["DisconnectParticipant"]),
    }
    return flows


def _metric(flow_id: str, channel: str, value: int) -> Dict[str, Any]:
    return {
        "Dimensions": {"FLOWS_RESOURCE_ID": flow_id, "CHANNEL": channel},
        "Collections": [{"Metric": {"Name": "FLOWS_STARTED"}, "Value": float(value)}],
    }


DEFAULT_TRAFFIC = [
    _metric("flow-ivr", "VOICE", 100),
    _metric("flow-webchat", "CHAT", 50),
    _metric("flow-sub", "CHAT", 20),  # reachable from flow-webchat: not its own entry
    _metric("flow-task", "TASK", 5),
    _metric("flow-queue", "VOICE", 30),  # queue flow: in use, never an entry
]


def _factory(
    associations: Optional[Dict[str, List[Dict[str, str]]]] = None,
    traffic: Optional[List[Dict[str, Any]]] = None,
    fail: Optional[Dict[str, Exception]] = None,
    denied: tuple = (),
) -> MagicMock:
    associations = (
        associations
        if associations is not None
        else {
            "VOICE_PHONE_NUMBER": [{"ResourceId": _num_arn("A"), "FlowId": _flow_arn("flow-ivr")}],
            "SMS_PHONE_NUMBER": [{"ResourceId": _num_arn("B"), "FlowId": _flow_arn("flow-sms")}],
            "WHATSAPP_MESSAGING_PHONE_NUMBER": [
                {"ResourceId": WHATSAPP_ARN, "FlowId": _flow_arn("flow-wa")}
            ],
            "INBOUND_EMAIL": [{"ResourceId": EMAIL_ARN, "FlowId": _flow_arn("flow-email")}],
        }
    )
    traffic = DEFAULT_TRAFFIC if traffic is None else traffic
    fail = fail or {}

    def _dispatch(_c, op, _s=None, **kwargs):
        key = f"{op}:{kwargs.get('ResourceType', '')}"
        for k in (key, op):
            if k in fail:
                raise fail[k]
        if op == "list_phone_numbers_v2":
            return {
                "ListPhoneNumbersSummaryList": [
                    {
                        "PhoneNumber": "+12065550101",
                        "PhoneNumberArn": _num_arn("A"),
                        "PhoneNumberType": "DID",
                        "PhoneNumberCountryCode": "US",
                    },
                    {
                        "PhoneNumber": "+18885550202",
                        "PhoneNumberArn": _num_arn("B"),
                        "PhoneNumberType": "TOLL_FREE",
                        "PhoneNumberCountryCode": "US",
                    },
                ]
            }
        if op == "list_flow_associations":
            return {"FlowAssociationSummaryList": associations.get(kwargs["ResourceType"], [])}
        if op == "search_email_addresses":
            return {
                "EmailAddresses": [
                    {"EmailAddressArn": EMAIL_ARN, "EmailAddress": "support@example.com"}
                ]
            }
        if op == "get_metric_data_v2":
            return {"MetricResults": traffic}
        raise AssertionError(f"unexpected operation {op}")

    factory = MagicMock()
    factory.get_connect_client.return_value = MagicMock()
    factory.call_api_with_resilience.side_effect = _dispatch
    factory.is_access_denied.side_effect = lambda e: (
        isinstance(e, PermissionError) or (str(e) in denied)
    )
    return factory


def _discover(**kwargs):
    return discover_entry_points(IID, INSTANCE_ARN, _factory(**kwargs), _flows(), {})


def _keys(found) -> List[tuple]:
    return [(e.channel, e.entry_type, e.identifier, e.contact_flow_id) for e in found.entry_points]


# --- B4: entry-point discovery ----------------------------------------------


class TestEntryDiscovery:
    def test_every_channel_is_discovered(self):
        found = _discover()
        assert _keys(found) == [
            ("VOICE", "DID", "+12065550101", "flow-ivr"),
            ("CHAT", "SMS", "+18885550202", "flow-sms"),
            ("CHAT", "WHATSAPP", "whatsapp:wa123", "flow-wa"),
            ("CHAT", "OBSERVED_FLOW", "flow-webchat name", "flow-webchat"),
            ("EMAIL", "EMAIL_ADDRESS", "support@example.com", "flow-email"),
            ("TASK", "OBSERVED_FLOW", "flow-task name", "flow-task"),
        ]
        assert found.limitations == []

    def test_voice_and_sms_on_one_number_are_separate_entries(self):
        # Original bug: a merged ARN-keyed map let the SMS flow overwrite the
        # number's voice journey.
        found = _discover(
            associations={
                "VOICE_PHONE_NUMBER": [
                    {"ResourceId": _num_arn("B"), "FlowId": _flow_arn("flow-ivr")}
                ],
                "SMS_PHONE_NUMBER": [
                    {"ResourceId": _num_arn("B"), "FlowId": _flow_arn("flow-sms")}
                ],
            },
            traffic=[],
        )
        assert _keys(found) == [
            ("VOICE", "TOLL_FREE", "+18885550202", "flow-ivr"),
            ("CHAT", "SMS", "+18885550202", "flow-sms"),
        ]
        voice = next(p for p in found.phone_entries if p.phone_number == "+18885550202")
        assert voice.contact_flow_id == "flow-ivr"

    def test_queue_flows_and_sub_flows_are_not_entries(self):
        found = _discover()
        entry_flows = {e.contact_flow_id for e in found.entry_points}
        assert "flow-queue" not in entry_flows  # CUSTOMER_QUEUE: never where contacts enter
        assert "flow-sub" not in entry_flows  # reached from flow-webchat
        tiers = {t.flow_id: t.tier for t in found.tier_assignments}
        assert tiers["flow-queue"] == "tier2_traffic"
        assert tiers["flow-sub"] == "tier1_observed"
        assert tiers["flow-old"] == "tier3_dormant"

    def test_observed_entries_are_judged_per_channel(self):
        # The voice IVR reaches flow-webchat, but chat customers start there
        # directly: it must still be a CHAT entry.
        flows = _flows()
        flows["flow-ivr"] = _graph(
            "flow-ivr",
            ["MessageParticipant", "TransferToFlow"],
            params={1: _transfer_to("flow-webchat")},
        )
        found = discover_entry_points(IID, INSTANCE_ARN, _factory(), flows, {})
        assert ("CHAT", "OBSERVED_FLOW", "flow-webchat name", "flow-webchat") in _keys(found)

    def test_messaging_failure_narrows_only_chat(self):
        found = _discover(
            fail={"list_flow_associations:SMS_PHONE_NUMBER": RuntimeError("ValidationException")}
        )
        assert "CHAT" in found.incomplete_channels
        assert "VOICE" not in found.incomplete_channels
        assert ("VOICE", "DID", "+12065550101", "flow-ivr") in _keys(found)
        assert any("SMS_PHONE_NUMBER" in item for item in found.limitations)

    def test_denied_email_lookup_still_yields_the_entry(self):
        found = _discover(fail={"search_email_addresses": PermissionError("denied")})
        assert ("EMAIL", "EMAIL_ADDRESS", "email:ea-1", "flow-email") in _keys(found)
        assert "connect:SearchEmailAddresses" in found.denied_permissions

    def test_without_metrics_association_entries_remain(self):
        found = _discover(fail={"get_metric_data_v2": PermissionError("denied")})
        types = {e.entry_type for e in found.entry_points}
        assert "OBSERVED_FLOW" not in types
        assert {"DID", "SMS", "WHATSAPP", "EMAIL_ADDRESS"} <= types
        assert "connect:GetMetricDataV2" in found.denied_permissions
        # Optional signal: recorded, but no channel is marked incomplete.
        assert not found.incomplete_channels

    def test_entry_to_unparseable_flow_is_a_gap(self):
        found = _discover(
            associations={
                "INBOUND_EMAIL": [{"ResourceId": EMAIL_ARN, "FlowId": _flow_arn("flow-missing")}]
            },
            traffic=[],
        )
        assert found.entry_points == []
        assert "EMAIL" in found.incomplete_channels


# --- B5: channel rules ---------------------------------------------------------


def _path(channel: str, entry_type: str, steps: List[str], terminal="agent_queue", reason=None):
    nodes = [
        JourneyNode(flow_id="f", flow_name="F", action_id=f"a{i}", action_type=s)
        for i, s in enumerate(steps)
    ]
    return JourneyPath(
        entry_identifier={"EMAIL_ADDRESS": "jane@example.com", "OBSERVED_FLOW": "Web chat"}.get(
            entry_type, "+12065550101"
        ),
        entry_type=entry_type,
        entry_channel=channel,
        nodes=nodes,
        terminal_type=terminal,
        terminal_details={"reason": reason} if reason else {},
        flows_traversed=["f"],
    )


class TestChannelRules:
    def test_rule_matrix(self):
        matrix = {
            c: (r.authentication, r.self_service, r.callback, r.dead_end)
            for c, r in CHANNEL_RULES.items()
        }
        assert matrix == {
            "VOICE": (True, True, True, True),
            "CHAT": (True, True, False, True),
            "EMAIL": (False, False, False, True),
            "TASK": (False, False, False, True),
        }
        # Every excluded rule explains itself.
        for rules in CHANNEL_RULES.values():
            for rule in ("authentication", "self_service", "callback"):
                if not rules.applies(rule):
                    assert rules.not_applicable.get(rule), (rules.channel, rule)

    def test_callback_deficiency_is_voice_only(self):
        voice = _score_single_path(_path("VOICE", "DID", ["MessageParticipant"]))
        chat = _score_single_path(_path("CHAT", "SMS", ["MessageParticipant"]))
        assert any("callback" in d for d in voice.deficiencies)
        assert not any("callback" in d for d in chat.deficiencies)

    def test_email_and_task_are_not_scored_for_auth_or_containment(self):
        for channel, entry_type in (("EMAIL", "EMAIL_ADDRESS"), ("TASK", "OBSERVED_FLOW")):
            score = _score_single_path(_path(channel, entry_type, ["MessageParticipant"]))
            assert not any("authentication" in d for d in score.deficiencies)
            assert not any("self-service" in d for d in score.deficiencies)

    def test_dedicated_authentication_action_counts(self):
        score = _score_single_path(_path("CHAT", "OBSERVED_FLOW", ["AuthenticateParticipant"]))
        assert score.has_authentication

    def test_maturity_scales_to_the_channel(self):
        score = JourneyScore(
            channel="EMAIL", has_personalization=True, has_returning_caller_detection=True
        )
        assert rules_for("EMAIL").maturity(score.cx_feature_count) == "Advanced"
        voice = JourneyScore(
            channel="VOICE", has_personalization=True, has_returning_caller_detection=True
        )
        assert rules_for("VOICE").maturity(voice.cx_feature_count) == "Intermediate"

    def test_voice_hash_is_unchanged_and_channels_differ(self):
        voice = _path("VOICE", "DID", ["MessageParticipant"])
        chat = _path("CHAT", "SMS", ["MessageParticipant"])
        legacy = hashlib.sha256("f::a0".encode()).hexdigest()[:16]
        assert voice.path_hash == legacy
        assert chat.path_hash != voice.path_hash


def _result(paths: List[JourneyPath], coverage: Optional[Dict[str, bool]] = None):
    scores = {p.path_hash: _score_single_path(p) for p in paths}
    channels = coverage or {p.entry_channel: True for p in paths}
    return JourneyMapResult(
        journeys=paths,
        scores=scores,
        tier_assignments=[],
        channel_coverage={
            c: {
                "complete": ok,
                "limitations": [] if ok else ["x"],
                "entry_points": 1,
                "journeys": 1,
            }
            for c, ok in channels.items()
        },
    )


def _finding(result: JourneyMapResult, control_id: str):
    (finding,) = generate_journey_findings(
        result, instance_id=IID, selected_control_ids=[control_id]
    )
    return finding


class TestChannelAwareFindings:
    def test_auth_counts_chat_and_excludes_email_with_reason(self):
        result = _result(
            [
                _path("CHAT", "SMS", ["MessageParticipant"]),
                _path("EMAIL", "EMAIL_ADDRESS", ["MessageParticipant"]),
            ]
        )
        finding = _finding(result, "sec-flow-auth-001")
        assert finding.status == CheckStatus.FAIL
        assert "(CHAT 1)" in finding.description
        assert "Not evaluated for EMAIL" in finding.description
        assert finding.evidence["evaluated_channels"] == ["CHAT"]
        assert "EMAIL" in finding.evidence["excluded_channels"]
        assert finding.evidence["affected_entry_points"] == [
            {"channel": "CHAT", "entry_type": "SMS", "entry": "***-***-0101"}
        ]

    def test_email_only_auth_is_not_applicable(self):
        result = _result([_path("EMAIL", "EMAIL_ADDRESS", ["MessageParticipant"])])
        finding = _finding(result, "sec-flow-auth-001")
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "Not evaluated for EMAIL" in finding.description

    def test_task_dead_end_is_reported(self):
        result = _result(
            [_path("TASK", "OBSERVED_FLOW", ["MessageParticipant"], "disconnect", "dead_end")]
        )
        finding = _finding(result, "journey-res-001")
        assert finding.status == CheckStatus.FAIL
        assert "(TASK 1)" in finding.description

    def test_email_identifiers_are_masked(self):
        result = _result(
            [_path("EMAIL", "EMAIL_ADDRESS", ["MessageParticipant"], "disconnect", "dead_end")]
        )
        finding = _finding(result, "journey-res-001")
        assert finding.evidence["affected_entry_points"][0]["entry"] == "j***@example.com"
        assert "jane@example.com" not in str(finding.evidence)

    def test_incomplete_out_of_scope_channel_does_not_block_a_clean_result(self):
        # EMAIL coverage is incomplete, but authentication does not apply to
        # email, so a clean voice result is still a PASS.
        result = _result(
            [_path("VOICE", "DID", ["InvokeLambdaFunction", "MessageParticipant"])],
            coverage={"VOICE": True, "EMAIL": False},
        )
        result.journeys[0].nodes[0].parameters = {"FunctionArn": "verify-identity"}
        result.scores = {p.path_hash: _score_single_path(p) for p in result.journeys}
        assert _finding(result, "sec-flow-auth-001").status == CheckStatus.PASS

    def test_incomplete_in_scope_channel_blocks_a_clean_result(self):
        result = _result(
            [_path("VOICE", "DID", ["MessageParticipant"], "disconnect")],
            coverage={"VOICE": True, "CHAT": False},
        )
        assert _finding(result, "journey-res-001").status == CheckStatus.SKIPPED


# --- End to end ------------------------------------------------------------------


class TestPipeline:
    def _run(self, flows=None, **kwargs):
        instance = ConnectInstance(
            instance_id=IID,
            instance_arn=INSTANCE_ARN,
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=False,
        )
        return run_journey_mapping(instance, flows or _flows(), _factory(**kwargs), {})

    def test_journeys_exist_on_every_discovered_channel(self):
        output = self._run()
        by_channel = {}
        for j in output.result.journeys:
            by_channel.setdefault(j.entry_channel, set()).add(j.entry_type)
        assert by_channel == {
            "VOICE": {"DID"},
            "CHAT": {"SMS", "WHATSAPP", "OBSERVED_FLOW"},
            "EMAIL": {"EMAIL_ADDRESS"},
            "TASK": {"OBSERVED_FLOW"},
        }
        assert set(output.result.channel_coverage) == {"VOICE", "CHAT", "EMAIL", "TASK"}
        assert output.result.enumeration_complete

    def test_dynamic_reference_in_chat_flow_leaves_voice_complete(self):
        flows = _flows()
        flows["flow-webchat"] = _graph(
            "flow-webchat",
            ["MessageParticipant", "TransferToFlow"],
            params={1: {"ContactFlowId": {"Type": "Attribute", "Value": "$.Attributes.next"}}},
        )
        result = self._run(flows=flows).result
        assert result.channel_coverage["VOICE"]["complete"] is True
        assert result.channel_coverage["CHAT"]["complete"] is False
        assert any("dynamic" in x for x in result.channel_coverage["CHAT"]["limitations"])

    def test_findings_name_channels(self):
        findings = {f.check_id: f for f in self._run().findings}
        auth = findings["sec-flow-auth-001"]
        # IVR, SMS and web chat reach an agent queue without authentication.
        assert auth.status == CheckStatus.FAIL
        assert "VOICE 1" in auth.description and "CHAT 2" in auth.description
        assert "Not evaluated for EMAIL" in auth.description
        dead = findings["journey-res-001"]
        assert dead.status == CheckStatus.FAIL
        assert "TASK 1" in dead.description


class TestHtmlMapTargets:
    def test_cached_entries_drive_the_map(self):
        from amazon_connect_assessment.engine import AssessmentEngine, _journey_entry_label

        engine = AssessmentEngine.__new__(AssessmentEngine)
        instance = MagicMock(instance_id=IID)
        engine._journey_entry_points = {
            IID: [
                EntryPoint("VOICE", "DID", "+12065550101", "flow-ivr"),
                EntryPoint("CHAT", "SMS", "+18885550202", "flow-sms"),
                EntryPoint("EMAIL", "EMAIL_ADDRESS", "support@example.com", "flow-email"),
                EntryPoint("CHAT", "OBSERVED_FLOW", "Web chat", "flow-webchat"),
            ]
        }
        targets, non_flow = engine._journey_map_targets(instance, [], {})
        assert [(t["channel"], t["entry_type"]) for t in targets] == [
            ("VOICE", "DID"),
            ("CHAT", "SMS"),
            ("EMAIL", "EMAIL_ADDRESS"),
            ("CHAT", "OBSERVED_FLOW"),
        ]
        assert [_journey_entry_label(t) for t in targets] == [
            "+12065550101",
            "+18885550202 · SMS",
            "support@example.com · Email",
            "Web chat · CHAT (observed)",
        ]

    def test_without_cache_the_map_is_voice_only(self):
        from amazon_connect_assessment.engine import AssessmentEngine

        engine = AssessmentEngine.__new__(AssessmentEngine)
        numbers = [{"PhoneNumberArn": "arn-a", "PhoneNumber": "+1", "PhoneNumberType": "DID"}]
        targets, non_flow = engine._journey_map_targets(
            MagicMock(instance_id=IID), numbers, {"arn-a": "flow-ivr"}
        )
        assert [(t["channel"], t["flow_id"]) for t in targets] == [("VOICE", "flow-ivr")]
        assert non_flow == 0


@pytest.mark.parametrize("channel", ["VOICE", "CHAT", "EMAIL", "TASK"])
def test_every_channel_has_rules(channel):
    assert rules_for(channel).channel == channel


# --- PR #22 review regressions -------------------------------------------------


class TestReviewRegressions:
    def _instance(self):
        return ConnectInstance(
            instance_id=IID,
            instance_arn=INSTANCE_ARN,
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=False,
        )

    def _scope(self, flows, factory):
        output = run_journey_mapping(self._instance(), flows, factory, {})
        return next(f for f in output.findings if f.check_id == "journey-scope-001")

    def test_failed_association_lookup_is_not_a_clean_pass(self):
        # Review #1: with every unreachable flow showing traffic, a denied
        # ListFlowAssociations used to read as "No dormant flows" (PASS).
        flows = _flows()
        flows.pop("flow-old")
        traffic = [_metric(f, "VOICE", 3) for f in ("flow-sms", "flow-wa", "flow-email")]
        factory = _factory(
            traffic=DEFAULT_TRAFFIC + traffic,
            fail={"list_flow_associations": PermissionError("denied")},
        )
        finding = self._scope(flows, factory)
        assert finding.status == CheckStatus.SKIPPED
        assert "entry-point discovery failed for" in finding.description
        assert "connect:ListFlowAssociations" in finding.description
        assert finding.evidence["discovery_incomplete_channels"] == ["CHAT", "EMAIL", "VOICE"]

    def test_failed_phone_lookup_with_dormant_flows_says_so(self):
        finding = self._scope(
            _flows(), _factory(fail={"list_phone_numbers_v2": RuntimeError("boom")})
        )
        assert finding.status == CheckStatus.FAIL
        assert "some of these flows may be reachable" in finding.description

    def test_usage_window_includes_today(self):
        # Review #2: a midnight-aligned end dropped today's contacts.
        from datetime import datetime, timedelta, timezone

        factory = _factory()
        discover_entry_points(IID, INSTANCE_ARN, factory, _flows(), {})
        (request,) = [
            c.kwargs
            for c in factory.call_api_with_resilience.call_args_list
            if c.args[1] == "get_metric_data_v2"
        ]
        now = datetime.now(timezone.utc)
        assert now - timedelta(minutes=3) <= request["EndTime"] <= now
        assert request["EndTime"] - request["StartTime"] == timedelta(days=30)

    def test_tier2_is_only_ever_non_entry_flow_types(self):
        # Review #3: tier 2 cannot hide an uncovered customer entry flow.
        found = _discover()
        flows = _flows()
        tier2 = [t.flow_id for t in found.tier_assignments if t.tier == "tier2_traffic"]
        assert tier2 == ["flow-queue"]
        assert all(flows[f].flow_type != "CONTACT_FLOW" for f in tier2)

    def test_metrics_skip_flows_whose_tier_cannot_change(self):
        # Review #4: a reachable hold flow is tier 1 whatever its traffic.
        flows = _flows()
        flows["flow-ivr"] = _graph(
            "flow-ivr",
            ["MessageParticipant", "TransferToFlow"],
            params={1: _transfer_to("flow-hold")},
        )
        flows["flow-hold"] = _graph("flow-hold", ["MessageParticipant"], flow_type="CUSTOMER_HOLD")
        factory = _factory()
        discover_entry_points(IID, INSTANCE_ARN, factory, flows, {})
        (request,) = [
            c.kwargs
            for c in factory.call_api_with_resilience.call_args_list
            if c.args[1] == "get_metric_data_v2"
        ]
        queried = next(
            f["FilterValues"] for f in request["Filters"] if f["FilterKey"] == "FLOWS_RESOURCE_ID"
        )
        assert "flow-hold" not in queried  # reachable, not entry-capable
        assert "flow-queue" in queried  # unreachable: may be in use
        assert "flow-ivr" in queried  # entry-capable: may be an observed entry


def test_policy_grants_every_permission_entry_discovery_calls():
    # A merge that drops these would otherwise pass every other test while
    # discovery degrades silently in real runs.
    from amazon_connect_assessment import iam_permissions

    granted = {a for s in iam_permissions.POLICY_STATEMENTS for a in s["Action"]}
    required = {
        "connect:ListPhoneNumbersV2",
        "connect:ListFlowAssociations",
        "connect:SearchEmailAddresses",
        "connect:GetMetricDataV2",
    }
    assert required <= granted, sorted(required - granted)
