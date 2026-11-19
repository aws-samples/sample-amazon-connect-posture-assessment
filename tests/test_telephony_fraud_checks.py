"""
Tests for the telephony toll-fraud controls (backlog A2-A5).

Request and response shapes mirror what the live APIs returned on a demo
account, including two behaviours a mock would not suggest:

* ListAuthenticationProfiles fails with InvalidRequestException "Account …
  is not allowed to use this feature" until AWS enables the feature — a
  finding, not an error.
* The CCP "Make outbound calls" permission is ``OutboundCallAccess``, and
  Connect's default Agent profile grants it.
"""

import logging
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from amazon_connect_assessment.checks.base import CheckContext
from amazon_connect_assessment.checks.telephony_fraud_checks import (
    FraudCostAlertingCheck,
    IpAccessControlCheck,
    OutboundDestinationCheck,
    OutboundPermissionScopeCheck,
    calling_code,
)
from amazon_connect_assessment.models import CheckStatus, ConnectInstance, Severity

ACCOUNT = "123456789012"
ARN = f"arn:aws:connect:us-east-1:{ACCOUNT}:instance/i-1"


def _client_error(code: str, message: str = "") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


def _instance(outbound: bool = True) -> ConnectInstance:
    return ConnectInstance(
        instance_id="i-1",
        instance_arn=ARN,
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=outbound,
        instance_alias="example",
    )


def _factory(responses: Dict[str, Any], calls: Optional[List[str]] = None) -> MagicMock:
    """Dispatch by operation; a value that is an Exception is raised."""

    def _call(_client, operation, _service=None, **kwargs):
        if calls is not None:
            calls.append(operation)
        value = responses.get(operation)
        if callable(value):
            value = value(**kwargs)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise AssertionError(f"unexpected operation {operation}")
        return value

    factory = MagicMock()
    factory.call_api_with_resilience.side_effect = _call
    factory.is_access_denied.side_effect = lambda e: (
        isinstance(e, ClientError) and e.response["Error"]["Code"] == "AccessDeniedException"
    )
    return factory


def _ctx(factory, instance=None) -> CheckContext:
    return CheckContext(
        instance=instance or _instance(),
        aws_client_factory=factory,
        config={},
        logger=logging.getLogger("test"),
    )


# --- A2: IP-based access control ------------------------------------------------


def _profiles(*profiles: Dict[str, Any]) -> Dict[str, Any]:
    by_id = {p["Id"]: p for p in profiles}
    return {
        "list_authentication_profiles": {
            "AuthenticationProfileSummaryList": [{"Id": p["Id"]} for p in profiles]
        },
        "describe_authentication_profile": lambda AuthenticationProfileId, **_: {
            "AuthenticationProfile": by_id[AuthenticationProfileId]
        },
    }


class TestIpAccessControl:
    def test_feature_not_enabled_is_a_finding(self):
        factory = _factory(
            {
                "list_authentication_profiles": _client_error(
                    "InvalidRequestException",
                    f"Account {ACCOUNT} is not allowed to use this feature. "
                    "Please contact customer support.",
                )
            }
        )
        finding = IpAccessControlCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.HIGH
        assert "not enabled for this AWS account" in finding.description
        assert finding.evidence == {"authentication_profiles_available": False}
        assert "AWS Support" in finding.remediation

    def test_default_allow_list_passes(self):
        factory = _factory(
            _profiles(
                {"Id": "d", "Name": "Default", "IsDefault": True, "AllowedIps": ["10.0.0.0/8"]}
            )
        )
        finding = IpAccessControlCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.PASS
        # Ranges are counted, never reported.
        assert "10.0.0.0/8" not in str(finding.evidence)

    @pytest.mark.parametrize(
        ("profiles", "phrase"),
        [
            ([{"Id": "d", "IsDefault": True, "BlockedIps": ["1.2.3.4/32"]}], "only blocks listed"),
            (
                [
                    {"Id": "d", "IsDefault": True},
                    {"Id": "o", "Name": "Office", "AllowedIps": ["10.0.0.0/8"]},
                ],
                "only the non-default profile(s) Office",
            ),
            ([{"Id": "d", "IsDefault": True}], "no authentication profile restricts"),
        ],
    )
    def test_partial_or_no_restriction_fails(self, profiles, phrase):
        finding = IpAccessControlCheck().execute(_ctx(_factory(_profiles(*profiles))))
        assert finding.status == CheckStatus.FAIL
        assert phrase in finding.description

    def test_severity_is_medium_without_outbound_calling(self):
        factory = _factory(_profiles({"Id": "d", "IsDefault": True}))
        finding = IpAccessControlCheck().execute(_ctx(factory, _instance(outbound=False)))
        assert finding.severity == Severity.MEDIUM

    def test_access_denied_skips(self):
        factory = _factory({"list_authentication_profiles": _client_error("AccessDeniedException")})
        assert IpAccessControlCheck().execute(_ctx(factory)).status == CheckStatus.SKIPPED


# --- A3: outbound calling permission scope --------------------------------------


def _scope_factory(users: List[List[str]], perms=None):
    perms = perms or {"agent": ["BasicAgentAccess", "OutboundCallAccess"], "mgr": ["ReportsAccess"]}
    factory = _factory(
        {
            "search_users": {
                "Users": [{"Id": f"u{i}", "SecurityProfileIds": p} for i, p in enumerate(users)]
            }
        }
    )
    factory.list_security_profiles_resilient.return_value = {
        "SecurityProfileSummaryList": [
            {"Id": "agent", "Name": "Agent"},
            {"Id": "mgr", "Name": "Manager"},
        ]
    }
    factory.list_security_profile_permissions_resilient.side_effect = lambda _i, pid, **_: {
        "Permissions": perms[pid]
    }
    return factory


class TestOutboundPermissionScope:
    def test_default_agent_grant_to_most_users_fails(self):
        factory = _scope_factory([["agent"], ["agent"], ["agent"], ["mgr"]])
        finding = OutboundPermissionScopeCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.FAIL
        assert "3 of 4 user(s) (75%)" in finding.description
        assert finding.evidence["profiles_granting_outbound_calling"] == {"Agent": 3}

    def test_scoped_grant_passes(self):
        factory = _scope_factory([["agent"], ["mgr"], ["mgr"], ["mgr"]])
        finding = OutboundPermissionScopeCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["users_with_outbound_calling"] == 1

    def test_not_applicable_without_outbound_calling(self):
        finding = OutboundPermissionScopeCheck().execute(
            _ctx(_scope_factory([["agent"]]), _instance(outbound=False))
        )
        assert finding.status == CheckStatus.NOT_APPLICABLE


# --- A4: outbound destinations ----------------------------------------------------


class TestCallingCode:
    @pytest.mark.parametrize(
        ("number", "code"),
        [
            ("+12065550100", "1"),
            ("+74951234567", "7"),
            ("+442071234567", "44"),
            ("+33142685300", "33"),
            ("+353123456", "353"),
            ("+8821234567", "882"),
            ("+979123456789", "979"),
            ("2065550100", None),
            ("+1-206", None),
            ("", None),
        ],
    )
    def test_calling_code(self, number, code):
        assert calling_code(number) == code


def _dest_factory(destinations: List[str], numbers=("+12065550100",), calls=None, total=None):
    contacts = [{"Id": f"c{i}", "InitiationMethod": "OUTBOUND"} for i in range(len(destinations))]
    by_id = {c["Id"]: d for c, d in zip(contacts, destinations)}
    return _factory(
        {
            "list_phone_numbers_v2": {
                "ListPhoneNumbersSummaryList": [{"PhoneNumber": n} for n in numbers]
            },
            "search_contacts": {"Contacts": contacts, "TotalCount": total or len(contacts)},
            "describe_contact": lambda ContactId, **_: {
                "Contact": {
                    "InitiationMethod": "OUTBOUND",
                    "CustomerEndpoint": {"Type": "TELEPHONE_NUMBER", "Address": by_id[ContactId]},
                }
            },
        },
        calls,
    )


class TestOutboundDestination:
    def test_premium_and_foreign_destinations_fail_high(self):
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+12065550111", "+33612345678", "+979123456789"]))
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.HIGH
        assert "+979 (international premium-rate service): 1" in finding.description
        assert "+33: 1" in finding.description

    def test_foreign_only_fails_medium(self):
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+33612345678", "+33612345679"]))
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.MEDIUM

    def test_home_destinations_pass(self):
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+12065550111", "+14155550100"]))
        )
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["destinations_by_calling_code"] == {"+1": 2}

    def test_dialed_numbers_never_reach_the_finding(self):
        dialed = ["+33612345678", "+979123456789"]
        finding = OutboundDestinationCheck().execute(_ctx(_dest_factory(dialed)))
        blob = str(finding.evidence) + finding.description + finding.remediation
        for number in dialed:
            assert number not in blob
            assert number[3:] not in blob

    def test_request_targets_recent_outbound_voice(self):
        factory = _dest_factory([])
        OutboundDestinationCheck().execute(_ctx(factory))
        search = next(
            c.kwargs
            for c in factory.call_api_with_resilience.call_args_list
            if c.args[1] == "search_contacts"
        )
        assert search["SearchCriteria"] == {
            "Channels": ["VOICE"],
            "InitiationMethods": ["OUTBOUND", "CALLBACK", "API"],
        }
        assert search["Sort"] == {"FieldName": "INITIATION_TIMESTAMP", "Order": "DESCENDING"}
        assert search["MaxResults"] == 100

    def test_no_outbound_calls_passes_with_allowlist_caveat(self):
        finding = OutboundDestinationCheck().execute(_ctx(_dest_factory([])))
        assert finding.status == CheckStatus.PASS
        assert "cannot be read" in finding.description

    def test_no_home_numbers_skips_unless_high_risk(self):
        clean = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+33612345678"], numbers=()))
        )
        assert clean.status == CheckStatus.SKIPPED
        risky = OutboundDestinationCheck().execute(_ctx(_dest_factory(["+8821234567"], numbers=())))
        assert risky.status == CheckStatus.FAIL

    def test_contact_record_access_denied_skips(self):
        factory = _dest_factory(["+33612345678"])
        factory.call_api_with_resilience.side_effect = None
        factory.call_api_with_resilience.side_effect = lambda _c, op, _s=None, **kw: (
            (_ for _ in ()).throw(_client_error("AccessDeniedException"))
            if op == "search_contacts"
            else {"ListPhoneNumbersSummaryList": []}
        )
        assert OutboundDestinationCheck().execute(_ctx(factory)).status == CheckStatus.SKIPPED


# --- A5: cost alerting ----------------------------------------------------------


def _cost_factory(monitors=(), subscriptions=(), budgets=(), errors=None):
    errors = errors or {}
    responses = {
        "get_anomaly_monitors": errors.get("monitors") or {"AnomalyMonitors": list(monitors)},
        "get_anomaly_subscriptions": errors.get("subs")
        or {"AnomalySubscriptions": list(subscriptions)},
        "describe_budgets": errors.get("budgets") or {"Budgets": list(budgets)},
    }
    return _factory(responses)


SERVICE_MONITOR = {"MonitorArn": "m1", "MonitorType": "DIMENSIONAL", "MonitorDimension": "SERVICE"}


class TestFraudCostAlerting:
    @pytest.mark.parametrize("frequency", ["IMMEDIATE", "DAILY"])
    def test_timely_anomaly_alert_passes(self, frequency):
        factory = _cost_factory(
            [SERVICE_MONITOR], [{"MonitorArnList": ["m1"], "Frequency": frequency}]
        )
        finding = FraudCostAlertingCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.PASS

    def test_weekly_only_fails_medium(self):
        # The demo account's real configuration: a weekly $200 digest.
        factory = _cost_factory(
            [SERVICE_MONITOR], [{"MonitorArnList": ["m1"], "Frequency": "WEEKLY"}]
        )
        finding = FraudCostAlertingCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.MEDIUM
        assert "up to a week" in finding.description

    def test_monitor_without_subscription_fails_medium(self):
        finding = FraudCostAlertingCheck().execute(_ctx(_cost_factory([SERVICE_MONITOR])))
        assert finding.severity == Severity.MEDIUM
        assert "notifies no one" in finding.description

    def test_nothing_fails_high_with_org_caveat(self):
        finding = FraudCostAlertingCheck().execute(_ctx(_cost_factory()))
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.HIGH
        assert "management account" in finding.description

    def test_connect_budget_passes(self):
        factory = _cost_factory(
            budgets=[{"BudgetName": "connect", "CostFilters": {"Service": ["Amazon Connect"]}}]
        )
        assert FraudCostAlertingCheck().execute(_ctx(factory)).status == CheckStatus.PASS

    def test_tag_monitor_does_not_count(self):
        tag_monitor = {"MonitorArn": "m2", "MonitorType": "DIMENSIONAL", "MonitorDimension": "TAG"}
        factory = _cost_factory([tag_monitor], [{"MonitorArnList": ["m2"], "Frequency": "DAILY"}])
        assert FraudCostAlertingCheck().execute(_ctx(factory)).severity == Severity.HIGH

    def test_custom_monitor_naming_connect_counts(self):
        custom = {
            "MonitorArn": "m3",
            "MonitorType": "CUSTOM",
            "MonitorSpecification": {
                "Dimensions": {"Key": "SERVICE", "Values": ["Amazon Connect"]}
            },
        }
        factory = _cost_factory([custom], [{"MonitorArnList": ["m3"], "Frequency": "DAILY"}])
        assert FraudCostAlertingCheck().execute(_ctx(factory)).status == CheckStatus.PASS

    def test_unreadable_monitors_skip_rather_than_claim_absence(self):
        factory = _cost_factory(errors={"monitors": _client_error("AccessDeniedException")})
        assert FraudCostAlertingCheck().execute(_ctx(factory)).status == CheckStatus.SKIPPED

    def test_account_evidence_is_read_once_per_run(self):
        calls: List[str] = []
        factory = _cost_factory()
        inner = factory.call_api_with_resilience.side_effect
        factory.call_api_with_resilience.side_effect = lambda *a, **k: (
            calls.append(a[1]),
            inner(*a, **k),
        )[1]
        check = FraudCostAlertingCheck()
        check.execute(_ctx(factory))
        check.execute(_ctx(factory))
        assert calls.count("get_anomaly_monitors") == 1
