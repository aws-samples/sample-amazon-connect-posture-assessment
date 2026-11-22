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


def _dest_factory(
    destinations: List[str],
    numbers=("+12065550100",),
    calls=None,
    total=None,
    quick_connects: Optional[Dict[str, str]] = None,
):
    contacts = [{"Id": f"c{i}", "InitiationMethod": "OUTBOUND"} for i in range(len(destinations))]
    by_id = {c["Id"]: d for c, d in zip(contacts, destinations)}
    return _factory(
        {
            "list_phone_numbers_v2": {
                "ListPhoneNumbersSummaryList": [{"PhoneNumber": n} for n in numbers]
            },
            "search_contacts": {"Contacts": contacts, "TotalCount": total or len(contacts)},
            "list_quick_connects": {
                "QuickConnectSummaryList": [
                    {"Id": name, "Name": name} for name in (quick_connects or {})
                ]
            },
            "describe_quick_connect": lambda QuickConnectId, **_: {
                "QuickConnect": {
                    "Name": QuickConnectId,
                    "QuickConnectConfig": {
                        "PhoneConfig": {"PhoneNumber": (quick_connects or {})[QuickConnectId]}
                    },
                }
            },
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
        assert finding.evidence["destinations_by_country"] == {"+1": 2}

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
            "InitiationMethods": ["OUTBOUND", "CALLBACK", "API", "EXTERNAL_OUTBOUND"],
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


def _cost_factory(monitors=(), subscriptions=(), budgets=(), errors=None, notified=None):
    errors = errors or {}
    notified = {b["BudgetName"]: 1 for b in budgets} if notified is None else notified
    responses = {
        "describe_budget_notifications_for_account": errors.get("notifications")
        or {
            "BudgetNotificationsForAccount": [
                {"BudgetName": name, "Notifications": [{}] * count}
                for name, count in notified.items()
            ]
        },
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


# --- Audit against the PR #22/#23 review findings -----------------------------


class TestReviewClassRegressions:
    """Each test pins one class of defect the earlier reviews found."""

    def test_ip_access_without_default_profile_skips(self):
        # Missing data must not become a confident FAIL.
        factory = _factory(_profiles({"Id": "o", "Name": "Office", "AllowedIps": ["10.0.0.0/8"]}))
        finding = IpAccessControlCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED

    def test_partial_destination_sample_is_not_a_clean_pass(self):
        # A failed batch must not leave partial data behind a PASS.
        factory = _dest_factory(["+12065550111", "+12065550112"])
        inner = factory.call_api_with_resilience.side_effect

        def _flaky(c, op, s=None, **kw):
            if op == "describe_contact" and kw["ContactId"] == "c1":
                raise _client_error("ThrottlingException")
            return inner(c, op, s, **kw)

        factory.call_api_with_resilience.side_effect = _flaky
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["destination_read_failures"] == 1

    def test_non_telephone_endpoints_do_not_block_a_pass(self):
        factory = _dest_factory(["+12065550111", "sip:agent@example"])
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.PASS

    def test_budget_without_notifications_does_not_pass(self):
        # A claimed control that alerts no one is not a control.
        budget = {"BudgetName": "connect", "CostFilters": {"Service": ["Amazon Connect"]}}
        finding = FraudCostAlertingCheck().execute(
            _ctx(_cost_factory(budgets=[budget], notified={"connect": 0}))
        )
        assert finding.status == CheckStatus.FAIL
        assert "have no notifications" in finding.description

    def test_filter_expression_budget_counts(self):
        # Budgets defined with the newer FilterExpression must not be missed.
        budget = {
            "BudgetName": "connect",
            "FilterExpression": {"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Connect"]}},
        }
        assert (
            FraudCostAlertingCheck().execute(_ctx(_cost_factory(budgets=[budget]))).status
            == CheckStatus.PASS
        )

    def test_unreadable_budgets_skip_rather_than_claim_absence(self):
        factory = _cost_factory(
            [SERVICE_MONITOR],
            [{"MonitorArnList": ["m1"], "Frequency": "WEEKLY"}],
            errors={"budgets": _client_error("AccessDeniedException")},
        )
        finding = FraudCostAlertingCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED

    def test_thresholds_are_recorded_as_the_methodology_states(self):
        sub = {"MonitorArnList": ["m1"], "Frequency": "WEEKLY", "Threshold": 200.0}
        finding = FraudCostAlertingCheck().execute(_ctx(_cost_factory([SERVICE_MONITOR], [sub])))
        assert finding.evidence["alert_thresholds_for_connect"][0]["threshold"] == 200.0

    def test_controls_are_registered_as_manual_review_with_consistent_severity(self):
        # Through the real registry, not a hand-set disposition: a broken
        # registration would export these to Security Hub as failed controls,
        # and a per-finding severity on a non-dynamic control is rejected.
        from amazon_connect_assessment.checks.control_registry import (
            get_atomic_control_registry,
        )
        from amazon_connect_assessment.checks.registration import register_all_checks
        from amazon_connect_assessment.checks.registry import CheckRegistry
        from amazon_connect_assessment.models import FindingDisposition
        from amazon_connect_assessment.score_policy import is_control_failure

        registry = CheckRegistry()
        register_all_checks(registry)
        catalog = get_atomic_control_registry()
        cases = {
            "sec-ip-access-001": _factory(_profiles({"Id": "d", "IsDefault": True})),
            "sec-outbound-scope-001": _scope_factory([["agent"], ["agent"]]),
            "sec-outbound-dest-001": _dest_factory(["+33612345678"]),
            "sec-fraud-alerting-001": _cost_factory(
                [SERVICE_MONITOR], [{"MonitorArnList": ["m1"], "Frequency": "WEEKLY"}]
            ),
        }
        for control_id, factory in cases.items():
            finding = registry.get_check(control_id).execute(_ctx(factory))
            control = catalog.get(control_id)
            assert finding.status == CheckStatus.FAIL, control_id
            assert finding.disposition == FindingDisposition.MANUAL_REVIEW, control_id
            assert not is_control_failure(finding), control_id
            if finding.severity != control.default_severity:
                assert control.dynamic_severity, control_id

    def test_contact_record_control_can_be_disabled_as_documented(self):
        from amazon_connect_assessment.checks.registration import register_all_checks
        from amazon_connect_assessment.checks.registry import CheckRegistry

        registry = CheckRegistry()
        register_all_checks(registry, checks_config={"sec-outbound-dest-001": {"enabled": False}})
        assert "sec-outbound-dest-001" not in registry.list_check_ids()


def test_policy_grants_every_permission_the_controls_call():
    # A merge that drops these would otherwise pass every other test while
    # the controls SKIP in real runs for lack of permission.
    from amazon_connect_assessment import iam_permissions

    granted = {a for s in iam_permissions.POLICY_STATEMENTS for a in s["Action"]}
    required = {
        "connect:ListAuthenticationProfiles",
        "connect:DescribeAuthenticationProfile",
        "connect:ListSecurityProfiles",
        "connect:ListSecurityProfilePermissions",
        "connect:SearchUsers",
        "connect:ListPhoneNumbersV2",
        "connect:SearchContacts",
        "connect:DescribeContact",
        "ce:GetAnomalyMonitors",
        "ce:GetAnomalySubscriptions",
        "budgets:ViewBudget",
    }
    assert required <= granted, sorted(required - granted)


# --- PR #23 third review ---------------------------------------------------------


class TestThirdReview:
    def test_unrestricted_non_default_profile_fails(self):
        # The API exposes no profile-to-user assignment, so an unrestricted
        # non-default profile cannot be ruled out as covering some users.
        factory = _factory(
            _profiles(
                {"Id": "d", "IsDefault": True, "AllowedIps": ["10.0.0.0/8"]},
                {"Id": "o", "Name": "Contractors"},
            )
        )
        finding = IpAccessControlCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.FAIL
        assert "Contractors" in finding.description
        assert "does not show which users" in finding.description

    def test_every_profile_restricted_passes(self):
        factory = _factory(
            _profiles(
                {"Id": "d", "IsDefault": True, "AllowedIps": ["10.0.0.0/8"]},
                {"Id": "o", "Name": "Office", "AllowedIps": ["192.168.0.0/16"]},
            )
        )
        assert IpAccessControlCheck().execute(_ctx(factory)).status == CheckStatus.PASS

    @pytest.mark.parametrize(
        ("number", "key"),
        [
            ("+18765550100", "1-876"),  # Jamaica
            ("+18095550100", "1-809"),  # Dominican Republic
            ("+12845550100", "1-284"),  # British Virgin Islands
            ("+12065550100", "1"),  # US
            ("+14165550100", "1"),  # Canada
            ("+17875550100", "1"),  # Puerto Rico (US territory)
        ],
    )
    def test_nanp_caribbean_codes_are_separate_countries(self, number, key):
        from amazon_connect_assessment.checks.telephony_fraud_checks import destination_key

        assert destination_key(number) == key

    def test_caribbean_premium_calls_from_a_us_instance_fail(self):
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+18765550111", "+12065550112"]))
        )
        assert finding.status == CheckStatus.FAIL
        assert "+1-876 (Jamaica): 1" in finding.description

    def test_caribbean_instance_treats_its_own_area_code_as_home(self):
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory(["+18765550111"], numbers=("+18765550100",)))
        )
        assert finding.status == CheckStatus.PASS

    def test_quick_connect_to_satellite_number_fails_without_any_calls(self):
        # Review: transfers to a +881 number would still PASS.
        finding = OutboundDestinationCheck().execute(
            _ctx(_dest_factory([], quick_connects={"Remote site": "+8816123456"}))
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.severity == Severity.HIGH
        assert "Remote site" in finding.description
        assert "+8816123456" not in str(finding.evidence) + finding.description

    @staticmethod
    def _failing(factory, operation, code, only_ids=None):
        """Make ``operation`` raise ``code`` (optionally only for some quick connects)."""
        orig = factory.call_api_with_resilience.side_effect

        def _call(client, op, service=None, **kwargs):
            if op == operation and (only_ids is None or kwargs.get("QuickConnectId") in only_ids):
                raise _client_error(code)
            return orig(client, op, service, **kwargs)

        factory.call_api_with_resilience.side_effect = _call
        return factory

    def test_unreadable_quick_connect_skips_rather_than_errors(self):
        factory = self._failing(
            _dest_factory(
                ["+12065550111"],
                quick_connects={"Office": "+12065550199", "Broken": "+12065550198"},
            ),
            "describe_quick_connect",
            "InternalServiceException",
            {"Broken"},
        )
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED
        assert "1 of 2 phone-number quick connect(s) could not be read" in finding.description
        assert finding.evidence["quick_connect_read_failures"] == 1
        assert finding.evidence["evidence_complete"] is False

    def test_unreadable_quick_connect_does_not_hide_a_flagged_one(self):
        factory = self._failing(
            _dest_factory([], quick_connects={"Remote site": "+8816123456", "Broken": "+1206"}),
            "describe_quick_connect",
            "InternalServiceException",
            {"Broken"},
        )
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["quick_connect_read_failures"] == 1

    def test_quick_connect_list_failure_skips_rather_than_errors(self):
        factory = self._failing(
            _dest_factory(["+12065550111"]), "list_quick_connects", "InternalServiceException"
        )
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED
        assert "quick connects could not be listed" in finding.description
        assert finding.evidence["quick_connect_list_failed"] is True

    def test_quick_connect_describe_access_denied_names_the_permission(self):
        factory = self._failing(
            _dest_factory([], quick_connects={"Office": "+12065550199"}),
            "describe_quick_connect",
            "AccessDeniedException",
        )
        finding = OutboundDestinationCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED
        assert "connect:DescribeQuickConnect" in str(finding.evidence) + finding.description

    @pytest.mark.parametrize("check_cls", [OutboundPermissionScopeCheck, OutboundDestinationCheck])
    def test_unreported_outbound_setting_skips_rather_than_not_applicable(self, check_cls):
        instance = _instance()
        instance.outbound_calls_enabled = None
        finding = check_cls().execute(_ctx(_factory({}), instance))
        assert finding.status == CheckStatus.SKIPPED

    def test_unreported_outbound_setting_keeps_ip_access_at_high(self):
        instance = _instance()
        instance.outbound_calls_enabled = None
        factory = _factory(_profiles({"Id": "d", "IsDefault": True}))
        assert IpAccessControlCheck().execute(_ctx(factory, instance)).severity == Severity.HIGH

    @pytest.mark.parametrize(
        ("partition", "region"), [("aws", "us-east-1"), ("aws-cn", "cn-northwest-1")]
    )
    def test_billing_clients_use_the_partition_region(self, partition, region):
        instance = _instance()
        instance.instance_arn = f"arn:{partition}:connect:x:{ACCOUNT}:instance/i-1"
        factory = _cost_factory()
        FraudCostAlertingCheck().execute(_ctx(factory, instance))
        regions = {c.kwargs.get("region_name") for c in factory.get_client.call_args_list}
        assert regions == {region}

    def test_govcloud_skips_with_an_explanation_and_no_calls(self):
        instance = _instance()
        instance.instance_arn = f"arn:aws-us-gov:connect:us-gov-west-1:{ACCOUNT}:instance/i-1"
        factory = _cost_factory()
        finding = FraudCostAlertingCheck().execute(_ctx(factory, instance))
        assert finding.status == CheckStatus.SKIPPED
        assert "GovCloud" in finding.description
        factory.call_api_with_resilience.assert_not_called()

    def test_client_creation_failure_skips_rather_than_errors(self):
        factory = _cost_factory()
        factory.get_client.side_effect = RuntimeError("no credentials")
        finding = FraudCostAlertingCheck().execute(_ctx(factory))
        assert finding.status == CheckStatus.SKIPPED

    def test_other_accounts_are_not_blocked_by_an_in_flight_fetch(self):
        import threading

        check = FraudCostAlertingCheck()
        release = threading.Event()
        slow = _cost_factory()
        inner = slow.call_api_with_resilience.side_effect
        slow.call_api_with_resilience.side_effect = lambda *a, **k: (
            release.wait(5),
            inner(*a, **k),
        )[1]
        other = _instance()
        other.instance_arn = "arn:aws:connect:us-east-1:999999999999:instance/i-2"
        worker = threading.Thread(target=check.execute, args=(_ctx(slow),))
        worker.start()
        done = threading.Event()
        threading.Thread(
            target=lambda: (check.execute(_ctx(_cost_factory(), other)), done.set())
        ).start()
        assert done.wait(2), "a second account waited behind the first account's fetch"
        release.set()
        worker.join(5)
