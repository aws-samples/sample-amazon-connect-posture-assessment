"""
Tests for advanced resilience checks.

Covers the ACGR check set (six atomic checks) plus the other resilience
advanced checks (CloudWatch alarm coverage, carrier diversity, hardcoded
routing).
"""

import json

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.resilience_advanced_checks import (
    ACGRConfigurationCheck,
    ACGRFailoverTestCheck,
    ACGRIdentityManagementCheck,
    ACGRPhoneNumberBindingCheck,
    ACGRTrafficDistributionCheck,
    ACGRTrafficDistributionGroupStatusCheck,
    CarrierDiversityCheck,
    CloudWatchAlarmMonitoringCheck,
    HardcodedRoutingCheck,
    _reset_acgr_cache,
    register_advanced_resilience_checks,
)
from amazon_connect_assessment.models import (
    CheckStatus,
    ContactFlow,
    FindingDisposition,
    Severity,
)
from tests.conftest import build_action, build_contact_flow


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:...:flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


def _instance_with_flows(instance, flows):
    """
    Attach multiple (name, flow_json) pairs as distinct ContactFlow
    objects. Used by the AWS-default-sample-flow-exclusion tests, which
    need both a "Sample ..." flow and a customer-named flow on the same
    instance to prove the sample one is excluded while the customer one
    is still evaluated.
    """
    instance.contact_flows = [
        ContactFlow(
            id=f"f{i}",
            arn=f"arn:...:flow/f{i}",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
        for i, (name, flow_json) in enumerate(flows)
    ]
    return instance


# ---------------------------------------------------------------------------
# ACGR helpers
#
# The six ACGR checks memoize per-instance API results in a module-level
# cache. Reset it between tests so cases don't leak into each other, and
# provide a helper that programs the factory mock to return whatever TDG
# shape a test needs.
# ---------------------------------------------------------------------------


def _program_acgr_apis(
    factory,
    *,
    tdgs=None,
    tdg_details=None,
    traffic_distributions=None,
    tdg_phone_numbers=None,
    instance_phone_numbers=None,
    cloudtrail_events=None,
    access_denied_on=None,
):
    """
    Route `call_api_with_resilience` responses for the ACGR context probes.

    `access_denied_on` is an optional set of operation names that should raise
    AccessDenied instead of returning a value — used to exercise the SKIPPED
    degradation paths.
    """
    _reset_acgr_cache()
    tdgs = tdgs or []
    tdg_details = tdg_details or {}
    traffic_distributions = traffic_distributions or {}
    tdg_phone_numbers = tdg_phone_numbers or {}
    instance_phone_numbers = instance_phone_numbers or []
    cloudtrail_events = cloudtrail_events or []
    access_denied_on = access_denied_on or set()

    def _side_effect(client, op_name, service, **kwargs):
        if op_name in access_denied_on:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op_name)
        if op_name == "list_traffic_distribution_groups":
            return {"TrafficDistributionGroupSummaryList": tdgs}
        if op_name == "describe_traffic_distribution_group":
            tdg_id = kwargs.get("TrafficDistributionGroupId")
            return {"TrafficDistributionGroup": tdg_details.get(tdg_id, {})}
        if op_name == "get_traffic_distribution":
            tdg_id = kwargs.get("Id")
            return traffic_distributions.get(tdg_id, {})
        if op_name == "list_phone_numbers_v2":
            target = kwargs.get("TargetArn", "")
            if "traffic-distribution-group" in target:
                # Match by TDG ARN if provided
                nums = tdg_phone_numbers.get(target, [])
                return {"ListPhoneNumbersSummaryList": nums}
            return {"ListPhoneNumbersSummaryList": instance_phone_numbers}
        if op_name == "lookup_events":
            return {"Events": cloudtrail_events}
        return {}

    factory.call_api_with_resilience.side_effect = _side_effect


def _cloudtrail_event(
    *, request_id=None, resource_names=None, malformed=False, error_code=None, error_message=None
):
    event = {
        "EventName": "UpdateTrafficDistribution",
        "EventTime": "2026-06-01T10:00:00Z",
    }
    if malformed:
        event["CloudTrailEvent"] = "{not-json"
    else:
        event_payload = {}
        if request_id is not None:
            event_payload["RequestParameters"] = {"Id": request_id}
        if error_code is not None:
            event_payload["errorCode"] = error_code
        if error_message is not None:
            event_payload["errorMessage"] = error_message
        event["CloudTrailEvent"] = json.dumps(event_payload)
    if resource_names is not None:
        event["Resources"] = [{"ResourceName": resource_name} for resource_name in resource_names]
    return event


def _valid_connect_alarm(metric, *, instance_id="test-instance-123", **overrides):
    alarm = {
        "AlarmName": f"{metric}-alarm",
        "Namespace": "AWS/Connect",
        "MetricName": metric,
        "Dimensions": [
            {"Name": "InstanceId", "Value": instance_id},
            {"Name": "MetricGroup", "Value": "VoiceCalls"},
        ],
        "ActionsEnabled": True,
        "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:connect-alerts"],
    }
    alarm.update(overrides)
    return alarm


_REQUIRED_VOICE_METRICS = (
    "ConcurrentCalls",
    "ThrottledCalls",
    "MissedCalls",
    "CallsPerInterval",
)


# ---------------------------------------------------------------------------
# res-acgr-config-001 — ACGR Configuration Discovery
# ---------------------------------------------------------------------------


class TestACGRConfigurationCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # No TDG configured → NOT_APPLICABLE (previously an informational
        # PASS with remediation; user feedback was that even a soft PASS
        # here cluttered reports for the ~95% who don't need ACGR).
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE
        # The reason is carried in the description prefix ("Not applicable: ...")
        assert "not configured" in finding.description.lower()
        # No structured remediation on N/A findings — nothing to fix.
        assert finding.structured_remediation is None

    def test_tdg_present_passes_and_reports_configured(
        self, make_check_context, mock_aws_client_factory
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {
                    "Id": "tdg-1",
                    "Name": "prod-tdg",
                    "Arn": "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1",
                }
            ],
        )
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS
        assert "configured" in finding.description.lower()
        assert finding.evidence["traffic_distribution_groups"] == 1

    def test_access_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            access_denied_on={"list_traffic_distribution_groups"},
        )
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED


# ---------------------------------------------------------------------------
# res-acgr-identity-001 — SAML identity required
# ---------------------------------------------------------------------------


class TestACGRIdentityManagementCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRIdentityManagementCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "acgr is not configured" in finding.description.lower()

    def test_connect_managed_identity_with_tdg_fails(
        self, make_check_context, mock_aws_client_factory, sample_connect_instance
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        # Fixture already uses CONNECT_MANAGED.
        assert sample_connect_instance.identity_management_type == "CONNECT_MANAGED"
        finding = ACGRIdentityManagementCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "saml" in finding.description.lower()
        assert finding.severity.value == "high"
        # Remediation must not pretend this is a quick toggle.
        step = finding.structured_remediation.steps[0].instruction.lower()
        assert "cannot be changed in place" in step or "migration" in step

    def test_saml_identity_with_tdg_passes(
        self, make_check_context, mock_aws_client_factory, sample_connect_instance
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        sample_connect_instance.identity_management_type = "SAML"
        finding = ACGRIdentityManagementCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# res-acgr-tdg-status-001 — TDG in ACTIVE status
# ---------------------------------------------------------------------------


class TestACGRTrafficDistributionGroupStatusCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_all_tdgs_active_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"},
                {"Id": "tdg-2", "Name": "dr-tdg", "Arn": "arn:...:tdg/tdg-2"},
            ],
            tdg_details={
                "tdg-1": {"Id": "tdg-1", "Status": "ACTIVE"},
                "tdg-2": {"Id": "tdg-2", "Status": "ACTIVE"},
            },
        )
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_non_active_tdg_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"},
                {"Id": "tdg-2", "Name": "dr-tdg", "Arn": "arn:...:tdg/tdg-2"},
            ],
            tdg_details={
                "tdg-1": {"Id": "tdg-1", "Status": "ACTIVE"},
                "tdg-2": {"Id": "tdg-2", "Status": "CREATION_FAILED"},
            },
        )
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "not in active status" in finding.description.lower()
        assert "dr-tdg" in finding.description
        assert "creation_failed" in finding.description.lower()


# ---------------------------------------------------------------------------
# res-acgr-traffic-dist-001 — traffic distribution inventory
# ---------------------------------------------------------------------------


class TestACGRTrafficDistributionCheck:
    def test_acgr_traffic_distribution_without_tdg_is_not_applicable(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])

        # Act
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_acgr_traffic_distribution_100_0_inventory_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [
                            {"Region": "us-east-1", "Percentage": 100},
                            {"Region": "us-west-2", "Percentage": 0},
                        ],
                    },
                }
            },
        )
        check = ACGRTrafficDistributionCheck()

        # Act
        finding = check.execute(make_check_context())

        # Assert
        assert check.disposition == FindingDisposition.INFORMATIONAL
        assert finding.status == CheckStatus.PASS
        assert finding.structured_remediation is None
        assert finding.evidence["distribution_mode_by_tdg"]["prod-tdg"] == "hot-standby"

    def test_acgr_traffic_distribution_single_region_inventory_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [{"Region": "us-east-1", "Percentage": 100}],
                    },
                }
            },
        )

        # Act
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["distribution_mode_by_tdg"]["prod-tdg"] == "single-region"

    def test_acgr_traffic_distribution_multi_region_inventory_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [
                            {"Region": "us-east-1", "Percentage": 80},
                            {"Region": "us-west-2", "Percentage": 20},
                        ],
                    },
                }
            },
        )

        # Act
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["distribution_mode_by_tdg"]["prod-tdg"] == "multi-region"

    def test_acgr_traffic_distribution_incomplete_evidence_is_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {"Id": "tdg-1", "Name": "complete-tdg", "Arn": "arn:...:tdg/tdg-1"},
                {"Id": "tdg-2", "Name": "incomplete-tdg", "Arn": "arn:...:tdg/tdg-2"},
            ],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [{"Region": "us-east-1", "Percentage": 100}],
                    },
                },
                "tdg-2": {},
            },
        )

        # Act
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["evaluated_tdg_count"] == 1
        assert finding.evidence["incomplete_tdg_count"] == 1

    def test_acgr_traffic_distribution_denied_evidence_is_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            access_denied_on={"get_traffic_distribution"},
        )

        # Act
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED


# ---------------------------------------------------------------------------
# res-acgr-failover-test-001 — scoped evidence in the last 90 days
# ---------------------------------------------------------------------------


class TestACGRFailoverTestCheck:
    def test_acgr_failover_without_tdg_is_not_applicable(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_acgr_failover_unrelated_tdg_event_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[_cloudtrail_event(request_id="tdg-unrelated")],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["candidate_event_count"] == 1
        assert finding.evidence["matched_event_count"] == 0
        assert finding.evidence["unrelated_event_count"] == 1

    def test_acgr_failover_request_id_match_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[_cloudtrail_event(request_id="tdg-1")],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["matched_event_count"] == 1
        assert finding.evidence["matched_tdgs"] == ["tdg-1"]

    def test_acgr_failover_resource_arn_match_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            cloudtrail_events=[_cloudtrail_event(resource_names=[tdg_arn])],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["matched_event_count"] == 1
        assert finding.evidence["matched_tdgs"] == ["tdg-1"]

    def test_acgr_failover_failed_and_malformed_matches_return_fail(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[
                _cloudtrail_event(
                    request_id="tdg-1",
                    error_code="AccessDeniedException",
                    error_message="denied",
                ),
                _cloudtrail_event(resource_names=["tdg-1"], malformed=True),
            ],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["matched_event_count"] == 2
        assert finding.evidence["successful_matched_event_count"] == 0
        assert finding.evidence["failed_matched_event_count"] == 1
        assert finding.evidence["malformed_matched_event_count"] == 1
        assert finding.evidence["failed_matched_events"][0]["error_code"] == (
            "AccessDeniedException"
        )
        assert finding.evidence["malformed_matched_events"][0]["reason"] == (
            "CloudTrailEvent payload is malformed"
        )

    def test_acgr_failover_successful_match_with_failed_attempt_returns_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[
                _cloudtrail_event(request_id="tdg-1", error_code="InternalFailure"),
                _cloudtrail_event(request_id="tdg-1"),
            ],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["matched_event_count"] == 2
        assert finding.evidence["successful_matched_event_count"] == 1
        assert finding.evidence["failed_matched_event_count"] == 1

    def test_acgr_failover_successful_match_with_incomplete_pagination_returns_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        base_side_effect = mock_aws_client_factory.call_api_with_resilience.side_effect

        def _repeated_token_side_effect(client, op_name, service, **kwargs):
            if op_name != "lookup_events":
                return base_side_effect(client, op_name, service, **kwargs)
            return {
                "Events": [_cloudtrail_event(request_id="tdg-1")],
                "NextToken": "repeated-token",
            }

        mock_aws_client_factory.call_api_with_resilience.side_effect = _repeated_token_side_effect

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["evidence_complete"] is False
        assert finding.evidence["pagination_complete"] is False
        assert finding.evidence["pages_scanned"] == 2
        assert finding.evidence["limitations"]
        assert "incomplete" in finding.description.lower()

    def test_acgr_failover_no_success_with_incomplete_pagination_returns_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        base_side_effect = mock_aws_client_factory.call_api_with_resilience.side_effect

        def _repeated_token_side_effect(client, op_name, service, **kwargs):
            if op_name != "lookup_events":
                return base_side_effect(client, op_name, service, **kwargs)
            return {
                "Events": [_cloudtrail_event(request_id="tdg-unrelated")],
                "NextToken": "repeated-token",
            }

        mock_aws_client_factory.call_api_with_resilience.side_effect = _repeated_token_side_effect

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["evidence_complete"] is False
        assert finding.evidence["pagination_complete"] is False
        assert finding.evidence["pages_scanned"] == 2
        assert finding.evidence["successful_matched_event_count"] == 0

    def test_acgr_failover_mixed_and_malformed_events_record_counts(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[
                _cloudtrail_event(request_id="tdg-1"),
                _cloudtrail_event(resource_names=["tdg-unrelated"]),
                _cloudtrail_event(malformed=True),
                {"EventName": "UpdateTrafficDistribution"},
            ],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["candidate_event_count"] == 4
        assert finding.evidence["matched_event_count"] == 1
        assert finding.evidence["unrelated_event_count"] == 1
        assert finding.evidence["malformed_event_count"] == 2
        assert finding.evidence["matched_tdgs"] == ["tdg-1"]

    def test_acgr_failover_matching_event_on_second_page_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        base_side_effect = mock_aws_client_factory.call_api_with_resilience.side_effect

        def _paginated_side_effect(client, op_name, service, **kwargs):
            if op_name != "lookup_events":
                return base_side_effect(client, op_name, service, **kwargs)
            if kwargs.get("NextToken") is None:
                return {
                    "Events": [_cloudtrail_event(request_id="tdg-unrelated")],
                    "NextToken": "page-2",
                }
            return {"Events": [_cloudtrail_event(request_id="tdg-1")]}

        mock_aws_client_factory.call_api_with_resilience.side_effect = _paginated_side_effect

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["candidate_event_count"] == 2
        assert finding.evidence["matched_event_count"] == 1
        lookup_calls = [
            call
            for call in mock_aws_client_factory.call_api_with_resilience.call_args_list
            if call.args[1] == "lookup_events"
        ]
        assert len(lookup_calls) == 2
        assert lookup_calls[1].kwargs["NextToken"] == "page-2"

    def test_acgr_failover_without_scoped_events_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[],
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["matched_event_count"] == 0

    def test_acgr_failover_cloudtrail_access_denied_is_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            access_denied_on={"lookup_events"},
        )

        # Act
        finding = ACGRFailoverTestCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert "cloudtrail:LookupEvents" in finding.evidence.get("required_permission", "")


# ---------------------------------------------------------------------------
# res-acgr-numbers-001 — Phone numbers claimed against TDG
# ---------------------------------------------------------------------------


class TestACGRPhoneNumberBindingCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_zero_numbers_on_tdg_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={tdg_arn: []},
            instance_phone_numbers=[{"PhoneNumber": "+18005551234"}],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "no phone numbers are claimed" in finding.description.lower()

    def test_paginates_beyond_first_page_of_numbers(
        self, make_check_context, mock_aws_client_factory
    ):
        # Regression test: list_phone_numbers_v2 used to be called once
        # with MaxResults=50 and no NextToken handling, so a TDG or
        # instance with more than 50 claimed numbers would silently
        # undercount (or a 51st+ number bound to the instance would go
        # unnoticed). Program two pages per TargetArn and confirm both
        # are combined into the final evidence counts.
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        instance_arn = "arn:aws:connect:us-east-1:1:instance/inst-1"

        def _side_effect(client, op_name, service, **kwargs):
            if op_name == "list_traffic_distribution_groups":
                return {
                    "TrafficDistributionGroupSummaryList": [
                        {"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}
                    ]
                }
            if op_name == "list_phone_numbers_v2":
                target = kwargs.get("TargetArn")
                token = kwargs.get("NextToken")
                if target == tdg_arn:
                    if token is None:
                        return {
                            "ListPhoneNumbersSummaryList": [{"PhoneNumber": "+1000000001"}],
                            "NextToken": "tdg-page-2",
                        }
                    return {"ListPhoneNumbersSummaryList": [{"PhoneNumber": "+1000000002"}]}
                if target == instance_arn:
                    return {"ListPhoneNumbersSummaryList": []}
            return {}

        mock_aws_client_factory.call_api_with_resilience.side_effect = _side_effect
        context = make_check_context()
        context.instance.instance_arn = instance_arn

        finding = ACGRPhoneNumberBindingCheck().execute(context)
        assert finding.evidence["numbers_on_tdgs"]["prod-tdg"] == 2
        assert finding.evidence["total_numbers_on_tdgs"] == 2
        assert finding.status == CheckStatus.PASS

    def test_some_numbers_on_instance_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={tdg_arn: [{"PhoneNumber": "+18005551234"}]},
            instance_phone_numbers=[
                {"PhoneNumber": "+18005555678"},
                {"PhoneNumber": "+18005559999"},
            ],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "directly against the instance" in finding.description.lower()
        assert finding.evidence["numbers_directly_on_instance"] == 2
        assert finding.evidence["total_numbers_on_tdgs"] == 1

    def test_all_numbers_on_tdg_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={
                tdg_arn: [
                    {"PhoneNumber": "+18005551234"},
                    {"PhoneNumber": "+18005555678"},
                ]
            },
            instance_phone_numbers=[],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# CloudWatch alarm coverage (res-cloudwatch-001)
# ---------------------------------------------------------------------------


class TestCloudWatchAlarmMonitoringCheck:
    def test_cloudwatch_alarm_inventory_without_alarms_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": []}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["missing_metrics"] == list(_REQUIRED_VOICE_METRICS)

    def test_cloudwatch_dimensionless_alarm_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        alarms[0]["Dimensions"] = []
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["missing_or_wrong_dimension_candidate_count"] == 1
        assert "ConcurrentCalls" in finding.evidence["missing_metrics"]

    def test_cloudwatch_wrong_instance_alarm_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        alarms[0] = _valid_connect_alarm("ConcurrentCalls", instance_id="other-instance")
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["wrong_instance_candidate_count"] == 1
        assert "ConcurrentCalls" in finding.evidence["missing_metrics"]

    def test_cloudwatch_wrong_metric_group_alarm_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        alarms[0]["Dimensions"][1]["Value"] = "Chats"
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["missing_or_wrong_dimension_candidate_count"] == 1
        assert "ConcurrentCalls" in finding.evidence["missing_metrics"]

    def test_cloudwatch_actionless_alarm_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        alarms[0]["AlarmActions"] = ["  "]
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["no_action_candidate_count"] == 1
        assert "ConcurrentCalls" in finding.evidence["missing_metrics"]

    def test_cloudwatch_disabled_alarm_is_rejected(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        alarms[0]["ActionsEnabled"] = False
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["disabled_candidate_count"] == 1
        assert "ConcurrentCalls" in finding.evidence["missing_metrics"]

    def test_cloudwatch_composite_alarm_without_metric_alarm_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.describe_alarms_resilient.return_value = {
            "MetricAlarms": [],
            "CompositeAlarms": [
                {
                    "AlarmName": "connect-composite",
                    "AlarmRule": 'ALARM("ConcurrentCalls-alarm")',
                }
            ],
        }

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["composite_alarm_count"] == 1
        assert finding.evidence["covered_metrics"] == []

    def test_cloudwatch_valid_instance_alarm_coverage_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        alarms = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS]
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["covered_metrics"] == sorted(_REQUIRED_VOICE_METRICS)
        assert "does not prove" in finding.description.lower()

    def test_cloudwatch_valid_coverage_on_second_page_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire(mock_aws_client_factory)
        page_one = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS[:2]]
        page_two = [_valid_connect_alarm(metric) for metric in _REQUIRED_VOICE_METRICS[2:]]
        mock_aws_client_factory.describe_alarms_resilient.side_effect = [
            {"MetricAlarms": page_one, "NextToken": "page-2"},
            {"MetricAlarms": page_two},
        ]

        # Act
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert mock_aws_client_factory.describe_alarms_resilient.call_count == 2
        second_call = mock_aws_client_factory.describe_alarms_resilient.call_args_list[1]
        assert second_call.kwargs["NextToken"] == "page-2"
        assert finding.evidence["covered_metrics"] == sorted(_REQUIRED_VOICE_METRICS)


# ---------------------------------------------------------------------------
# Carrier diversity (res-carrier-diversity-001)
# ---------------------------------------------------------------------------


class TestCarrierDiversityCheck:
    def test_single_country_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": [
                {"PhoneNumberCountryCode": "US"},
                {"PhoneNumberCountryCode": "US"},
            ]
        }

        # Act
        finding = CarrierDiversityCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "nothing to fix" in finding.description
        assert "Global Resiliency" in finding.description

    def test_multi_country_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": [
                {"PhoneNumberCountryCode": "US"},
                {"PhoneNumberCountryCode": "GB"},
            ]
        }
        finding = CarrierDiversityCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_no_numbers_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": []
        }
        finding = CarrierDiversityCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# Hardcoded routing (res-hardcoded-routing-001)
#
# Reviewer feedback: (1) AWS's built-in "Sample ..." flows ship with
# literal phone numbers by design and shouldn't be flagged as a customer
# defect; (2) hardcoding is a normal pattern in contact centers, so the
# check is LOW severity and always reports complete literal inventory as PASS.
# ---------------------------------------------------------------------------


class TestHardcodedRoutingCheck:
    def test_hardcoded_literals_inventory_passes_expected_result(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        actions = [
            build_action(
                f"a{i}",
                "TransferContactToPhoneNumber",
                {"PhoneNumber": f"+1800555000{i}"},
            )
            for i in range(5)
        ]
        flow = build_contact_flow(actions)
        inst = _instance_with_flow(sample_connect_instance, flow)

        # Act
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["hardcoded_count"] == 5
        assert "threshold" not in finding.description.lower()
        for detail in finding.evidence["hardcoded_details"]:
            assert detail["hardcoded_value"].startswith("***")

    def test_dynamic_references_pass(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "$.Attributes.Dest"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_few_hardcoded_is_acceptable(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005551234"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        # One observed literal is still an informational PASS.
        assert finding.status == CheckStatus.PASS

    def test_sample_flows_excluded_from_hardcoded_count(
        self, make_check_context, sample_connect_instance
    ):
        # A default "Sample ..." flow with literal numbers is excluded because
        # it is AWS demo content, not customer-authored configuration.
        sample_actions = [
            build_action(
                f"s{i}",
                "TransferContactToPhoneNumber",
                {"PhoneNumber": f"+1800555000{i}"},
            )
            for i in range(5)
        ]
        sample_flow = build_contact_flow(sample_actions)
        customer_flow = build_contact_flow(
            [
                build_action(
                    "c1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005559999"},
                )
            ]
        )
        inst = _instance_with_flows(
            sample_connect_instance,
            [("Sample AB test", sample_flow), ("My Custom Flow", customer_flow)],
        )
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        # Only the one literal destination in the customer flow counts.
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["sample_flows_excluded"] == 1
        assert finding.evidence["hardcoded_count"] == 1

    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: hardcoding is a normal, common pattern in
        # contact center flows, not a defect — downgraded from the
        # original MEDIUM to reflect that.
        assert HardcodedRoutingCheck().severity == Severity.LOW


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_advanced_resilience_checks():
    registry = CheckRegistry()
    register_advanced_resilience_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    # The full ACGR set (six checks) plus the other advanced resilience checks.
    assert {
        "res-acgr-config-001",
        "res-acgr-identity-001",
        "res-acgr-tdg-status-001",
        "res-acgr-traffic-dist-001",
        "res-acgr-failover-test-001",
        "res-acgr-numbers-001",
        "res-cloudwatch-001",
        "res-carrier-diversity-001",
        "res-hardcoded-routing-001",
    } <= ids
    # Old id must be gone — the rename is deliberate.
    assert "res-global-001" not in ids


# ---------------------------------------------------------------------------
# Regression test: ACGR context cache race under the parallel engine.
#
# The original implementation inserted an empty _ACGRContext into the
# module-level cache under the lock, released the lock, and only then made
# the slow API calls to fill it in. A second thread for the SAME instance
# arriving in that window would find the still-empty context and conclude
# "ACGR not configured" even though real TDGs existed and the first
# thread's fetch just hadn't finished yet — a silent false negative on a
# real DR misconfiguration. It was also an unsynchronized read/write race
# on the dataclass fields.
#
# The fix gives each instance its own fetch lock: whichever thread wins
# holds it for the entire fetch, and any other thread for the same
# instance blocks until the fetch is complete, then gets the fully
# populated context. This test simulates two ACGR checks racing for the
# same instance_id by making the mocked API call block (via a
# threading.Event) until both threads have had a chance to reach
# _get_acgr_context, so a broken implementation would very likely
# demonstrate the race; the fixed implementation must not.
# ---------------------------------------------------------------------------


def test_acgr_context_fetch_is_serialized_per_instance():
    import threading
    import time as time_module
    from unittest.mock import Mock

    from amazon_connect_assessment.checks.base import CheckContext
    from amazon_connect_assessment.checks.resilience_advanced_checks import (
        _get_acgr_context,
        _reset_acgr_cache,
    )
    from amazon_connect_assessment.models import ConnectInstance

    _reset_acgr_cache()

    instance = ConnectInstance(
        instance_id="race-instance",
        instance_arn="arn:aws:connect:us-east-1:111:instance/race-instance",
        identity_management_type="SAML",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        status="ACTIVE",
    )

    real_tdgs = [{"Id": "tdg-1", "Name": "Primary TDG"}]

    started_fetch = threading.Event()
    release_fetch = threading.Event()
    fetch_call_count = {"n": 0}

    def slow_list_tdgs(client, op_name, service, **kwargs):
        if op_name == "list_traffic_distribution_groups":
            fetch_call_count["n"] += 1
            started_fetch.set()
            # Simulate a slow API call — block until the test explicitly
            # releases it, giving a second thread time to arrive at
            # _get_acgr_context while the first fetch is still in flight.
            release_fetch.wait(timeout=5)
            return {"TrafficDistributionGroupSummaryList": real_tdgs}
        if op_name == "describe_traffic_distribution_group":
            return {"TrafficDistributionGroup": {"Status": "ACTIVE"}}
        if op_name == "get_traffic_distribution":
            return {}
        return {}

    factory = Mock()
    factory.get_connect_client.return_value = Mock()
    factory.call_api_with_resilience.side_effect = slow_list_tdgs
    factory.is_access_denied = AWSClientFactory.is_access_denied

    results = {}

    def worker(name):
        ctx = CheckContext(instance=instance, aws_client_factory=factory, config={}, logger=None)
        results[name] = _get_acgr_context(ctx)

    t1 = threading.Thread(target=worker, args=("t1",))
    t1.start()

    # Wait until thread 1 has actually entered the slow API call, then
    # start thread 2 — this is the exact window in which the old
    # implementation would have handed thread 2 an empty placeholder.
    assert started_fetch.wait(timeout=5), "thread 1 never reached the API call"

    t2 = threading.Thread(target=worker, args=("t2",))
    t2.start()

    # Give thread 2 a moment to reach _get_acgr_context and block on the
    # per-instance fetch lock (it should NOT proceed to make its own API
    # call while thread 1's fetch is in flight).
    time_module.sleep(0.2)
    assert fetch_call_count["n"] == 1, (
        "a second thread made its own list_traffic_distribution_groups "
        "call instead of waiting for the in-flight fetch — the "
        "per-instance fetch lock did not serialize correctly"
    )

    # Now let the first fetch complete; thread 2 should then get the
    # fully-populated result from the cache rather than fetching again.
    release_fetch.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert not t1.is_alive() and not t2.is_alive()
    assert results["t1"].tdgs == real_tdgs
    assert results["t2"].tdgs == real_tdgs
    assert results["t1"].fetch_complete is True
    assert results["t2"].fetch_complete is True
    # The fetch should have happened exactly once — thread 2 reused the
    # completed context rather than re-fetching.
    assert fetch_call_count["n"] == 1


def test_acgr_context_different_instances_fetch_concurrently():
    """
    The per-instance lock must not serialize *different* instances —
    only concurrent checks against the *same* instance should block on
    each other.
    """
    import threading
    from unittest.mock import Mock

    from amazon_connect_assessment.checks.base import CheckContext
    from amazon_connect_assessment.checks.resilience_advanced_checks import (
        _get_acgr_context,
        _reset_acgr_cache,
    )
    from amazon_connect_assessment.models import ConnectInstance

    _reset_acgr_cache()

    def _instance(iid):
        return ConnectInstance(
            instance_id=iid,
            instance_arn=f"arn:aws:connect:us-east-1:111:instance/{iid}",
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            status="ACTIVE",
        )

    factory = Mock()
    factory.get_connect_client.return_value = Mock()
    factory.call_api_with_resilience.return_value = {"TrafficDistributionGroupSummaryList": []}
    factory.is_access_denied = AWSClientFactory.is_access_denied

    results = {}

    def worker(iid):
        ctx = CheckContext(
            instance=_instance(iid), aws_client_factory=factory, config={}, logger=None
        )
        results[iid] = _get_acgr_context(ctx)

    threads = [threading.Thread(target=worker, args=(f"iid-{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert all(not t.is_alive() for t in threads)
    assert len(results) == 5
    for r in results.values():
        assert r.fetch_complete is True
