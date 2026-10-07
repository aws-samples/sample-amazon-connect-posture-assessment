"""Tests for AI and agentic security checks."""

from unittest.mock import call
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.ai_agent_security_checks import (
    ExcessiveAgencyCheck,
    register_ai_agent_security_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:aws:connect:us-east-1:123456789012:instance/i/flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


def _arrange_lambda_role(instance, factory, role_name="TestRole"):
    flow = build_contact_flow(
        [
            build_action(
                "a1",
                "InvokeLambdaFunction",
                {"FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:handler"},
            )
        ]
    )
    _instance_with_flow(instance, flow)
    _wire(factory)
    factory.get_lambda_function_resilient.return_value = {
        "Configuration": {"Role": f"arn:aws:iam::123456789012:role/{role_name}"}
    }
    factory.list_role_policies_resilient.return_value = {"PolicyNames": []}
    factory.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}


def _policy_document(action):
    return {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": action, "Resource": "*"},
    }


class TestExcessiveAgencyCheck:
    def test_excessive_agency_inline_risky_policy_fail(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "InlineRole")
        mock_aws_client_factory.list_role_policies_resilient.return_value = {
            "PolicyNames": ["risky-inline"]
        }
        mock_aws_client_factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": _policy_document(["s3:PutObject", "iam:CreateUser"])
        }

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["inspection_complete"] is True
        assert {item["policy_source"] for item in finding.evidence["excessive_permissions"]} == {
            "inline"
        }

    def test_excessive_agency_attached_risky_policy_fail(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "AttachedRole")
        policy_arn = "arn:aws:iam::123456789012:policy/risky-managed"
        mock_aws_client_factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "risky-managed", "PolicyArn": policy_arn}]
        }
        mock_aws_client_factory.get_policy_resilient.return_value = {
            "Policy": {"DefaultVersionId": "v3"}
        }
        mock_aws_client_factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {"Document": _policy_document("secretsmanager:GetSecretValue")}
        }

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.FAIL
        risky = finding.evidence["excessive_permissions"][0]
        assert risky["policy_source"] == "attached"
        assert risky["policy_arn"] == policy_arn
        assert risky["default_version_id"] == "v3"

    def test_excessive_agency_safe_attached_policy_pass(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "SafeRole")
        policy_arn = "arn:aws:iam::123456789012:policy/safe-managed"
        mock_aws_client_factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "safe-managed", "PolicyArn": policy_arn}]
        }
        mock_aws_client_factory.get_policy_resilient.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        encoded = quote(str(_policy_document("connect:DescribeInstance")).replace("'", '"'))
        mock_aws_client_factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {"Document": encoded}
        }

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["inspection_complete"] is True
        assert finding.evidence["evaluated_identity_policies"][0]["policy_source"] == "attached"

    def test_excessive_agency_policy_pagination_inspects_all_pages_fail(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "PagedRole")
        mock_aws_client_factory.list_role_policies_resilient.side_effect = [
            {"PolicyNames": ["safe-inline"], "IsTruncated": True, "Marker": "inline-2"},
            {"PolicyNames": ["risky-inline"], "IsTruncated": False},
        ]
        mock_aws_client_factory.get_role_policy_resilient.side_effect = lambda _, name: {
            "PolicyDocument": _policy_document(
                "s3:DeleteObject" if name == "risky-inline" else "connect:DescribeInstance"
            )
        }
        attached_arns = [
            "arn:aws:iam::123456789012:policy/safe-1",
            "arn:aws:iam::123456789012:policy/safe-2",
        ]
        mock_aws_client_factory.list_attached_role_policies_resilient.side_effect = [
            {
                "AttachedPolicies": [{"PolicyName": "safe-1", "PolicyArn": attached_arns[0]}],
                "IsTruncated": True,
                "Marker": "attached-2",
            },
            {
                "AttachedPolicies": [{"PolicyName": "safe-2", "PolicyArn": attached_arns[1]}],
                "IsTruncated": False,
            },
        ]
        mock_aws_client_factory.get_policy_resilient.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_aws_client_factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {"Document": _policy_document("connect:DescribeInstance")}
        }

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["inspection_complete"] is True
        assert mock_aws_client_factory.list_role_policies_resilient.call_args_list == [
            call("PagedRole"),
            call("PagedRole", Marker="inline-2"),
        ]
        assert mock_aws_client_factory.list_attached_role_policies_resilient.call_args_list == [
            call("PagedRole"),
            call("PagedRole", Marker="attached-2"),
        ]
        assert len(finding.evidence["evaluated_identity_policies"]) == 4

    @pytest.mark.parametrize("error_code", ["AccessDenied", "InternalError"])
    def test_excessive_agency_attached_policy_detail_error_skipped(
        self,
        error_code,
        make_check_context,
        sample_connect_instance,
        mock_aws_client_factory,
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "UnreadableRole")
        policy_arn = "arn:aws:iam::123456789012:policy/unreadable"
        mock_aws_client_factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "unreadable", "PolicyArn": policy_arn}]
        }
        mock_aws_client_factory.get_policy_resilient.side_effect = ClientError(
            {"Error": {"Code": error_code, "Message": "policy unavailable"}}, "GetPolicy"
        )

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["inspection_complete"] is False
        assert finding.evidence["policy_source_failures"][0]["policy_source"] == "attached"
        assert finding.evidence["policy_source_failures"][0]["operation"] == "iam:GetPolicy"

    def test_excessive_agency_known_risk_with_detail_failure_fail(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory, "PartialRole")
        mock_aws_client_factory.list_role_policies_resilient.return_value = {
            "PolicyNames": ["known-risk"]
        }
        mock_aws_client_factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": _policy_document("iam:CreateRole")
        }
        policy_arn = "arn:aws:iam::123456789012:policy/unreadable"
        mock_aws_client_factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "unreadable", "PolicyArn": policy_arn}]
        }
        mock_aws_client_factory.get_policy_resilient.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetPolicy"
        )

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["inspection_complete"] is False
        assert finding.evidence["excessive_permissions"][0]["policy_name"] == "known-risk"
        assert "Permission boundaries are not inspected." in finding.evidence["limitations"]

    def test_excessive_agency_lambda_access_denied_skipped(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _arrange_lambda_role(sample_connect_instance, mock_aws_client_factory)
        mock_aws_client_factory.get_lambda_function_resilient.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetFunction"
        )

        # Act
        finding = ExcessiveAgencyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["policy_source_failures"][0]["operation"] == "lambda:GetFunction"


def test_ai_agent_security_registration_contains_excessive_agency():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_ai_agent_security_checks(registry)
    ids = {check.check_id for check in registry.get_all_checks()}

    # Assert
    assert "sec-excessive-agency-001" in ids
