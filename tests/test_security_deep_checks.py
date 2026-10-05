"""
Tests for deep-inspection security checks (Task 4 / Requirements 7-12).

Uses the mock AWSClientFactory with the real ``is_access_denied`` static method
wired in so the SKIPPED-on-access-denied paths exercise actual logic.
"""

import json
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.security_deep_checks import (
    ApprovedOriginsCheck,
    CloudTrailIntegrationCheck,
    IAMServiceRolePolicyCheck,
    IdentityFederationCheck,
    InstanceStorageEncryptionCheck,
    SecurityProfileAuditCheck,
    register_security_deep_checks,
)
from amazon_connect_assessment.models import CheckStatus, Severity


def _denied():
    def _raise(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op")

    return _raise


def _wire_real_access_denied(factory):
    # Mock(spec=...) replaces the staticmethod with a Mock; restore the real one.
    factory.is_access_denied = AWSClientFactory.is_access_denied


# --- IAM service role policy (sec-iam-deep-001) ---------------------------


class TestIAMServiceRolePolicyCheck:
    def test_no_service_role_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.service_role = None
        finding = IAMServiceRolePolicyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.structured_remediation is not None

    def test_wildcard_write_on_star_resource_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "least-privilege" in finding.description.lower()

    @pytest.mark.parametrize(
        "action",
        [
            "dynamodb:BatchWriteItem",
            "dynamodb:BatchExecuteStatement",
            "example:BatchCreateThing",
            "example:BatchDeleteThing",
            "example:BatchPutThing",
            "example:BatchStopThing",
            "example:BatchGrantThing",
            "example:BatchRevokeThing",
            "example:BatchAssociateThing",
            "example:BatchDisassociateThing",
        ],
    )
    def test_iam_batch_write_action_on_wildcard_resource_returns_fail(
        self, action, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.list_role_policies_resilient.return_value = {"PolicyNames": ["batch-write"]}
        factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]
            }
        }
        factory.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["least_privilege_violations"][0]["action"] == action

    def test_iam_batch_write_actions_on_scoped_resource_return_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        actions = ["dynamodb:BatchWriteItem", "dynamodb:BatchExecuteStatement"]
        factory.list_role_policies_resilient.return_value = {"PolicyNames": ["scoped-batch"]}
        factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/example",
                    }
                ]
            }
        }
        factory.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["least_privilege_violations"] == []

    @pytest.mark.parametrize(
        "action",
        ["dynamodb:BatchGetItem", "example:BatchDescribeThing", "example:BatchCheckThing"],
    )
    def test_iam_batch_read_action_on_wildcard_resource_returns_pass(
        self, action, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.list_role_policies_resilient.return_value = {"PolicyNames": ["batch-read"]}
        factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]
            }
        }
        factory.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["least_privilege_violations"] == []

    def test_out_of_scope_action_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:CreateUser"],
                        "Resource": "arn:x",
                    }
                ]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "out-of-scope" in finding.description.lower()
        # remediation names the role
        assert finding.structured_remediation.target_resources

    def test_scoped_policy_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["connect:DescribeInstance"],
                        "Resource": "arn:aws:connect:us-east-1:123:instance/abc",
                    }
                ]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_access_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_role_policies_resilient.side_effect = _denied()
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED

    def test_iam_service_role_risky_attached_policy_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        policy_arn = "arn:aws:iam::123456789012:policy/risky-managed"
        condition = {"StringEquals": {"aws:SourceAccount": "123456789012"}}
        factory.list_role_policies_resilient.return_value = {
            "PolicyNames": [],
            "IsTruncated": False,
        }
        factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "risky-managed", "PolicyArn": policy_arn}],
            "IsTruncated": False,
        }
        factory.get_policy_resilient.return_value = {
            "Policy": {"PolicyName": "risky-managed", "DefaultVersionId": "v7"}
        }
        factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": {
                        "Effect": "ALLOW",
                        "Action": "S3:PuTObject",
                        "Resource": "*",
                        "Condition": condition,
                    }
                }
            }
        }

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        violation = finding.evidence["least_privilege_violations"][0]
        assert violation == {
            "policy_source": "attached",
            "policy_name": "risky-managed",
            "policy_arn": policy_arn,
            "policy_version_id": "v7",
            "statement_index": 0,
            "action": "S3:PuTObject",
            "resource": "*",
            "condition": condition,
        }
        assert finding.evidence["inspection_complete"] is True

    def test_iam_service_role_safe_attached_policy_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        policy_arn = "arn:aws:iam::123456789012:policy/safe-managed"
        document = {
            "Statement": {
                "Effect": "Allow",
                "Action": "connect:DescribeInstance",
                "Resource": "arn:aws:connect:us-east-1:123456789012:instance/abc",
            }
        }
        factory.list_role_policies_resilient.return_value = {
            "PolicyNames": [],
            "IsTruncated": False,
        }
        factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "safe-managed", "PolicyArn": policy_arn}],
            "IsTruncated": False,
        }
        factory.get_policy_resilient.return_value = {
            "Policy": {"PolicyName": "safe-managed", "DefaultVersionId": "v2"}
        }
        factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {"Document": quote(json.dumps(document))}
        }

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["inspection_complete"] is True
        assert finding.evidence["evaluated_identity_policies"] == [
            {
                "policy_source": "attached",
                "policy_name": "safe-managed",
                "policy_arn": policy_arn,
                "policy_version_id": "v2",
            }
        ]
        factory.get_policy_version_resilient.assert_called_once_with(policy_arn, "v2")

    def test_iam_service_role_policy_lists_paginate_and_inspect_all_pages_passes(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory

        def _list_inline(role_name, **kwargs):
            if kwargs.get("Marker") == "inline-next":
                return {"PolicyNames": ["inline-page-2"], "IsTruncated": False}
            return {
                "PolicyNames": ["inline-page-1"],
                "IsTruncated": True,
                "Marker": "inline-next",
            }

        def _list_attached(role_name, **kwargs):
            if kwargs.get("Marker") == "attached-next":
                return {
                    "AttachedPolicies": [
                        {
                            "PolicyName": "attached-page-2",
                            "PolicyArn": "arn:aws:iam::123456789012:policy/attached-page-2",
                        }
                    ],
                    "IsTruncated": False,
                }
            return {
                "AttachedPolicies": [
                    {
                        "PolicyName": "attached-page-1",
                        "PolicyArn": "arn:aws:iam::123456789012:policy/attached-page-1",
                    }
                ],
                "IsTruncated": True,
                "Marker": "attached-next",
            }

        safe_document = {
            "Statement": {
                "Effect": "Allow",
                "Action": "connect:DescribeInstance",
                "Resource": "arn:aws:connect:us-east-1:123456789012:instance/abc",
            }
        }
        factory.list_role_policies_resilient.side_effect = _list_inline
        factory.get_role_policy_resilient.return_value = {"PolicyDocument": safe_document}
        factory.list_attached_role_policies_resilient.side_effect = _list_attached
        factory.get_policy_resilient.return_value = {
            "Policy": {"PolicyName": "managed", "DefaultVersionId": "v1"}
        }
        factory.get_policy_version_resilient.return_value = {
            "PolicyVersion": {"Document": safe_document}
        }

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["inline_policy_count"] == 2
        assert finding.evidence["attached_policy_count"] == 2
        assert finding.evidence["evaluated_identity_policy_count"] == 4
        inline_calls = factory.list_role_policies_resilient.call_args_list
        attached_calls = factory.list_attached_role_policies_resilient.call_args_list
        assert [call.kwargs for call in inline_calls] == [{}, {"Marker": "inline-next"}]
        assert [call.kwargs for call in attached_calls] == [
            {},
            {"Marker": "attached-next"},
        ]

    def test_iam_service_role_unread_managed_policy_returns_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        policy_arn = "arn:aws:iam::123456789012:policy/unreadable"
        factory.list_role_policies_resilient.return_value = {
            "PolicyNames": [],
            "IsTruncated": False,
        }
        factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "unreadable", "PolicyArn": policy_arn}],
            "IsTruncated": False,
        }
        factory.get_policy_resilient.side_effect = _denied()

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["inspection_complete"] is False
        failure = finding.evidence["policy_source_failures"][0]
        assert failure["policy_source"] == "attached"
        assert failure["policy_arn"] == policy_arn
        assert failure["operation"] == "iam:GetPolicy"
        assert failure["access_denied"] is True

    def test_iam_service_role_inline_violation_with_unread_attached_source_remains_fail(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        policy_arn = "arn:aws:iam::123456789012:policy/unreadable"
        factory.list_role_policies_resilient.return_value = {
            "PolicyNames": ["known-risk"],
            "IsTruncated": False,
        }
        factory.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "allow",
                    "Action": "IAM:CreateUser",
                    "Resource": "arn:aws:iam::123456789012:user/example",
                }
            }
        }
        factory.list_attached_role_policies_resilient.return_value = {
            "AttachedPolicies": [{"PolicyName": "unreadable", "PolicyArn": policy_arn}],
            "IsTruncated": False,
        }
        factory.get_policy_resilient.side_effect = RuntimeError("managed policy unavailable")

        # Act
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["inspection_complete"] is False
        assert finding.evidence["out_of_scope_actions"][0]["policy_name"] == "known-risk"
        assert finding.evidence["out_of_scope_actions"][0]["action"] == "IAM:CreateUser"
        assert finding.evidence["policy_source_failures"][0]["policy_arn"] == policy_arn
        assert any("incomplete" in item.lower() for item in finding.evidence["limitations"])
        assert "incomplete" in finding.description.lower()


# --- Storage encryption (sec-storage-001) ---------------------------------


class TestInstanceStorageEncryptionCheck:
    def test_missing_storage_encryption_fails_expected_result(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)

        def _configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {"StorageConfigs": [{"StorageType": "S3", "S3Config": {"BucketName": "b"}}]}
            return {"StorageConfigs": []}

        mock_aws_client_factory.list_instance_storage_configs_resilient.side_effect = _configs

        # Act
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert "unencrypted" in finding.description.lower()

    def test_customer_managed_key_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory

        def _configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {
                                "BucketName": "b",
                                "EncryptionConfig": {"KeyId": "arn:aws:kms:...:key/abc"},
                            },
                        }
                    ]
                }
            return {"StorageConfigs": []}

        f.list_instance_storage_configs_resilient.side_effect = _configs
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_aws_managed_storage_encryption_passes_expected_result(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)

        def _configs(instance_id, resource_type):
            if resource_type == "CHAT_TRANSCRIPTS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {
                                "BucketName": "b",
                                "EncryptionConfig": {"KeyId": "alias/aws/connect"},
                            },
                        }
                    ]
                }
            return {"StorageConfigs": []}

        mock_aws_client_factory.list_instance_storage_configs_resilient.side_effect = _configs

        # Act
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["customer_managed_key_not_configured"] == ["CHAT_TRANSCRIPTS"]
        assert "organizational policy" in finding.description.lower()

    def test_partial_storage_read_is_skipped_expected_result(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)

        def _configs(instance_id, resource_type):
            if resource_type == "CHAT_TRANSCRIPTS":
                raise RuntimeError("transient read failure")
            return {"StorageConfigs": []}

        mock_aws_client_factory.list_instance_storage_configs_resilient.side_effect = _configs

        # Act
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["analysis_complete"] is False
        assert finding.evidence["resource_types_failed"][0]["resource_type"] == "CHAT_TRANSCRIPTS"

    @pytest.mark.parametrize("error_code", ["InvalidRequestException", "ResourceNotFoundException"])
    def test_storage_uncertain_api_error_returns_skipped_with_error_code(
        self, error_code, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory

        def _configs(instance_id, resource_type):
            if resource_type == "CHAT_TRANSCRIPTS":
                raise ClientError(
                    {"Error": {"Code": error_code, "Message": "uncertain"}},
                    "ListInstanceStorageConfigs",
                )
            return {"StorageConfigs": []}

        factory.list_instance_storage_configs_resilient.side_effect = _configs

        # Act
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        failure = finding.evidence["resource_types_failed"][0]
        assert failure["resource_type"] == "CHAT_TRANSCRIPTS"
        assert failure["error_code"] == error_code
        assert finding.evidence["analysis_complete"] is False

    def test_missing_encryption_with_partial_evidence_stays_fail_expected_result(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)

        def _configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {"StorageConfigs": [{"StorageType": "S3", "S3Config": {"BucketName": "b"}}]}
            if resource_type == "CHAT_TRANSCRIPTS":
                raise RuntimeError("transient read failure")
            return {"StorageConfigs": []}

        mock_aws_client_factory.list_instance_storage_configs_resilient.side_effect = _configs

        # Act
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["analysis_complete"] is False
        assert finding.evidence["limitations"]
        assert "incomplete" in finding.description.lower()


# --- Approved origins (sec-origins-001) -----------------------------------


class TestApprovedOriginsCheck:
    def test_wildcard_origin_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {
            "Origins": ["https://app.example.com", "http://*"]
        }
        finding = ApprovedOriginsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_no_origins_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {"Origins": []}

        # Act
        finding = ApprovedOriginsCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "Contact Control Panel" in finding.description
        assert "safe default" in finding.description
        assert finding.structured_remediation is not None
        assert finding.structured_remediation.applies_if == (
            "the CCP is embedded in a custom agent application."
        )

    def test_specific_origins_pass(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {
            "Origins": ["https://app.example.com"]
        }
        finding = ApprovedOriginsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# --- CloudTrail (sec-cloudtrail-001) --------------------------------------


def _basic_selector(include_management=True, read_write_type="All"):
    return {
        "EventSelectors": [
            {
                "IncludeManagementEvents": include_management,
                "ReadWriteType": read_write_type,
            }
        ]
    }


def _advanced_selector(event_source=None):
    field_selectors = [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "readOnly", "Equals": ["false"]},
    ]
    if event_source:
        field_selectors.append({"Field": "eventSource", "Equals": [event_source]})
    return {
        "AdvancedEventSelectors": [{"Name": "management-writes", "FieldSelectors": field_selectors}]
    }


class TestCloudTrailIntegrationCheck:
    def test_cloudtrail_no_trail_fail(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.describe_trails_resilient.return_value = {"trailList": []}

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["trail_count"] == 0

    def test_cloudtrail_stopped_trail_fail(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "stopped"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": False}
        factory.get_trail_event_selectors_resilient.return_value = _basic_selector()

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["trail_details"][0]["is_logging"] is False
        factory.get_trail_event_selectors_resilient.assert_called_once_with("stopped")

    def test_cloudtrail_basic_selector_management_disabled_fail(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = _basic_selector(False)

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        reasoning = finding.evidence["trail_details"][0]["selector_reasoning"][0]
        assert reasoning["qualifies"] is False
        assert "disables management" in reasoning["reason"]

    @pytest.mark.parametrize("read_write_type", ["WriteOnly", "All"])
    def test_cloudtrail_basic_selector_write_coverage_pass(
        self, read_write_type, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = _basic_selector(
            read_write_type=read_write_type
        )

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["qualifying_trails"] == ["audit"]

    def test_cloudtrail_advanced_management_without_source_restriction_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = _advanced_selector()

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert (
            finding.evidence["trail_details"][0]["selector_covers_connect_management_writes"]
            is True
        )

    def test_cloudtrail_advanced_explicit_unrelated_source_fail(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = _advanced_selector(
            "s3.amazonaws.com"
        )

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert "eventSource" in str(finding.evidence["trail_details"][0]["selector_reasoning"])

    def test_cloudtrail_advanced_unsupported_field_returns_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        selectors = _advanced_selector()
        selectors["AdvancedEventSelectors"][0]["FieldSelectors"].append(
            {"Field": "resources.type", "Equals": ["AWS::Connect::Instance"]}
        )
        factory.get_trail_event_selectors_resilient.return_value = selectors

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["selector_analysis_complete"] is False
        assert finding.evidence["indeterminate_selector_trails"] == ["audit"]
        reasoning = finding.evidence["trail_details"][0]["selector_reasoning"][0]
        assert reasoning["qualifies"] is None

    def test_cloudtrail_advanced_malformed_selector_returns_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = {
            "AdvancedEventSelectors": [
                {"Name": "malformed", "FieldSelectors": {"Field": "eventCategory"}}
            ]
        }

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["selector_analysis_complete"] is False
        reasoning = finding.evidence["trail_details"][0]["selector_reasoning"][0]
        assert reasoning["qualifies"] is None
        assert "not a list" in reasoning["reason"]

    def test_cloudtrail_known_coverage_with_unknown_selector_returns_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {
            "trailList": [{"Name": "verified"}, {"Name": "unknown"}]
        }
        factory.get_trail_status_resilient.side_effect = [
            {"IsLogging": True},
            {"IsLogging": True},
        ]
        unknown_selector = _advanced_selector()
        unknown_selector["AdvancedEventSelectors"][0]["FieldSelectors"][0][
            "UnsupportedOperator"
        ] = ["Management"]
        factory.get_trail_event_selectors_resilient.side_effect = [
            _basic_selector(read_write_type="WriteOnly"),
            unknown_selector,
        ]

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["qualifying_trails"] == ["verified"]
        assert finding.evidence["inspection_complete"] is False
        assert finding.evidence["indeterminate_selector_trails"] == ["unknown"]
        assert "could not be fully inspected" in finding.description

    def test_cloudtrail_advanced_connect_source_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.return_value = {"IsLogging": True}
        factory.get_trail_event_selectors_resilient.return_value = _advanced_selector(
            "connect.amazonaws.com"
        )

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["inspection_complete"] is True

    def test_cloudtrail_detail_access_denial_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {"trailList": [{"Name": "audit"}]}
        factory.get_trail_status_resilient.side_effect = _denied()
        factory.get_trail_event_selectors_resilient.return_value = _basic_selector()

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["inspection_complete"] is False
        assert finding.evidence["detail_failures"][0]["access_denied"] is True
        factory.get_trail_event_selectors_resilient.assert_called_once_with("audit")

    def test_cloudtrail_mixed_trails_without_coverage_fail(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {
            "trailList": [{"Name": "stopped"}, {"Name": "read-only"}]
        }
        factory.get_trail_status_resilient.side_effect = [
            {"IsLogging": False},
            {"IsLogging": True},
        ]
        factory.get_trail_event_selectors_resilient.side_effect = [
            _basic_selector(),
            _basic_selector(read_write_type="ReadOnly"),
        ]

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert len(finding.evidence["trail_details"]) == 2
        assert factory.get_trail_status_resilient.call_count == 2
        assert factory.get_trail_event_selectors_resilient.call_count == 2

    def test_cloudtrail_known_qualifying_coverage_with_other_denial_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        factory = mock_aws_client_factory
        factory.describe_trails_resilient.return_value = {
            "trailList": [{"Name": "verified"}, {"Name": "unreadable"}]
        }
        factory.get_trail_status_resilient.side_effect = [
            {"IsLogging": True},
            _denied(),
        ]
        factory.get_trail_event_selectors_resilient.side_effect = [
            _basic_selector(read_write_type="WriteOnly"),
            _denied(),
        ]

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["qualifying_trails"] == ["verified"]
        assert finding.evidence["inspection_complete"] is False
        assert "could not be fully inspected" in finding.description

    def test_cloudtrail_describe_access_denied_skipped(
        self, make_check_context, mock_aws_client_factory
    ):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.describe_trails_resilient.side_effect = _denied()

        # Act
        finding = CloudTrailIntegrationCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.SKIPPED


# --- Federation (sec-federation-001) --------------------------------------


class TestIdentityFederationCheck:
    def test_saml_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.identity_management_type = "SAML"
        finding = IdentityFederationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS

    def test_non_saml_identity_inventory_passes_expected_result(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        sample_connect_instance.identity_management_type = "CONNECT_MANAGED"

        # Act
        finding = IdentityFederationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.structured_remediation is None
        assert "verify" in finding.description.lower()
        assert "migrate" not in finding.description.lower()

    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: SAML is one good option, not the only
        # one -- Connect-managed identity paired with a third-party IdP
        # (Okta, Entra ID) for MFA is also viable. Downgraded from MEDIUM.
        assert IdentityFederationCheck().severity == Severity.LOW


# --- Security profile audit (sec-profile-audit-001) -----------------------


class TestSecurityProfileAuditCheck:
    def test_overprivileged_profile_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Agent"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Users.Create", "Users.Edit"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "Agent" in str(finding.structured_remediation.target_resources)

    def test_admin_profile_allowed(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Admin"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Users.Create", "SecurityProfiles.Edit"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_agent_profile_without_admin_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Agent"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Contacts.View", "Dashboards.View"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# --- Registration ----------------------------------------------------------


def test_register_security_deep_checks_registers_six():
    registry = CheckRegistry()
    register_security_deep_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "sec-iam-deep-001",
        "sec-storage-001",
        "sec-origins-001",
        "sec-cloudtrail-001",
        "sec-federation-001",
        "sec-profile-audit-001",
    } <= ids
