"""Regression tests for IAM wildcard, storage, ACGR, profile audit and enumerator hardening."""

import json

import pytest
from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.ai_agent_security_checks import _risky_actions
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.resilience_advanced_checks import (
    ACGRConfigurationCheck,
    ACGRIdentityManagementCheck,
    ACGRPhoneNumberBindingCheck,
    ACGRTrafficDistributionGroupStatusCheck,
    _reset_acgr_cache,
)
from amazon_connect_assessment.checks.security_deep_checks import (
    IAMServiceRolePolicyCheck,
    InstanceStorageEncryptionCheck,
    SecurityProfileAuditCheck,
)
from amazon_connect_assessment.journey.models import (
    JourneyNode,
    PhoneNumberEntry,
    SuperGraph,
)
from amazon_connect_assessment.journey.path_enumerator import (
    _enumerate_from_entry,
    enumerate_journeys_with_completeness,
)
from amazon_connect_assessment.models import CheckStatus


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _doc(*actions, resource="*"):
    return {"Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": resource}]}


# --- ExcessiveAgency / IAM action analysis --------------------------------


@pytest.mark.parametrize(
    "action", ["s3:*", "kms:*", "sqs:*", "sns:*", "dynamodb:*", "iam:PassRole", "*"]
)
def test_excessive_agency_service_wildcard_is_flagged(action):
    # Arrange
    policy = _doc(action)

    # Act
    risky = _risky_actions(policy)

    # Assert
    assert risky == [action]


@pytest.mark.parametrize("action", ["iam:Get*", "iam:List*", "iam:GetRole", "logs:PutLogEvents"])
def test_excessive_agency_read_only_iam_action_is_ignored(action):
    # Arrange
    policy = _doc(action)

    # Act
    risky = _risky_actions(policy)

    # Assert
    assert risky == []


def test_iam_policy_read_only_and_substring_actions_are_not_broad():
    # Arrange
    read_only = _doc(
        "ec2:Describe*", "s3:Get*", "s3:List*", "compute-optimizer:GetX", "logs:Output*"
    )
    write_actions = _doc("s3:*", "s3:PutObject")

    # Act
    read_only_broad, _ = IAMServiceRolePolicyCheck._analyze_document(read_only, {})
    write_broad, _ = IAMServiceRolePolicyCheck._analyze_document(write_actions, {})

    # Assert
    assert read_only_broad == []
    assert {entry["action"] for entry in write_broad} == {"s3:*", "s3:PutObject"}


# --- Storage encryption -----------------------------------------------------


def test_storage_encryption_stream_configs_are_not_unencrypted():
    # Arrange
    classify = InstanceStorageEncryptionCheck._kms_type
    kinesis_stream = {"KinesisStreamConfig": {"StreamArn": "a"}}
    firehose_stream = {"KinesisFirehoseConfig": {"FirehoseArn": "a"}}
    unencrypted_s3 = {"S3Config": {"BucketName": "b"}}

    # Act
    stream_result = classify(kinesis_stream)
    firehose_result = classify(firehose_stream)
    s3_result = classify(unencrypted_s3)

    # Assert
    assert stream_result == "stream_managed"
    assert firehose_result == "stream_managed"
    assert s3_result == "none"


def test_storage_encryption_paginated_configs_are_deduplicated_with_complete_evidence(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)
    encrypted = {"BucketName": "b", "EncryptionConfig": {"KeyId": "arn:aws:kms:::key/k"}}

    def _configs(instance_id, resource_type, **kwargs):
        if resource_type != "CALL_RECORDINGS":
            return {"StorageConfigs": []}
        if not kwargs:
            return {
                "StorageConfigs": [{"StorageType": "S3", "S3Config": {"BucketName": "x"}}],
                "NextToken": "t1",
            }
        assert kwargs == {"NextToken": "t1"}
        return {
            "StorageConfigs": [
                {"StorageType": "S3", "S3Config": {"BucketName": "y"}},
                {"StorageType": "S3", "S3Config": encrypted},
                {"StorageType": "KINESIS_STREAM", "KinesisStreamConfig": {"StreamArn": "a"}},
            ]
        }

    factory.list_instance_storage_configs_resilient.side_effect = _configs

    # Act
    finding = InstanceStorageEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.FAIL
    assert finding.evidence["unencrypted_resource_types"] == ["CALL_RECORDINGS"]
    assert len(finding.evidence["storage"]["CALL_RECORDINGS"]) == 4


def test_storage_encryption_stream_only_config_is_unevaluated(
    make_check_context, mock_aws_client_factory
):
    # A stream ARN does not establish encryption of the stream destination.
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)
    factory.list_instance_storage_configs_resilient.side_effect = lambda i, rt, **k: {
        "StorageConfigs": (
            [{"StorageType": "KINESIS_FIREHOSE", "KinesisFirehoseConfig": {"FirehoseArn": "a"}}]
            if rt == "AGENT_EVENTS"
            else []
        )
    }

    # Act
    finding = InstanceStorageEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["analysis_complete"] is False
    assert finding.evidence["unencrypted_resource_types"] == []
    assert finding.evidence["stream_managed_encryption_resource_types"] == ["AGENT_EVENTS"]
    assert "Kinesis" in finding.description
    stream_evidence = finding.evidence["storage"]["AGENT_EVENTS"][0]
    assert stream_evidence["stream_resource_arn"] == "a"
    assert stream_evidence["encryption_evaluated"] is False
    assert stream_evidence["encrypted"] is None


def test_storage_encryption_kinesis_delivery_prevents_clean_pass(
    make_check_context, mock_aws_client_factory
):
    # Encrypted recordings do not prove that other stream destinations are encrypted.
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)
    encrypted_s3 = {
        "StorageType": "S3",
        "S3Config": {
            "BucketName": "b",
            "EncryptionConfig": {"KeyId": "arn:aws:kms:us-east-1:111122223333:key/k"},
        },
    }
    stream = {"StorageType": "KINESIS_STREAM", "KinesisStreamConfig": {"StreamArn": "a"}}

    def _configs(instance_id, resource_type, **kwargs):
        if resource_type == "CALL_RECORDINGS":
            return {"StorageConfigs": [encrypted_s3]}
        if resource_type in ("CONTACT_TRACE_RECORDS", "AGENT_EVENTS"):
            return {"StorageConfigs": [stream]}
        return {"StorageConfigs": []}

    factory.list_instance_storage_configs_resilient.side_effect = _configs

    # Act
    finding = InstanceStorageEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["analysis_complete"] is False
    assert finding.evidence["evaluated_resource_types"] == ["CALL_RECORDINGS"]
    assert sorted(finding.evidence["stream_managed_encryption_resource_types"]) == [
        "AGENT_EVENTS",
        "CONTACT_TRACE_RECORDS",
    ]


def test_storage_encryption_partial_read_prevents_clean_pass(
    make_check_context, mock_aws_client_factory
):
    # Successfully evaluated types do not establish the missing type's encryption.
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)
    encrypted_s3 = {
        "StorageType": "S3",
        "S3Config": {
            "BucketName": "b",
            "EncryptionConfig": {"KeyId": "arn:aws:kms:us-east-1:111122223333:key/k"},
        },
    }

    def _configs(instance_id, resource_type, **kwargs):
        if resource_type == "CHAT_TRANSCRIPTS":
            raise RuntimeError("transient read failure")
        if resource_type == "CALL_RECORDINGS":
            return {"StorageConfigs": [encrypted_s3]}
        return {"StorageConfigs": []}

    factory.list_instance_storage_configs_resilient.side_effect = _configs

    # Act
    finding = InstanceStorageEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["analysis_complete"] is False
    assert finding.evidence["resource_types_failed"][0]["resource_type"] == "CHAT_TRANSCRIPTS"
    assert "did not complete" in finding.description


def test_storage_encryption_no_configurations_is_not_applicable(
    make_check_context, mock_aws_client_factory
):
    factory = mock_aws_client_factory
    _wire(factory)
    factory.list_instance_storage_configs_resilient.return_value = {"StorageConfigs": []}

    finding = InstanceStorageEncryptionCheck().execute(make_check_context())

    assert finding.status == CheckStatus.NOT_APPLICABLE
    assert finding.evidence["analysis_complete"] is True
    assert finding.evidence["evaluated_resource_types"] == []


# --- ACGR -------------------------------------------------------------------


def _program(factory, *, list_error=False, pages=None, describe_error=False, tdgs=None):
    _reset_acgr_cache()
    pages = pages or {None: {"TrafficDistributionGroupSummaryList": tdgs or []}}

    def _side_effect(client, op, service, **kwargs):
        if op == "list_traffic_distribution_groups":
            if list_error:
                raise ClientError({"Error": {"Code": "InternalFailure", "Message": "x"}}, op)
            return pages[kwargs.get("NextToken")]
        if op == "describe_traffic_distribution_group" and describe_error:
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "x"}}, op)
        return {}

    factory.call_api_with_resilience.side_effect = _side_effect


@pytest.mark.parametrize(
    "check_cls",
    [
        ACGRConfigurationCheck,
        ACGRIdentityManagementCheck,
        ACGRTrafficDistributionGroupStatusCheck,
        ACGRPhoneNumberBindingCheck,
    ],
)
def test_acgr_tdg_listing_error_returns_skipped(
    check_cls, make_check_context, mock_aws_client_factory
):
    # Arrange
    _wire(mock_aws_client_factory)
    _program(mock_aws_client_factory, list_error=True)

    # Act
    finding = check_cls().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED


def test_acgr_tdg_paginated_listing_counts_all_groups(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory)
    _program(
        mock_aws_client_factory,
        pages={
            None: {"TrafficDistributionGroupSummaryList": [{"Id": "a"}], "NextToken": "n"},
            "n": {"TrafficDistributionGroupSummaryList": [{"Id": "b"}]},
        },
    )

    # Act
    finding = ACGRConfigurationCheck().execute(make_check_context())

    # Assert
    assert finding.evidence["traffic_distribution_groups"] == 2


def test_acgr_tdg_description_error_returns_skipped_not_failed(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    _wire(mock_aws_client_factory)
    _program(mock_aws_client_factory, describe_error=True, tdgs=[{"Id": "a", "Name": "a"}])

    # Act
    finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED


def test_acgr_identity_missing_type_returns_skipped(
    make_check_context, mock_aws_client_factory, sample_connect_instance
):
    # Arrange
    _wire(mock_aws_client_factory)
    _program(mock_aws_client_factory, tdgs=[{"Id": "a", "Name": "a"}])
    sample_connect_instance.identity_management_type = None

    # Act
    finding = ACGRIdentityManagementCheck().execute(
        make_check_context(instance=sample_connect_instance)
    )

    # Assert
    assert finding.status == CheckStatus.SKIPPED


# --- Security profile audit -------------------------------------------------


def test_security_profile_audit_paginated_read_failure_returns_skipped(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)

    def _profiles(instance_id, **kw):
        if not kw:
            return {"SecurityProfileSummaryList": [{"Id": "p1", "Name": "A"}], "NextToken": "n"}
        return {"SecurityProfileSummaryList": [{"Id": "p2", "Name": "B"}]}

    def _perms(instance_id, pid, **kw):
        if pid == "p2":
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "s"}}, "Op")
        return {"Permissions": ["Contacts.View"]}

    factory.list_security_profiles_resilient.side_effect = _profiles
    factory.list_security_profile_permissions_resilient.side_effect = _perms

    # Act
    finding = SecurityProfileAuditCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["profile_count"] == 2
    failure = finding.evidence["source_failures"][0]
    assert failure["error_code"] == "ThrottlingException"
    assert "error" not in failure


def test_security_profile_paginated_permissions_detect_admin_grant(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    factory = mock_aws_client_factory
    _wire(factory)
    factory.list_security_profiles_resilient.return_value = {
        "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Agent"}]
    }
    factory.list_security_profile_permissions_resilient.side_effect = lambda i, pid, **kw: (
        {"Permissions": ["Contacts.View"], "NextToken": "n"}
        if not kw
        else {"Permissions": ["Users.Create"]}
    )

    # Act
    finding = SecurityProfileAuditCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.FAIL


# --- Evidence hygiene --------------------------------------------------------


def test_evidence_source_failure_omits_sensitive_error_message():
    # Arrange
    error = ClientError({"Error": {"Code": "Boom", "Message": "secret detail"}}, "Op")

    class _Factory:
        pass

    _Factory.is_access_denied = staticmethod(AWSClientFactory.is_access_denied)

    # Act
    output = IAMServiceRolePolicyCheck._source_failure(
        factory=_Factory, source="inline", operation="op", error=error
    )

    # Assert
    assert output["error_code"] == "Boom"
    assert "secret detail" not in json.dumps(output)


# --- Registration -----------------------------------------------------------


def test_registration_unknown_check_ids_raise_typed_error_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act / Assert
    with pytest.raises(ValueError, match="Unknown check ID"):
        register_all_checks(registry, check_ids={"does-not-exist"})


# --- Path enumerator --------------------------------------------------------


def test_journey_enumerator_loop_evidence_preserves_complete_result_expected_result():
    # Arrange
    def node(aid, typ):
        return JourneyNode(
            flow_id="f", flow_name="flow-f", action_id=aid, action_type=typ, parameters={}
        )

    graph = SuperGraph()
    for aid, typ in [("a", "Wait"), ("b", "Wait"), ("c", "DisconnectParticipant")]:
        graph.nodes[f"f::{aid}"] = node(aid, typ)
    graph.adjacency = {"f::a": ["f::b"], "f::b": ["f::a", "f::c"]}
    graph.entry_points = {"f": "f::a"}
    entry = PhoneNumberEntry(
        phone_number="+1", number_type="DID", country_code="US", contact_flow_id="f"
    )

    # Act
    paths, complete, limitations = enumerate_journeys_with_completeness(graph, [entry])
    _, step_limitations = _enumerate_from_entry(graph, "f::a", "+1", "DID", 200, 50, max_steps=1)

    # Assert
    assert paths and complete
    assert any("loop-back" in item for item in limitations)
    assert any("step limit" in item for item in step_limitations)
