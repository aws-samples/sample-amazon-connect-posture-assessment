"""
--instance-id validation: malformed IDs are rejected at argument parsing, and
an ID that does not exist in the target region fails validation before any
checks run (instead of producing an empty "successful" report).
"""

import argparse
from unittest.mock import Mock

import pytest

from amazon_connect_assessment.aws_client_factory import (
    AWSClientFactory,
    CredentialSource,
    CredentialValidationResult,
    PermissionValidationResult,
)
from amazon_connect_assessment.cli import create_argument_parser, instance_id_arg
from amazon_connect_assessment.engine import AssessmentEngine

TARGET = "11111111-2222-3333-4444-555555555555"
OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _factory(summaries, credentials_valid=True):
    f = Mock(spec=AWSClientFactory)
    f.region = "us-west-2"
    f.validate_credentials.return_value = CredentialValidationResult(
        is_valid=credentials_valid,
        credential_source=CredentialSource.ENVIRONMENT_VARIABLES,
        account_id="123456789012",
    )
    f.validate_permissions.return_value = PermissionValidationResult(
        is_valid=True, missing_permissions=[], tested_permissions=["connect:ListInstances"]
    )
    f.list_connect_instances_resilient.return_value = {"InstanceSummaryList": summaries}
    return f


def _engine(factory, instance_id=TARGET):
    return AssessmentEngine(factory, config={"aws": {"instance_id": instance_id}})


class TestValidateConfiguration:
    def test_existing_instance_is_valid(self):
        engine = _engine(_factory([{"Id": TARGET, "InstanceAlias": "prod"}]))

        result = engine.validate_configuration()

        assert result["is_valid"] is True
        assert result["errors"] == []

    def test_missing_instance_fails_and_lists_available_instances(self):
        engine = _engine(_factory([{"Id": OTHER, "InstanceAlias": "sandbox"}]))

        result = engine.validate_configuration()

        assert result["is_valid"] is False
        (error,) = result["errors"]
        assert f"{TARGET} not found in us-west-2" in error
        assert f"{OTHER} ('sandbox')" in error

    def test_missing_instance_in_empty_region_points_at_region(self):
        engine = _engine(_factory([]))

        result = engine.validate_configuration()

        assert result["is_valid"] is False
        assert "no Connect instances" in result["errors"][0]
        assert "--region" in result["errors"][0]

    def test_paginates_to_find_instance(self):
        factory = _factory([])
        factory.list_connect_instances_resilient.side_effect = [
            {"InstanceSummaryList": [{"Id": OTHER}], "NextToken": "t"},
            {"InstanceSummaryList": [{"Id": TARGET}]},
        ]

        result = _engine(factory).validate_configuration()

        assert result["is_valid"] is True

    def test_list_failure_warns_instead_of_failing(self):
        factory = _factory([])
        factory.list_connect_instances_resilient.side_effect = RuntimeError("AccessDenied")

        result = _engine(factory).validate_configuration()

        assert result["is_valid"] is True
        assert any("Could not verify instance" in w for w in result["warnings"])

    def test_skipped_when_credentials_invalid(self):
        factory = _factory([], credentials_valid=False)

        _engine(factory).validate_configuration()

        factory.list_connect_instances_resilient.assert_not_called()

    def test_no_instance_id_does_not_list_instances(self):
        factory = _factory([])

        AssessmentEngine(factory, config={}).validate_configuration()

        factory.list_connect_instances_resilient.assert_not_called()


class TestDiscoveryNotFound:
    def test_missing_instance_is_recorded_as_execution_error(self):
        engine = _engine(_factory([{"Id": OTHER}]))

        assert engine.discover_instances() == []
        assert any(TARGET in e for e in engine.get_execution_errors())


class TestInstanceIdArgument:
    def test_accepts_uuid_and_normalizes_case_and_whitespace(self):
        assert instance_id_arg(f"  {TARGET.upper()} ") == TARGET

    @pytest.mark.parametrize(
        "value",
        [
            "prod-instance",
            f"arn:aws:connect:us-east-1:123456789012:instance/{TARGET}",
            TARGET[:-1],
            "",
        ],
    )
    def test_rejects_non_uuid(self, value):
        with pytest.raises(argparse.ArgumentTypeError):
            instance_id_arg(value)

    def test_parser_rejects_malformed_instance_id(self, capsys):
        with pytest.raises(SystemExit) as exc:
            create_argument_parser().parse_args(["--instance-id", "my-alias"])

        assert exc.value.code == 2
        assert "not a Connect instance ID" in capsys.readouterr().err
