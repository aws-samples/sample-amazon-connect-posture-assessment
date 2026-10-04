"""Regression tests for the Amazon Lex conversation-log security check."""

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.lex_security_checks import (
    LexConversationLogEncryptionCheck,
    register_lex_security_checks,
)
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import CheckStatus, Severity

_ALIAS_ARN = "arn:aws:lex:us-east-1:123456789012:bot-alias/BOTID12345/TSTALIASID"
_ALIAS_ARN_EU = "arn:aws:lex:eu-west-2:123456789012:bot-alias/BOTID67890/PRODALIAS1"


def _wire(factory, *, v2_bots=None, v1_bots=None):
    """Point list_bots_resilient at per-version canned pages."""
    factory.is_access_denied = AWSClientFactory.is_access_denied
    pages = {"V2": v2_bots or [], "V1": v1_bots or []}

    def _list_bots(instance_id, lex_version, **kwargs):
        return {"LexBots": pages[lex_version]}

    factory.list_bots_resilient.side_effect = _list_bots


def _v2_bot(alias_arn: str = _ALIAS_ARN):
    return {"LexV2Bot": {"AliasArn": alias_arn}}


def _alias(*, text=None, audio=None, name="prod"):
    settings = {}
    if text is not None:
        settings["textLogSettings"] = text
    if audio is not None:
        settings["audioLogSettings"] = audio
    return {"botAliasName": name, "conversationLogSettings": settings}


def _text_setting(
    enabled=True, selective=False, log_group="arn:aws:logs:us-east-1:123:log-group:g"
):
    return {
        "enabled": enabled,
        "destination": {"cloudWatch": {"cloudWatchLogGroupArn": log_group, "logPrefix": "p"}},
        "selectiveLoggingEnabled": selective,
    }


def _audio_setting(enabled=True, kms_key_arn=None, bucket="arn:aws:s3:::lex-audio"):
    s3 = {"s3BucketArn": bucket, "logPrefix": "p"}
    if kms_key_arn:
        s3["kmsKeyArn"] = kms_key_arn
    return {"enabled": enabled, "destination": {"s3Bucket": s3}}


def _access_denied(operation: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, operation)


def test_no_lex_bots_is_not_applicable(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory)

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.NOT_APPLICABLE
    assert finding.evidence["v1_bot_count"] == 0
    assert "no Amazon Lex bot is associated" in finding.description


def test_v1_only_is_not_applicable_and_names_v1(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(
        mock_aws_client_factory, v1_bots=[{"LexBot": {"Name": "OldBot", "LexRegion": "us-east-1"}}]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.NOT_APPLICABLE
    assert finding.evidence["v1_bot_count"] == 1
    assert "V1" in finding.description


def test_logging_disabled_passes_with_no_remediation(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias()

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.PASS
    assert finding.evidence["text_logging_enabled_count"] == 0
    assert finding.evidence["audio_logging_enabled_count"] == 0
    assert finding.structured_remediation is None


def test_unencrypted_audio_logging_fails(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias(
        audio=[_audio_setting(kms_key_arn=None)]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.FAIL
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["unencrypted_audio_log_count"] == 1
    assert finding.evidence["aliases"][0]["audio_kms_key_arn"] is None


def test_audio_logging_with_cmk_passes(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias(
        audio=[_audio_setting(kms_key_arn="arn:aws:kms:us-east-1:123:key/abc")]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.PASS
    assert finding.evidence["audio_logging_enabled_count"] == 1
    assert finding.evidence["unencrypted_audio_log_count"] == 0


def test_one_unencrypted_destination_among_several_fails(
    make_check_context, mock_aws_client_factory
):
    # Arrange — a single unprotected destination is enough to expose the audio.
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias(
        audio=[
            _audio_setting(kms_key_arn="arn:aws:kms:us-east-1:123:key/abc"),
            _audio_setting(kms_key_arn=None, bucket="arn:aws:s3:::second"),
        ]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.FAIL
    assert finding.evidence["aliases"][0]["audio_kms_key_arn"] is None


def test_disabled_audio_setting_without_key_does_not_fail(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias(
        audio=[_audio_setting(enabled=False, kms_key_arn=None)]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.PASS
    assert finding.evidence["audio_logging_enabled_count"] == 0


def test_text_logging_reports_encryption_as_unassessable(
    make_check_context, mock_aws_client_factory
):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias(
        text=[_text_setting()]
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.PASS
    assert finding.evidence["text_logging_enabled_count"] == 1
    assert finding.evidence["text_log_encryption_assessable"] is False
    assert finding.structured_remediation is not None
    assert finding.structured_remediation.applies_if


def test_alias_is_described_in_its_own_region(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot(_ALIAS_ARN_EU)])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias()

    # Act
    LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.assert_called_once_with(
        "BOTID67890", "PRODALIAS1", region_name="eu-west-2"
    )


def test_duplicate_alias_arns_are_evaluated_once(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot(), _v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias()

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.evidence["alias_count"] == 1
    assert mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.call_count == 1


def test_malformed_alias_arn_is_counted_not_guessed(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot("arn:aws:lex:us-east-1:123:bot/NotAnAlias")])

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.NOT_APPLICABLE
    assert finding.evidence["unparseable_alias_arns"] == 1
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.assert_not_called()


def test_paginated_bot_list_is_fully_walked(make_check_context, mock_aws_client_factory):
    # Arrange
    mock_aws_client_factory.is_access_denied = AWSClientFactory.is_access_denied
    pages = [
        {"LexBots": [_v2_bot(_ALIAS_ARN)], "NextToken": "t1"},
        {"LexBots": [_v2_bot(_ALIAS_ARN_EU)]},
    ]

    def _list_bots(instance_id, lex_version, **kwargs):
        return pages[1] if kwargs.get("NextToken") else pages[0]

    mock_aws_client_factory.list_bots_resilient.side_effect = _list_bots
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.return_value = _alias()

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.evidence["alias_count"] == 2


def test_list_bots_access_denied_is_skipped(make_check_context, mock_aws_client_factory):
    # Arrange
    mock_aws_client_factory.is_access_denied = AWSClientFactory.is_access_denied
    mock_aws_client_factory.list_bots_resilient.side_effect = _access_denied("ListBots")

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["required_permission"] == "connect:ListBots"


def test_describe_alias_access_denied_is_skipped(make_check_context, mock_aws_client_factory):
    # Arrange
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.side_effect = _access_denied(
        "DescribeBotAlias"
    )

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["required_permission"] == "lex:DescribeBotAlias"


def test_describe_alias_failure_is_skipped_not_passed(make_check_context, mock_aws_client_factory):
    # Arrange — a non-permission failure must not read as a healthy bot.
    _wire(mock_aws_client_factory, v2_bots=[_v2_bot()])
    mock_aws_client_factory.describe_lex_v2_bot_alias_resilient.side_effect = RuntimeError("boom")

    # Act
    finding = LexConversationLogEncryptionCheck().execute(make_check_context())

    # Assert
    assert finding.status == CheckStatus.SKIPPED
    assert finding.evidence["error_type"] == "RuntimeError"


def test_check_is_registered():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_lex_security_checks(registry)

    # Assert
    assert "sec-lex-convlogs-001" in {c.check_id for c in registry.get_all_checks()}


def test_check_is_registered_by_register_all_checks():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry)

    # Assert
    assert "sec-lex-convlogs-001" in {c.check_id for c in registry.get_all_checks()}


def test_check_survives_skip_flow_analysis():
    # Arrange — the check reads APIs, not flow content, so it must still run.
    registry = CheckRegistry()

    # Act
    register_all_checks(registry, skip_flow_analysis=True)

    # Assert
    assert "sec-lex-convlogs-001" in {c.check_id for c in registry.get_all_checks()}


def test_lex_audio_remediation_compliance_boundary_avoids_legal_determination():
    # Arrange
    unencrypted = [
        {
            "bot_alias_arn": _ALIAS_ARN,
            "bot_id": "BOTID12345",
            "bot_alias_id": "TSTALIASID",
            "region": "us-east-1",
        }
    ]

    # Act
    remediation = LexConversationLogEncryptionCheck._audio_remediation(unencrypted)

    # Assert
    assert "determine the obligations that apply" in remediation.summary
    assert "AWS shared responsibility model" in remediation.summary
    assert "GDPR" not in remediation.summary
