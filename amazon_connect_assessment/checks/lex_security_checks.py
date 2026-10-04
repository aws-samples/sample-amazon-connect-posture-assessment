"""
Amazon Lex conversation-log posture for bots associated with a Connect instance.

- sec-lex-convlogs-001 : Lex V2 conversation logs recorded without a CMK

Conversation logs are where a self-service bot's contents leave the bot. Text
logging writes the caller's utterances to a CloudWatch log group; audio logging
writes the caller's recorded voice to an S3 bucket. In a contact centre those
utterances and recordings routinely carry what the caller read out loud to the
bot — an account number, a date of birth, a postcode — so the protection on the
destination matters as much as the protection on the live conversation.

Scope is deliberately narrow and decidable. The check fails on one condition:
audio logging enabled with no ``kmsKeyArn`` on the S3 destination, which means
the recordings are not protected by a key whose policy, audit trail, and
revocation you control. Everything else is reported as inventory, because Lex
does not expose enough to judge it:

* ``CloudWatchLogGroupLogDestination`` has no KMS member at all, so whether the
  text log group is encrypted with a CMK is not knowable from Lex. The finding
  says so and points the reader at CloudWatch Logs instead of guessing.
* Logging being enabled is not itself a defect — it is usually a deliberate and
  often required choice. The check reports that it is on, and what protects the
  destination, rather than treating the operator's decision as a problem.

Compliance and shared responsibility: Lex conversation logs and audio may
contain personal, payment-card, or health data depending on the workload. Under
the AWS shared responsibility model, customers must classify the data,
determine which legal, regulatory, and contractual obligations apply, and
configure retention, access, and encryption for each log destination. This
check is an engineering signal, not a compliance determination. See
https://aws.amazon.com/compliance/

Amazon Lex V1 bots are not evaluated. Their conversation-log settings live on a
different API shape (``lex-models:GetBotAlias``), and an instance whose only
association is a V1 bot receives ``NOT_APPLICABLE`` naming that limitation, so a
clean result never implies a V1 bot was inspected.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..models import (
    CheckStatus,
    Finding,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

_MAX_LIST_PAGES = 20
_LIST_PAGE_SIZE = 25


@dataclass
class _IncompleteCollectionError(Exception):
    """Describe an incomplete paginated lookup without discarding partial evidence."""

    operation: str
    reason: str
    partial_count: int = 0
    pages_completed: int = 0
    cause: Optional[Exception] = None


def _collect_bots(
    fetch_page: Callable[..., Dict[str, Any]], *, operation: str
) -> List[Dict[str, Any]]:
    """Collect every page of ``connect:ListBots`` or raise with partial evidence."""
    items: List[Dict[str, Any]] = []
    next_token: Optional[str] = None

    for page_index in range(_MAX_LIST_PAGES):
        kwargs: Dict[str, Any] = {"MaxResults": _LIST_PAGE_SIZE}
        if next_token:
            kwargs["NextToken"] = next_token
        try:
            response = fetch_page(**kwargs)
        except Exception as error:  # noqa: BLE001 - classified by the caller
            raise _IncompleteCollectionError(
                operation=operation,
                reason="api_call_failed",
                partial_count=len(items),
                pages_completed=page_index,
                cause=error,
            ) from error

        page_items = response.get("LexBots") or []
        items.extend(item for item in page_items if isinstance(item, dict))
        next_token = response.get("NextToken")
        if not next_token:
            return items

    raise _IncompleteCollectionError(
        operation=operation,
        reason="pagination_limit_reached",
        partial_count=len(items),
        pages_completed=_MAX_LIST_PAGES,
    )


def _parse_bot_alias_arn(arn: str) -> Optional[Dict[str, str]]:
    """
    Split a Lex V2 bot-alias ARN into the parts needed to describe the alias.

    Expected shape:
    ``arn:aws:lex:<region>:<account>:bot-alias/<botId>/<botAliasId>``

    Returns ``None`` for anything that does not match, so an unexpected ARN
    format is skipped and counted rather than producing a half-formed API call.
    """
    parts = (arn or "").split(":")
    if len(parts) < 6 or parts[2] != "lex":
        return None

    resource = parts[5].split("/")
    if len(resource) != 3 or resource[0] != "bot-alias":
        return None

    return {
        "region": parts[3],
        "bot_id": resource[1],
        "bot_alias_id": resource[2],
        "arn": arn,
    }


def _v2_alias_refs(bots: List[Dict[str, Any]]) -> tuple[List[Dict[str, str]], int]:
    """Return the parseable V2 alias references and the count that could not be parsed."""
    refs: List[Dict[str, str]] = []
    unparseable = 0
    seen: set = set()

    for bot in bots:
        arn = (bot.get("LexV2Bot") or {}).get("AliasArn") or ""
        ref = _parse_bot_alias_arn(arn)
        if ref is None:
            unparseable += 1
            continue
        key = (ref["region"], ref["bot_id"], ref["bot_alias_id"])
        if key in seen:
            continue
        seen.add(key)
        refs.append(ref)

    return refs, unparseable


class LexConversationLogEncryptionCheck(BaseCheck):
    """
    Evaluate Lex V2 conversation-log destinations for customer-managed encryption.

    Fails only when audio logging writes caller recordings to S3 with no
    ``kmsKeyArn``. Text-log encryption is reported as unknown rather than
    guessed, because Lex exposes no KMS field for the CloudWatch destination.
    """

    def __init__(self) -> None:
        super().__init__(
            check_id="sec-lex-convlogs-001",
            name="Lex Conversation Log Encryption",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Reports Amazon Lex V2 conversation logging for the bots associated with "
                "this instance, and fails when audio logging writes caller recordings to "
                "S3 without a customer-managed KMS key. Lex exposes no KMS setting for the "
                "CloudWatch text-log destination, so text-log encryption is reported as "
                "unknown rather than inferred. Amazon Lex V1 bots are not evaluated."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory

        try:
            v2_bots = _collect_bots(
                lambda **kwargs: factory.list_bots_resilient(instance.instance_id, "V2", **kwargs),
                operation="connect:ListBots (V2)",
            )
        except _IncompleteCollectionError as error:
            return self._skipped_for_incomplete(context, error, "connect:ListBots")

        alias_refs, unparseable_arns = _v2_alias_refs(v2_bots)

        if not alias_refs:
            return self._not_applicable_for_no_v2_bots(context, factory, unparseable_arns)

        inventory: List[Dict[str, Any]] = []
        unencrypted_audio: List[Dict[str, Any]] = []

        for index, ref in enumerate(alias_refs):
            try:
                alias = factory.describe_lex_v2_bot_alias_resilient(
                    ref["bot_id"], ref["bot_alias_id"], region_name=ref["region"]
                )
            except Exception as error:  # noqa: BLE001 - classified below
                return self._skipped_for_alias_error(context, error, ref, index, len(alias_refs))

            entry = self._summarize_alias(ref, alias)
            inventory.append(entry)
            if entry["audio_logging_enabled"] and not entry["audio_kms_key_arn"]:
                unencrypted_audio.append(entry)

        text_logging_count = sum(1 for e in inventory if e["text_logging_enabled"])
        audio_logging_count = sum(1 for e in inventory if e["audio_logging_enabled"])
        evidence: Dict[str, Any] = {
            "alias_count": len(inventory),
            "text_logging_enabled_count": text_logging_count,
            "audio_logging_enabled_count": audio_logging_count,
            "unencrypted_audio_log_count": len(unencrypted_audio),
            "aliases": inventory,
            "text_log_encryption_assessable": False,
            "text_log_encryption_note": (
                "Amazon Lex does not expose a KMS setting for the CloudWatch text-log "
                "destination. Confirm the log group's encryption in CloudWatch Logs."
            ),
            "lex_v1_bots_evaluated": False,
        }
        if unparseable_arns:
            evidence["unparseable_alias_arns"] = unparseable_arns

        if unencrypted_audio:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="LexBotAlias",
                description=(
                    f"{len(unencrypted_audio)} of {len(inventory)} Lex V2 bot alias(es) record "
                    "caller audio to S3 with no customer-managed KMS key, so access to the "
                    "recordings is not gated by a key policy you control."
                ),
                evidence=evidence,
                structured_remediation=self._audio_remediation(unencrypted_audio),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="LexBotAlias",
            description=self._pass_description(
                len(inventory), text_logging_count, audio_logging_count
            ),
            evidence=evidence,
            structured_remediation=self._text_log_remediation(inventory),
        )

    @staticmethod
    def _summarize_alias(ref: Dict[str, str], alias: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce a DescribeBotAlias response to the conversation-log facts reported."""
        log_settings = alias.get("conversationLogSettings") or {}

        text_settings = log_settings.get("textLogSettings") or []
        text_enabled = any(bool(setting.get("enabled")) for setting in text_settings)
        text_log_groups = [
            ((setting.get("destination") or {}).get("cloudWatch") or {}).get(
                "cloudWatchLogGroupArn"
            )
            for setting in text_settings
            if setting.get("enabled")
        ]

        audio_settings = log_settings.get("audioLogSettings") or []
        audio_enabled = any(bool(setting.get("enabled")) for setting in audio_settings)
        audio_buckets: List[str] = []
        audio_kms_key_arn: Optional[str] = None
        for setting in audio_settings:
            if not setting.get("enabled"):
                continue
            s3_bucket = (setting.get("destination") or {}).get("s3Bucket") or {}
            bucket_arn = s3_bucket.get("s3BucketArn")
            if bucket_arn:
                audio_buckets.append(str(bucket_arn))
            # Any enabled destination without a key leaves the alias unprotected,
            # so the first missing key decides; only record a key when every
            # enabled destination has one.
            key_arn = s3_bucket.get("kmsKeyArn")
            if not key_arn:
                audio_kms_key_arn = None
                break
            audio_kms_key_arn = str(key_arn)

        # selectiveLoggingEnabled means Lex logs only the turns a flow opts in
        # to. Reported as context: whether it should be on depends on why the
        # logs exist, which this tool cannot know.
        selective_text = any(
            bool(setting.get("selectiveLoggingEnabled"))
            for setting in text_settings
            if setting.get("enabled")
        )
        selective_audio = any(
            bool(setting.get("selectiveLoggingEnabled"))
            for setting in audio_settings
            if setting.get("enabled")
        )

        return {
            "bot_alias_arn": ref["arn"],
            "bot_id": ref["bot_id"],
            "bot_alias_id": ref["bot_alias_id"],
            "bot_alias_name": alias.get("botAliasName"),
            "region": ref["region"],
            "text_logging_enabled": text_enabled,
            "text_log_groups": [group for group in text_log_groups if group],
            "text_selective_logging": selective_text,
            "audio_logging_enabled": audio_enabled,
            "audio_buckets": audio_buckets,
            "audio_kms_key_arn": audio_kms_key_arn,
            "audio_selective_logging": selective_audio,
        }

    @staticmethod
    def _pass_description(alias_count: int, text_count: int, audio_count: int) -> str:
        if text_count == 0 and audio_count == 0:
            return (
                f"Conversation logging is disabled on all {alias_count} associated Lex V2 bot "
                "alias(es); no caller transcripts or recordings are being written."
            )

        parts = []
        if text_count:
            parts.append(f"{text_count} log caller transcripts to CloudWatch Logs")
        if audio_count:
            parts.append(f"{audio_count} record caller audio to S3 under a customer-managed key")
        return (
            f"Of {alias_count} associated Lex V2 bot alias(es), " + " and ".join(parts) + ". "
            "No audio destination is missing a customer-managed key. Text-log encryption is "
            "not exposed by Lex and was not assessed."
        )

    @staticmethod
    def _audio_remediation(unencrypted: List[Dict[str, Any]]) -> Remediation:
        first = unencrypted[0]
        return Remediation(
            summary=(
                "Encrypt Lex audio conversation logs with a customer-managed KMS key, or turn "
                "audio logging off if the recordings are not needed. These logs may contain "
                "personal, payment-card, or health data; determine the obligations that apply "
                "and configure the destination under the AWS shared responsibility model "
                "(https://aws.amazon.com/compliance/)."
            ),
            target_resources=[entry["bot_alias_arn"] for entry in unencrypted],
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        "Decide first whether the recordings are needed. Turning audio logging "
                        "off removes the exposure outright and is cheaper than protecting data "
                        "nobody reads."
                    ),
                    console_path=(
                        "Amazon Lex V2 console > Bots > (bot) > Aliases > (alias) > "
                        "Conversation logs > Audio logs"
                    ),
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "If the recordings are needed, select a customer-managed KMS key for "
                        "the audio log destination so access is gated by a key policy you "
                        "control and key use is recorded in CloudTrail."
                    ),
                    console_path=(
                        "Amazon Lex V2 console > Bots > (bot) > Aliases > (alias) > "
                        "Conversation logs > Audio logs > Encryption"
                    ),
                ),
                RemediationStep(
                    order=3,
                    instruction=(
                        "Confirm the change took effect, and that the destination bucket "
                        "policy restricts reads to the roles that review conversations."
                    ),
                    command=(
                        "aws lexv2-models describe-bot-alias "
                        f"--bot-id {first['bot_id']} --bot-alias-id {first['bot_alias_id']} "
                        f"--region {first['region']} "
                        "--query 'conversationLogSettings.audioLogSettings'"
                    ),
                ),
                RemediationStep(
                    order=4,
                    instruction=(
                        "Separately confirm the text-log group's encryption. Lex exposes no KMS "
                        "setting for the CloudWatch destination, so this check could not assess "
                        "it; a log group with no kmsKeyId uses CloudWatch Logs service-side "
                        "encryption only."
                    ),
                    command=(
                        "aws logs describe-log-groups --log-group-name-prefix /aws/lex "
                        "--query 'logGroups[].[logGroupName,kmsKeyId]'"
                    ),
                ),
            ],
            references=[
                RemediationReference(
                    title="Amazon Lex V2: Conversation logs",
                    url="https://docs.aws.amazon.com/lexv2/latest/dg/conversation-logs.html",
                ),
                RemediationReference(
                    title="Amazon Lex V2: Encryption at rest",
                    url="https://docs.aws.amazon.com/lexv2/latest/dg/encryption-at-rest.html",
                ),
            ],
        )

    @staticmethod
    def _text_log_remediation(inventory: List[Dict[str, Any]]) -> Optional[Remediation]:
        """
        Conditional guidance for the one thing Lex cannot answer.

        Returned only when text logging is actually on, so an instance with
        logging disabled gets a clean pass with no action attached to it.
        """
        logging_aliases = [entry for entry in inventory if entry["text_logging_enabled"]]
        if not logging_aliases:
            return None

        return Remediation(
            summary=(
                "Confirm the CloudWatch log groups holding Lex caller transcripts are "
                "encrypted with a customer-managed KMS key."
            ),
            target_resources=[entry["bot_alias_arn"] for entry in logging_aliases],
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        "Check each text-log group for a kmsKeyId. Lex exposes no KMS setting "
                        "for this destination, so this check reports the encryption state as "
                        "unknown rather than passing it."
                    ),
                    command=(
                        "aws logs describe-log-groups --log-group-name-prefix /aws/lex "
                        "--query 'logGroups[].[logGroupName,kmsKeyId]'"
                    ),
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "Associate a customer-managed key with any group that has none, and "
                        "review the group's retention period against how long transcripts of "
                        "caller conversations should be kept."
                    ),
                    console_path="CloudWatch console > Log groups > (group) > Actions",
                ),
            ],
            references=[
                RemediationReference(
                    title="Amazon Lex V2: Conversation logs",
                    url="https://docs.aws.amazon.com/lexv2/latest/dg/conversation-logs.html",
                ),
            ],
            applies_if="Lex conversation transcripts are retained in CloudWatch Logs.",
        )

    def _not_applicable_for_no_v2_bots(
        self, context: CheckContext, factory: Any, unparseable_arns: int
    ) -> Finding:
        """
        Distinguish "no Lex at all" from "Lex V1 only", which this check skips.

        The V1 lookup is a second list call, and it is worth it: reporting Not
        Applicable without naming a V1 bot that is present would read as "there
        is no bot here" when what happened is that the bot was out of scope.
        """
        evidence: Dict[str, Any] = {"v2_alias_count": 0}
        if unparseable_arns:
            evidence["unparseable_alias_arns"] = unparseable_arns

        try:
            v1_bots = _collect_bots(
                lambda **kwargs: factory.list_bots_resilient(
                    context.instance.instance_id, "V1", **kwargs
                ),
                operation="connect:ListBots (V1)",
            )
        except _IncompleteCollectionError:
            # The V1 count is only there to phrase the reason. Losing it is not
            # worth downgrading a determinate V2 result to SKIPPED.
            v1_bots = []
            evidence["v1_bot_count_unavailable"] = True

        evidence["v1_bot_count"] = len(v1_bots)

        if v1_bots:
            reason = (
                f"the instance is associated with {len(v1_bots)} Amazon Lex V1 bot(s) and no "
                "Lex V2 bots; V1 conversation-log settings use a different API and are not "
                "evaluated by this check"
            )
        else:
            reason = "no Amazon Lex bot is associated with the instance"

        return self.not_applicable(
            context,
            reason,
            resource_type="LexBotAlias",
            evidence=evidence,
        )

    def _skipped_for_incomplete(
        self,
        context: CheckContext,
        error: _IncompleteCollectionError,
        required_permission: str,
    ) -> Finding:
        evidence: Dict[str, Any] = {
            "operation": error.operation,
            "limitation": error.reason,
            "partial_item_count": error.partial_count,
            "pages_completed": error.pages_completed,
        }
        factory = context.aws_client_factory
        if error.cause is not None and factory.is_access_denied(error.cause):
            finding = self.skipped_for_access_denied(context, required_permission)
            finding.evidence.update(evidence)
            return finding

        if error.cause is not None:
            evidence["error_type"] = type(error.cause).__name__
        return self.create_finding(
            status=CheckStatus.SKIPPED,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Skipped: insufficient data from {error.operation}. Partial results were "
                "retained as evidence but were not interpreted as a healthy configuration."
            ),
            evidence=evidence,
        )

    def _skipped_for_alias_error(
        self,
        context: CheckContext,
        error: Exception,
        ref: Dict[str, str],
        index: int,
        total: int,
    ) -> Finding:
        evidence = {
            "operation": "lex:DescribeBotAlias",
            "bot_alias_arn": ref["arn"],
            "aliases_evaluated": index,
            "alias_count": total,
        }
        if context.aws_client_factory.is_access_denied(error):
            finding = self.skipped_for_access_denied(
                context, "lex:DescribeBotAlias", resource_type="LexBotAlias"
            )
            finding.evidence.update(evidence)
            return finding

        return self.create_finding(
            status=CheckStatus.SKIPPED,
            resource_id=context.instance.instance_id,
            resource_type="LexBotAlias",
            description=(
                "Skipped: lex:DescribeBotAlias failed, so conversation-log settings could not "
                "be read for every associated bot alias. Partial observations were not "
                "interpreted as a healthy configuration."
            ),
            evidence={"error_type": type(error).__name__, **evidence},
        )


def register_lex_security_checks(registry) -> None:
    """Register the Amazon Lex conversation-log security checks."""
    registry.register_check(LexConversationLogEncryptionCheck())
