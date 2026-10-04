"""
Cost optimization intelligence checks (Phase 4 / Task 8).

Usage-metric and configuration-based cost checks:

- cost-usage-metrics-001    : CloudWatch usage metrics vs. capacity (Req 13)
- cost-unused-numbers-001   : Phone numbers with zero traffic (Req 14)
- cost-premium-features-001 : Enabled premium features that appear unconfigured (Req 15)
- cost-hours-mismatch-001   : Hours of Operation vs. actual traffic pattern (Req 16)

All checks degrade to SKIPPED on access denied and emit structured remediation.
"""

from ..cost.cost_estimator import estimate_unused_numbers_cost
from ..models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

# Amazon Connect publishes ConcurrentCalls keyed on InstanceId *and* MetricGroup,
# and CloudWatch matches a metric only on its complete dimension set. Querying
# InstanceId alone matches no metric and returns an empty datapoint list, which
# this check would misread as "the instance carried no traffic" on a busy
# instance — reporting every active instance as possibly unused.
_CONCURRENT_CALLS_METRIC_GROUP = "VoiceCalls"


class UsageMetricsCheck(BaseCheck):
    """Analyze CloudWatch usage metrics for over-provisioning (Req 13)."""

    def __init__(self):
        super().__init__(
            check_id="cost-usage-metrics-001",
            name="CloudWatch Usage Metrics Analysis",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description=(
                "Queries CloudWatch for call volume metrics over 30 days "
                "to identify unused or under-utilized instances."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)

        try:
            resp = factory.call_api_with_resilience(
                factory.get_cloudwatch_client(),
                "get_metric_statistics",
                "cloudwatch",
                Namespace="AWS/Connect",
                MetricName="ConcurrentCalls",
                Dimensions=[
                    {"Name": "InstanceId", "Value": instance.instance_id},
                    {"Name": "MetricGroup", "Value": _CONCURRENT_CALLS_METRIC_GROUP},
                ],
                StartTime=start.isoformat(),
                EndTime=end.isoformat(),
                Period=86400,
                Statistics=["Maximum", "Average"],
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudwatch:GetMetricStatistics")
            raise

        datapoints = resp.get("Datapoints", [])
        evidence = {
            "metric": "ConcurrentCalls",
            "datapoints_count": len(datapoints),
            "period_days": 30,
        }

        if not datapoints:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"No ConcurrentCalls metrics found for instance "
                    f"{instance.display_name} over the past 30 days — "
                    "the instance may be unused."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Investigate whether this instance is still needed.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Confirm whether this instance is actively "
                                "handling contacts. If unused, consider deleting "
                                "it and releasing associated phone numbers."
                            ),
                        ),
                    ],
                    applies_if="the instance is expected to handle live traffic.",
                ),
            )

        peak = max(dp.get("Maximum", 0) for dp in datapoints)
        avg = sum(dp.get("Average", 0) for dp in datapoints) / len(datapoints)
        evidence["peak_concurrent"] = peak
        evidence["avg_concurrent"] = round(avg, 2)

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Instance shows active usage: peak {peak:.0f} concurrent, "
                f"avg {avg:.1f} concurrent over 30 days."
            ),
            evidence=evidence,
        )


class UnusedPhoneNumbersCheck(BaseCheck):
    """Inventory claimed phone numbers for separate usage review."""

    def __init__(self):
        super().__init__(
            check_id="cost-unused-numbers-001",
            name="Claimed Phone Number Inventory",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description=(
                "Inventories claimed phone numbers and estimates a worst-case monthly "
                "holding cost for separate traffic and ownership verification."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "list_phone_numbers_v2",
                "connect",
                TargetArn=instance.instance_arn,
                MaxResults=50,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            resp = {"ListPhoneNumbersSummaryList": []}

        numbers = resp.get("ListPhoneNumbersSummaryList", []) or []
        if not numbers:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="No phone numbers claimed; nothing to evaluate.",
                evidence={"phone_count": 0},
            )

        # GetMetricDataV2 cannot filter by phone number, so this check cannot
        # determine number-level usage from CloudWatch. Report the limitation
        # explicitly and quantify only the supported worst-case holding cost.
        us_numbers = [n for n in numbers if n.get("PhoneNumberCountryCode", "US") == "US"]
        non_us_numbers = [n for n in numbers if n.get("PhoneNumberCountryCode", "US") != "US"]
        us_cost = estimate_unused_numbers_cost(len(us_numbers), country_code="US")
        international_cost = (
            estimate_unused_numbers_cost(len(non_us_numbers), country_code="INTL")
            if non_us_numbers
            else None
        )
        worst_case_total = (us_cost.monthly_estimate_usd or 0) + (
            international_cost.monthly_estimate_usd if international_cost else 0
        )
        evidence = {
            "phone_count": len(numbers),
            "numbers": [
                {
                    "country": n.get("PhoneNumberCountryCode", "?"),
                    "type": n.get("PhoneNumberType", "?"),
                }
                for n in numbers
            ],
            "worst_case_monthly_cost_usd": round(worst_case_total, 2),
            "cost_basis": us_cost.calculation_basis
            + (f"; {international_cost.calculation_basis}" if international_cost else ""),
        }

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"{len(numbers)} phone number(s) are claimed on "
                f"{instance.display_name}. CloudWatch does not expose "
                "number-level call volume for this check, so confirm usage "
                "with a Historical Metrics report filtered by number or a "
                "CTR export. If every claimed number were unused, the "
                f"supported worst-case holding cost is about "
                f"${worst_case_total:.2f}/month; actual avoidable cost depends "
                "on which numbers receive no traffic."
            ),
            evidence=evidence,
        )


# Human-readable names + pricing notes for the premium instance-attribute
# features this check surfaces. Keys match the ``AttributeType`` enum
# actually accepted by Connect's DescribeInstanceAttribute API.
#
# IMPORTANT: only CONTACT_LENS is a valid AttributeType. There is no
# WISDOM or CASES value in the DescribeInstanceAttribute enum — Amazon Q
# in Connect (Wisdom) and Cases are not instance attributes at all; they
# don't have an on/off flag exposed through this API. Earlier versions of
# this check probed "WISDOM" and "CASES" as AttributeType values, which
# always raised (invalid enum member), got swallowed by a bare
# `except Exception`, and silently reported both as permanently
# "disabled" regardless of actual configuration. Verified against the
# live botocore service model for connect.DescribeInstanceAttribute:
# valid members are INBOUND_CALLS, OUTBOUND_CALLS, CONTACTFLOW_LOGS,
# CONTACT_LENS, AUTO_RESOLVE_BEST_VOICES, USE_CUSTOM_TTS_VOICES,
# EARLY_MEDIA, MULTI_PARTY_CONFERENCE, HIGH_VOLUME_OUTBOUND,
# ENHANCED_CONTACT_MONITORING, ENHANCED_CHAT_MONITORING,
# MULTI_PARTY_CHAT_CONFERENCE, MESSAGE_STREAMING.
_PREMIUM_FEATURES = {
    "CONTACT_LENS": {
        "label": "Contact Lens for Voice / Chat",
        "billing": (
            "per minute of analyzed audio (voice) or per analyzed message "
            "(chat) — only when a flow explicitly enables analytics on the "
            "contact via `Set contact recording and analytics behavior`. "
            "Enablement alone does not create charges."
        ),
    },
}


class PremiumFeaturesCostCheck(BaseCheck):
    """Report enabled premium features so cost reviewers can audit usage."""

    def __init__(self):
        super().__init__(
            check_id="cost-premium-features-001",
            name="Premium Feature Enablement Inventory",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Inventories the Contact Lens instance attribute as enabled or disabled. "
                "Enablement itself is free; usage within contact flows is billed."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        # A failed attribute read is unknown, never equivalent to disabled.
        features_enabled = {}
        failed_attributes = []
        for attr_type in _PREMIUM_FEATURES:
            try:
                resp = factory.call_api_with_resilience(
                    factory.get_connect_client(),
                    "describe_instance_attribute",
                    "connect",
                    InstanceId=instance.instance_id,
                    AttributeType=attr_type,
                )
                attribute = resp.get("Attribute")
                value = attribute.get("Value") if isinstance(attribute, dict) else None
                if not isinstance(value, str):
                    raise ValueError("DescribeInstanceAttribute response omitted Attribute.Value")
                features_enabled[attr_type] = value.lower() == "true"
            except Exception as e:  # noqa: BLE001
                failed_attributes.append(
                    {
                        "attribute": attr_type,
                        "error_type": type(e).__name__,
                        "access_denied": bool(factory.is_access_denied(e)),
                    }
                )

        enabled = [f for f, value in features_enabled.items() if value]
        disabled = [f for f, value in features_enabled.items() if not value]
        evidence = {
            "features_checked": features_enabled,
            "features_enabled": enabled,
            "features_disabled": disabled,
            "features_undetermined": [row["attribute"] for row in failed_attributes],
            "failed_attribute_reads": failed_attributes,
            "analysis_complete": not failed_attributes,
        }

        if failed_attributes:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Premium feature enablement inventory was incomplete because "
                    f"{len(failed_attributes)} attribute read(s) failed. Observed enabled "
                    "and disabled states are retained in the evidence but are not treated "
                    "as a complete inventory."
                ),
                evidence=evidence,
            )

        if enabled:
            feature_lines = [
                f"* **{_PREMIUM_FEATURES[feature]['label']}** — billed "
                f"{_PREMIUM_FEATURES[feature]['billing']}"
                for feature in enabled
            ]
            description = (
                f"Connect instance {instance.display_name} has {len(enabled)} premium "
                "feature(s) enabled at the instance level:\n\n"
                + "\n".join(feature_lines)
                + "\n\nEnablement alone does not create charges. Verify whether production "
                "flows invoke each enabled feature and reconcile that usage with billing."
            )
        else:
            description = (
                f"Connect instance {instance.display_name} has no premium features "
                "(Contact Lens) enabled at the instance level."
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=description,
            evidence=evidence,
        )


class HoursOfOperationMismatchCheck(BaseCheck):
    """Inventory configured hours-of-operation schedules."""

    def __init__(self):
        super().__init__(
            check_id="cost-hours-mismatch-001",
            name="Hours of Operation Inventory",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Inventories returned Hours of Operation schedule summaries for "
                "separate schedule, traffic, staffing, and association review."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        # Retrieve hours of operation count.
        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "list_hours_of_operations",
                "connect",
                InstanceId=instance.instance_id,
                MaxResults=25,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListHoursOfOperations")
            resp = {"HoursOfOperationSummaryList": []}

        hoo_list = resp.get("HoursOfOperationSummaryList", []) or []
        evidence = {"hours_of_operation_count": len(hoo_list)}

        if not hoo_list:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="No hours of operation configured; check N/A.",
                evidence=evidence,
            )

        # For MVP: flag if there's only one 24/7 HoO (common misconfiguration
        # when a narrower schedule would reduce staffing cost).
        evidence["hoo_names"] = [h.get("Name") for h in hoo_list]
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"{len(hoo_list)} Hours of Operation schedule(s) configured. "
                "Review traffic patterns to confirm alignment."
            ),
            evidence=evidence,
        )


def register_cost_intelligence_checks(registry) -> None:
    """Register all cost-intelligence checks."""
    registry.register_check(UsageMetricsCheck())
    registry.register_check(UnusedPhoneNumbersCheck())
    registry.register_check(PremiumFeaturesCostCheck())
    registry.register_check(HoursOfOperationMismatchCheck())
