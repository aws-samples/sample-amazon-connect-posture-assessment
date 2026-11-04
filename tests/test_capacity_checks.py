"""
Tests for the service-quota and capacity headroom checks.

The behaviour worth pinning here is mostly about *not* reporting a false PASS:
an unmeasurable resource, a denied API call, or a quota AWS does not publish
must never be rendered as "you have headroom".
"""

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.capacity_checks import (
    CallVolumeGrowthTrendCheck,
    ConcurrentCallsHeadroomCheck,
    ConfigurationQuotaUtilizationCheck,
    QuotaLookupDenied,
    QuotaLookupIncomplete,
    _linear_fit,
    _match_quota,
    _MetricWindow,
    _weekly_peaks,
    get_connect_quotas,
    quota_context_ids,
    register_capacity_checks,
    reset_quota_cache,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import CheckStatus, Severity

ACCESS_DENIED = ClientError(
    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListServiceQuotas"
)

# Two instances in one region, which is the case a region-keyed quota table
# cannot represent.
ARN_A = "arn:aws:connect:us-east-1:123456789012:instance/instance-a"
ARN_B = "arn:aws:connect:us-east-1:123456789012:instance/instance-b"

# Quota names as Service Quotas publishes them for Amazon Connect.
DEFAULT_QUOTAS = [
    {"QuotaName": "Users per instance", "Value": 500.0},
    {"QuotaName": "Queues per instance", "Value": 250.0},
    {"QuotaName": "Routing profiles per instance", "Value": 100.0},
    {"QuotaName": "Security profiles per instance", "Value": 100.0},
    {"QuotaName": "Flows per instance", "Value": 100.0},
    {"QuotaName": "Phone numbers per instance", "Value": 100.0},
    {"QuotaName": "Concurrent active calls per instance", "Value": 100.0},
]


@pytest.fixture(autouse=True)
def _clear_quota_cache():
    """The quota table is cached per region; isolate every test from it."""
    reset_quota_cache()
    yield
    reset_quota_cache()


def _days_ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


class _Api:
    """
    Dispatches ``call_api_with_resilience`` by operation name.

    Each operation maps either to a response dict or to an exception instance
    to raise, which is how the denied-permission paths are exercised.
    """

    def __init__(self, **responses):
        self.responses = responses
        self.calls = []
        # Request arguments are retained as well as operation names: a canned
        # response for any argument list is what allowed a malformed CloudWatch
        # query to pass CI, so the dimensions have to be assertable.
        self.calls_with_kwargs = []

    def __call__(self, client, operation, service=None, **kwargs):
        self.calls.append(operation)
        self.calls_with_kwargs.append({"operation": operation, "kwargs": kwargs})
        if operation not in self.responses:
            raise AssertionError(f"unexpected API call: {operation}")
        result = self.responses[operation]
        # A list means "one response per successive call", which is how the
        # paginated paths are exercised.
        if isinstance(result, list):
            result = result.pop(0) if len(result) > 1 else result[0]
        if isinstance(result, Exception):
            raise result
        return result

    def kwargs_for(self, operation):
        """Return the request arguments of the first call to ``operation``."""
        return next(
            call["kwargs"] for call in self.calls_with_kwargs if call["operation"] == operation
        )


def _wire(factory, api):
    factory.call_api_with_resilience = api
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _quota_responses(defaults=None, applied=None, denied=None):
    """Build the two Service Quotas list responses used by every check."""
    if denied == "both":
        return {
            "list_aws_default_service_quotas": ACCESS_DENIED,
            "list_service_quotas": ACCESS_DENIED,
        }
    return {
        "list_aws_default_service_quotas": {
            "Quotas": DEFAULT_QUOTAS if defaults is None else defaults
        },
        "list_service_quotas": {"Quotas": applied or []},
        # No traffic distribution group by default: the instance-scoped phone
        # number count is then complete. Tests that exercise the ACGR path
        # override this with a non-empty summary list.
        "list_traffic_distribution_groups": {"TrafficDistributionGroupSummaryList": []},
    }


def _metric_response(points):
    return {"Datapoints": [{"Timestamp": ts, "Maximum": value} for ts, value in points]}


def _populate(instance, queues=10, routing=10, security=10, flows=10):
    """
    Give an instance non-empty collections so counts are measurable.

    Users are deliberately absent: no analyzer populates ``instance.users``, so a
    test that sets it would assert against a state no real run produces. The
    check counts users from ListUsers, which tests wire through ``_users``.
    """
    instance.queues = [object()] * queues
    instance.routing_profiles = [object()] * routing
    instance.security_profiles = [object()] * security
    instance.contact_flows = [object()] * flows
    return instance


def _users(count, next_token=None):
    """A ListUsers page as Connect returns it."""
    response = {"UserSummaryList": [{"Id": f"u{i}"} for i in range(count)]}
    if next_token:
        response["NextToken"] = next_token
    return response


# ---------------------------------------------------------------------------
# Quota lookup and matching
# ---------------------------------------------------------------------------


class TestQuotaLookup:
    def test_applied_quota_overrides_default(self, mock_aws_client_factory):
        api = _Api(
            **_quota_responses(applied=[{"QuotaName": "Users per instance", "Value": 2000.0}])
        )
        _wire(mock_aws_client_factory, api)
        quotas = get_connect_quotas(mock_aws_client_factory)
        assert quotas["Users per instance"] == 2000.0

    def test_defaults_used_when_no_increase_requested(self, mock_aws_client_factory):
        # An instance that never requested an increase has no applied quotas.
        # Falling back to defaults is what keeps the checks usable there.
        api = _Api(**_quota_responses(applied=[]))
        _wire(mock_aws_client_factory, api)
        assert get_connect_quotas(mock_aws_client_factory)["Users per instance"] == 500.0

    def test_both_reads_denied_raises(self, mock_aws_client_factory):
        api = _Api(**_quota_responses(denied="both"))
        _wire(mock_aws_client_factory, api)
        with pytest.raises(QuotaLookupDenied):
            get_connect_quotas(mock_aws_client_factory)

    def test_applied_denial_alone_still_returns_the_defaults_table(self, mock_aws_client_factory):
        # Only the applied listing is denied. The defaults still supply every
        # ceiling, so the table is usable — the sole casualty is an unseen
        # per-instance increase, which makes the comparison conservative rather
        # than a silent miss.
        api = _Api(
            list_aws_default_service_quotas={"Quotas": DEFAULT_QUOTAS},
            list_service_quotas=ACCESS_DENIED,
        )
        _wire(mock_aws_client_factory, api)
        assert get_connect_quotas(mock_aws_client_factory)["Queues per instance"] == 250.0

    def test_defaults_denial_alone_raises(self, mock_aws_client_factory):
        # The dangerous asymmetry: defaults denied but applied allowed. An
        # instance still on defaults then has no applied override, so the table
        # is empty and every quota reads as unpublished — the silent opposite of
        # this module's purpose. It must SKIP, not quietly report NOT_APPLICABLE.
        api = _Api(
            list_aws_default_service_quotas=ACCESS_DENIED,
            list_service_quotas={"Quotas": []},
        )
        _wire(mock_aws_client_factory, api)
        with pytest.raises(QuotaLookupDenied):
            get_connect_quotas(mock_aws_client_factory)

    def test_table_is_cached_across_checks(self, mock_aws_client_factory):
        api = _Api(**_quota_responses())
        _wire(mock_aws_client_factory, api)
        get_connect_quotas(mock_aws_client_factory)
        get_connect_quotas(mock_aws_client_factory)
        # Two operations on the first call, nothing on the second.
        assert len(api.calls) == 2

    # --- Instance scoping. A Connect quota can be raised for one instance, so
    # the region's table is a set of candidate values, not an answer. Reducing
    # it to one number per region evaluated every instance in the region
    # against whichever record happened to be read last. ---

    def test_resource_level_quota_applies_only_to_its_instance(self, mock_aws_client_factory):
        api = _Api(
            **_quota_responses(
                applied=[
                    {
                        "QuotaName": "Users per instance",
                        "QuotaCode": "L-CE1D9967",
                        "Value": 5000.0,
                        "QuotaAppliedAtLevel": "RESOURCE",
                        "QuotaContext": {
                            "ContextScope": "RESOURCE",
                            "ContextScopeType": "connect:instance",
                            "ContextId": ARN_B,
                        },
                    }
                ]
            )
        )
        _wire(mock_aws_client_factory, api)
        # Instance B had its ceiling raised; A is still on the AWS default. One
        # regional value for both reports A as 9% consumed when it is at 90%,
        # or B as 200% consumed when it has plenty of room.
        assert get_connect_quotas(mock_aws_client_factory, (ARN_A,))["Users per instance"] == 500.0
        assert get_connect_quotas(mock_aws_client_factory, (ARN_B,))["Users per instance"] == 5000.0
        # And resolving per instance must not cost an extra listing.
        assert len(api.calls) == 2

    def test_resource_value_outranks_account_value(self, mock_aws_client_factory):
        api = _Api(
            **_quota_responses(
                applied=[
                    {"QuotaName": "Users per instance", "Value": 1000.0},
                    {
                        "QuotaName": "Users per instance",
                        "Value": 5000.0,
                        "QuotaContext": {"ContextId": ARN_B},
                    },
                ]
            )
        )
        _wire(mock_aws_client_factory, api)
        quotas = get_connect_quotas(mock_aws_client_factory, (ARN_B,))
        assert quotas["Users per instance"] == 5000.0
        # An instance with no resource-level record falls back to the account
        # value, and only then to the AWS default.
        assert get_connect_quotas(mock_aws_client_factory, (ARN_A,))["Users per instance"] == 1000.0

    def test_applied_listing_asks_for_resource_level_values(self, mock_aws_client_factory):
        # Without QuotaAppliedAtLevel the response carries account-level values
        # only, so a per-instance increase would never be seen and the fix above
        # would have nothing to resolve against.
        api = _Api(**_quota_responses())
        _wire(mock_aws_client_factory, api)
        get_connect_quotas(mock_aws_client_factory)
        assert api.kwargs_for("list_service_quotas")["QuotaAppliedAtLevel"] == "ALL"

    def test_instance_id_is_offered_as_a_context_id(self, sample_connect_instance):
        # Service Quotas does not document whether Connect keys the context on
        # the ARN or the ID, so both are offered rather than one guessed.
        ids = quota_context_ids(sample_connect_instance)
        assert sample_connect_instance.instance_arn in ids
        assert sample_connect_instance.instance_id in ids

    def test_truncated_listing_raises_rather_than_returning_a_partial_table(
        self, mock_aws_client_factory
    ):
        # A truncated table keeps the defaults read first and drops the applied
        # values that would have superseded them, so every percentage it feeds
        # is computed against a ceiling that may not be in force.
        page = {"Quotas": DEFAULT_QUOTAS, "NextToken": "more"}
        api = _Api(
            list_aws_default_service_quotas=[page] * 21,
            list_service_quotas={"Quotas": []},
        )
        _wire(mock_aws_client_factory, api)
        with pytest.raises(QuotaLookupIncomplete):
            get_connect_quotas(mock_aws_client_factory)

    def test_non_access_denied_error_propagates(self, mock_aws_client_factory):
        # A throttle or network fault must not be silently swallowed into an
        # empty quota table, which would read as "no quotas published".
        boom = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
            "ListServiceQuotas",
        )
        api = _Api(list_aws_default_service_quotas=boom, list_service_quotas=boom)
        _wire(mock_aws_client_factory, api)
        with pytest.raises(ClientError):
            get_connect_quotas(mock_aws_client_factory)


class TestQuotaMatching:
    def test_shortest_match_wins(self):
        quotas = {
            "Queues per instance": 250.0,
            "Queues per routing profile per instance": 50.0,
        }
        assert _match_quota(quotas, ("queues", "per instance")) == (
            "Queues per instance",
            250.0,
        )

    def test_returns_none_when_unpublished(self):
        assert _match_quota({"Users per instance": 1.0}, ("widgets", "per instance")) is None


def _consecutive(values):
    """``(week index, peak)`` pairs for a gap-free series."""
    return [(index, float(value)) for index, value in enumerate(values)]


def _slope(points):
    return _linear_fit(points)[0]


def _window(points, lookback_days=90, end=None):
    """A metric window around ``(timestamp, value)`` pairs, as the check sees one."""
    end = end or datetime.now(timezone.utc)
    return _MetricWindow(
        points=sorted(points, key=lambda item: item[0]),
        start=end - timedelta(days=lookback_days),
        end=end,
        lookback_days=lookback_days,
    )


class TestTrendMath:
    def test_slope_detects_growth(self):
        assert _slope(_consecutive([10, 20, 30, 40])) == pytest.approx(10.0)

    def test_slope_detects_decline(self):
        assert _slope(_consecutive([40, 30, 20, 10])) == pytest.approx(-10.0)

    def test_single_outlier_does_not_dominate(self):
        # Flat series with one spike at the end: a first-vs-last comparison
        # would call this steep growth, least squares should not.
        assert _slope(_consecutive([10, 10, 10, 10, 10, 10, 60])) < 8.0

    def test_slope_uses_elapsed_weeks_not_list_position(self):
        # The same four peaks spread over ten weeks grow at a third of the rate.
        # Regressing against position reported 10/week for both, understating
        # the runway threefold and escalating severity on the strength of it.
        gapped = [(0, 10.0), (3, 20.0), (6, 30.0), (9, 40.0)]
        assert _slope(gapped) == pytest.approx(10.0 / 3, abs=0.01)
        assert _slope(_consecutive([10, 20, 30, 40])) == pytest.approx(10.0)

    def test_fit_returns_the_intercept_as_well_as_the_slope(self):
        # The intercept is what lets a projection start from the fitted level
        # rather than from the last raw observation.
        slope, intercept = _linear_fit(_consecutive([30, 40, 50, 60]))
        assert slope == pytest.approx(10.0)
        assert intercept == pytest.approx(30.0)

    def test_fitted_level_ignores_a_quiet_final_week(self):
        # Six weeks climbing 10/week, then a quiet week at 20. Anchoring on the
        # raw final peak puts the current level at 20 with a 100-call quota
        # 8 weeks away; the fit puts it near 55, which is where the trend is.
        points = _consecutive([10, 20, 30, 40, 50, 60]) + [(6, 20.0)]
        slope, intercept = _linear_fit(points)
        assert intercept + slope * 6 > 40.0

    def test_weekly_peaks_take_the_max_per_bucket(self):
        points = [(_days_ago(20 - day), float(day)) for day in range(21)]
        weekly = _weekly_peaks(_window(points))
        assert [week for week, _ in weekly] == [0, 1, 2]
        assert [peak for _, peak in weekly] == sorted(peak for _, peak in weekly)

    def test_weekly_peaks_retain_the_index_of_a_skipped_week(self):
        # A week with no datapoint is absent, not zero: CloudWatch reporting
        # nothing is not the same claim as the instance having taken no calls.
        points = [(_days_ago(21), 10.0), (_days_ago(7), 30.0)]
        assert _weekly_peaks(_window(points)) == [(0, 10.0), (2, 30.0)]

    def test_buckets_are_anchored_to_the_window_end(self):
        # The most recent bucket must cover a full seven days. Anchored to the
        # first datapoint instead, a window that does not divide into whole
        # weeks leaves the *newest* bucket short, so it reports the peak of a
        # few days against buckets reporting the peak of seven.
        newest = [(_days_ago(day), 50.0) for day in range(7)]
        oldest = [(_days_ago(day), 10.0) for day in range(7, 14)]
        weekly = _weekly_peaks(_window(newest + oldest, lookback_days=90))
        assert weekly == [(0, 10.0), (1, 50.0)]

    def test_short_leading_bucket_is_dropped(self):
        # A 90-day lookback holds 12 whole weeks and a 6-day remainder. A
        # datapoint in that remainder would form a bucket covering less than a
        # week, understating its peak and tilting the fit.
        points = [(_days_ago(88), 99.0), (_days_ago(3), 10.0)]
        assert _weekly_peaks(_window(points, lookback_days=90)) == [(0, 10.0)]


# ---------------------------------------------------------------------------
# res-quota-config-001
# ---------------------------------------------------------------------------


class TestConfigurationQuotaUtilization:
    def _run(self, context, api):
        _wire(context.aws_client_factory, api)
        return ConfigurationQuotaUtilizationCheck().execute(context)

    def test_passes_with_headroom(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": [{}] * 5},
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert finding.evidence["measured"]["users"]["utilization_pct"] == 2.0

    def test_fails_when_a_quota_is_nearly_consumed(self, check_context):
        _populate(check_context.instance, queues=210)  # 210 / 250 = 84%
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.FAIL
        assert finding.severity is Severity.MEDIUM
        assert finding.evidence["measured"]["queues"]["utilization_pct"] == 84.0

    def test_severity_escalates_past_critical_threshold(self, check_context):
        _populate(check_context.instance, queues=245)  # 98%
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.FAIL
        assert finding.severity is Severity.HIGH

    def test_empty_collection_is_unmeasured_not_zero(self, check_context):
        # Reporting 0 queues as 0% utilization would be a false PASS on the one
        # instance whose discovery data is missing.
        _populate(check_context.instance, queues=0)
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert "queues" in finding.evidence["unmeasured_resources"]
        assert "queues" not in finding.evidence["measured"]

    def test_denied_phone_number_read_does_not_discard_other_subjects(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2=ACCESS_DENIED,
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert "phone_numbers" in finding.evidence["unmeasured_resources"]
        assert "queues" in finding.evidence["measured"]

    def test_phone_count_unmeasured_when_traffic_distribution_group_present(self, check_context):
        # ListPhoneNumbersV2 against an instance ARN omits numbers claimed to a
        # traffic distribution group, so on an ACGR instance the count is a lower
        # bound. Comparing it would report headroom that may not exist, so the
        # subject is dropped as unmeasured — the other subjects still stand.
        _populate(check_context.instance)
        api = _Api(
            **{
                **_quota_responses(),
                "list_traffic_distribution_groups": {
                    "TrafficDistributionGroupSummaryList": [{"Id": "tdg-1"}]
                },
            },
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": [{}] * 5},
        )
        finding = self._run(check_context, api)
        assert "phone_numbers" not in finding.evidence["measured"]
        assert "phone_numbers" in finding.evidence["unmeasured_resources"]
        assert finding.evidence["unmeasured_reasons"]["phone_numbers"].startswith(
            "count_incomplete"
        )
        assert "queues" in finding.evidence["measured"]

    def test_denied_tdg_listing_keeps_the_instance_phone_count(self, check_context):
        # A denied or unavailable TDG listing cannot confirm ACGR is in use, so
        # the instance-scoped count is kept rather than discarded on every
        # ordinary (no-TDG) instance that lacks the listing permission.
        _populate(check_context.instance)
        api = _Api(
            **{
                **_quota_responses(),
                "list_traffic_distribution_groups": ACCESS_DENIED,
            },
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": [{}] * 5},
        )
        finding = self._run(check_context, api)
        assert "phone_numbers" in finding.evidence["measured"]
        assert finding.evidence["measured"]["phone_numbers"]["count"] == 5

    def test_skips_when_quota_reads_denied(self, check_context):
        _populate(check_context.instance)
        api = _Api(**_quota_responses(denied="both"))
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.SKIPPED
        assert "servicequotas:ListServiceQuotas" in finding.description

    def test_skips_when_nothing_is_measurable(self, check_context):
        _populate(check_context.instance, queues=0, routing=0, security=0, flows=0)
        api = _Api(
            **_quota_responses(),
            list_users=ACCESS_DENIED,
            list_phone_numbers_v2=ACCESS_DENIED,
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.SKIPPED

    def test_unpublished_quota_is_recorded_not_assumed(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(defaults=[{"QuotaName": "Users per instance", "Value": 500.0}]),
            list_users=_users(10),
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert "queues" in finding.evidence["quotas_without_published_limit"]

    # --- user quota: counted from the API, not from instance.users -----------

    def test_users_are_counted_from_list_users_not_the_instance_model(self, check_context):
        # The regression this pins: no analyzer populates instance.users, so
        # deriving the count from it reported the users quota as unmeasured on
        # every real run. The instance is left exactly as the pipeline leaves it.
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=_users(40),  # 40 / 500 = 8%
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert not check_context.instance.users
        assert finding.evidence["measured"]["users"]["count"] == 40
        assert finding.evidence["measured"]["users"]["utilization_pct"] == 8.0
        assert "users" not in finding.evidence["unmeasured_resources"]
        assert api.kwargs_for("list_users")["InstanceId"] == check_context.instance.instance_id

    def test_user_count_is_paginated(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=[_users(100, next_token="p2"), _users(60)],  # nosec B106
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        # 160 of 500 users, reached only by following the continuation token.
        assert finding.evidence["measured"]["users"]["count"] == 160
        assert finding.evidence["measured"]["users"]["utilization_pct"] == 32.0
        user_calls = [c for c in api.calls_with_kwargs if c["operation"] == "list_users"]
        assert len(user_calls) == 2
        assert user_calls[1]["kwargs"]["NextToken"] == "p2"

    def test_denied_user_read_is_unmeasured_not_zero(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=ACCESS_DENIED,
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": [{}] * 5},
        )
        finding = self._run(check_context, api)
        assert "users" in finding.evidence["unmeasured_resources"]
        assert "users" not in finding.evidence["measured"]
        assert finding.evidence["unmeasured_reasons"]["users"] == "access_denied"
        # A denied user read must not discard the subjects still measurable.
        assert "queues" in finding.evidence["measured"]
        assert "phone_numbers" in finding.evidence["measured"]

    # --- a bounded page pull that ran out of pages is a lower bound, and a
    # lower bound over a quota is a utilization figure that can only be too
    # low — the direction that turns a breach into a PASS. ---

    def test_exhausted_page_limit_is_unmeasured_not_a_total(self, check_context):
        _populate(check_context.instance)
        # Every one of the 20 permitted pages is full and still carries a token:
        # 2,000 users counted, an unknown number unread. Reported as 2,000 of a
        # 4,000 quota this is 50% and a PASS; the instance could be at 88%.
        api = _Api(
            **_quota_responses(),
            list_users=[_users(100, next_token="more")] * 21,  # nosec B106
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert "users" not in finding.evidence["measured"]
        assert "users" in finding.evidence["unmeasured_resources"]
        assert finding.evidence["unmeasured_reasons"]["users"].startswith("count_incomplete")
        assert "connect:ListUsers" in finding.evidence["unmeasured_reasons"]["users"]
        # The subjects that were fully read are still assessed.
        assert "queues" in finding.evidence["measured"]

    def test_final_page_without_a_token_is_a_complete_count(self, check_context):
        _populate(check_context.instance)
        # The bound itself is fine. Exactly 20 pages where the last one carries
        # no token is a finished collection, not a truncated one.
        api = _Api(
            **_quota_responses(defaults=[{"QuotaName": "Users per instance", "Value": 4000.0}]),
            list_users=[_users(100, next_token=f"p{i}") for i in range(19)] + [_users(100)],
            list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
        )
        finding = self._run(check_context, api)
        assert finding.evidence["measured"]["users"]["count"] == 2000
        assert "users" not in finding.evidence["unmeasured_resources"]

    def test_truncated_phone_number_count_is_unmeasured(self, check_context):
        _populate(check_context.instance)
        api = _Api(
            **_quota_responses(),
            list_users=_users(10),
            list_phone_numbers_v2=[{"ListPhoneNumbersSummaryList": [{}] * 100, "NextToken": "more"}]
            * 21,
        )
        finding = self._run(check_context, api)
        assert "phone_numbers" not in finding.evidence["measured"]
        assert finding.evidence["unmeasured_reasons"]["phone_numbers"].startswith(
            "count_incomplete"
        )

    # --- instance scoping, end to end ---------------------------------------

    def test_two_instances_in_one_region_use_their_own_quotas(
        self, make_check_context, sample_connect_instance
    ):
        import copy

        raised = copy.deepcopy(sample_connect_instance)
        raised.instance_id, raised.instance_arn = "instance-b", ARN_B
        default = copy.deepcopy(sample_connect_instance)
        default.instance_id, default.instance_arn = "instance-a", ARN_A

        applied = [
            {
                "QuotaName": "Users per instance",
                "Value": 5000.0,
                "QuotaContext": {"ContextId": ARN_B},
            }
        ]
        findings = {}
        for instance in (raised, default):
            _populate(instance)
            context = make_check_context(instance=instance)
            api = _Api(
                **_quota_responses(applied=applied),
                list_users=_users(50),
                list_phone_numbers_v2={"ListPhoneNumbersSummaryList": []},
            )
            findings[instance.instance_id] = self._run(context, api)

        # 50 users against 5,000 on the instance whose ceiling was raised, and
        # against the 500 default on the one that was not. A single regional
        # value reported both at whichever figure was read last.
        assert findings["instance-b"].evidence["measured"]["users"]["quota_value"] == 5000.0
        assert findings["instance-a"].evidence["measured"]["users"]["quota_value"] == 500.0
        assert findings["instance-b"].evidence["measured"]["users"]["utilization_pct"] == 1.0
        assert findings["instance-a"].evidence["measured"]["users"]["utilization_pct"] == 10.0


# ---------------------------------------------------------------------------
# res-quota-headroom-001
# ---------------------------------------------------------------------------


class TestConcurrentCallsHeadroom:
    def _run(self, context, api):
        _wire(context.aws_client_factory, api)
        return ConcurrentCallsHeadroomCheck().execute(context)

    def test_passes_with_headroom(self, check_context):
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response([(_days_ago(2), 40.0)]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert finding.evidence["utilization_pct"] == 40.0

    def test_fails_near_the_ceiling(self, check_context):
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response([(_days_ago(5), 60.0), (_days_ago(2), 85.0)]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.FAIL
        assert finding.severity is Severity.HIGH
        assert finding.evidence["peak_concurrent_calls"] == 85.0

    def test_critical_at_the_ceiling(self, check_context):
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response([(_days_ago(1), 99.0)]),
        )
        finding = self._run(check_context, api)
        assert finding.severity is Severity.CRITICAL

    def test_not_applicable_without_traffic(self, check_context):
        api = _Api(**_quota_responses(), get_metric_statistics=_metric_response([]))
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.NOT_APPLICABLE

    def test_not_applicable_when_quota_unpublished(self, check_context):
        api = _Api(**_quota_responses(defaults=[{"QuotaName": "Users per instance", "Value": 5.0}]))
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.NOT_APPLICABLE

    def test_skips_when_metrics_denied(self, check_context):
        api = _Api(**_quota_responses(), get_metric_statistics=ACCESS_DENIED)
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.SKIPPED
        assert "cloudwatch:GetMetricStatistics" in finding.description

    def test_metric_query_names_both_dimensions(self, check_context):
        # Connect publishes ConcurrentCalls under InstanceId *and* MetricGroup,
        # and CloudWatch keys every metric on its complete dimension set. A
        # one-dimension query matches no metric and returns no datapoints, which
        # this check would then report as "no measurable call traffic" on a busy
        # instance. Asserted on the request because a double that answers any
        # argument list cannot catch this.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response([(_days_ago(2), 40.0)]),
        )
        self._run(check_context, api)
        kwargs = api.kwargs_for("get_metric_statistics")
        assert kwargs["Namespace"] == "AWS/Connect"
        assert kwargs["MetricName"] == "ConcurrentCalls"
        assert kwargs["Dimensions"] == [
            {"Name": "InstanceId", "Value": check_context.instance.instance_id},
            {"Name": "MetricGroup", "Value": "VoiceCalls"},
        ]


# ---------------------------------------------------------------------------
# res-quota-growth-001
# ---------------------------------------------------------------------------


class TestCallVolumeGrowthTrend:
    def _run(self, context, api):
        _wire(context.aws_client_factory, api)
        return CallVolumeGrowthTrendCheck().execute(context)

    @staticmethod
    def _weekly(values):
        """One datapoint per week, oldest first, so bucketing is unambiguous."""
        return _metric_response(
            [(_days_ago(7 * (len(values) - 1 - i)), float(v)) for i, v in enumerate(values)]
        )

    def test_passes_when_flat(self, check_context):
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=self._weekly([20, 20, 20, 20, 20]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert finding.evidence["growth_calls_per_week"] == 0.0

    def test_passes_when_declining(self, check_context):
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=self._weekly([50, 45, 40, 35, 30]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert finding.evidence["growth_calls_per_week"] < 0

    def test_fails_when_quota_is_within_the_horizon(self, check_context):
        # Growing 10/week from 60, quota 100 => ~4 weeks of runway.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=self._weekly([30, 40, 50, 60]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.FAIL
        assert finding.severity is Severity.HIGH
        assert finding.evidence["projected_weeks_to_quota"] == pytest.approx(4.0, abs=0.5)

    def test_passes_when_growth_is_beyond_the_horizon(self, check_context):
        # Growing 0.1/week from 20 against a 100-call quota is centuries away.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=self._weekly([20.0, 20.1, 20.2, 20.3, 20.4]),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.PASS
        assert finding.evidence["projected_weeks_to_quota"] > 26

    def test_not_applicable_with_too_little_history(self, check_context):
        api = _Api(**_quota_responses(), get_metric_statistics=self._weekly([10, 20]))
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.NOT_APPLICABLE

    def test_skips_when_metrics_denied(self, check_context):
        api = _Api(**_quota_responses(), get_metric_statistics=ACCESS_DENIED)
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.SKIPPED

    def test_gaps_between_weeks_do_not_inflate_the_growth_rate(self, check_context):
        # Peaks of 10/20/30/40 at weeks 0, 3, 6 and 9. Treating them as four
        # consecutive weeks reported 10 calls/week and about 6 weeks of runway,
        # inside the horizon and High severity. The real rate is ~3.33/week and
        # about 18 weeks, still inside the horizon but not the same finding.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response(
                [
                    (_days_ago(63), 10.0),
                    (_days_ago(42), 20.0),
                    (_days_ago(21), 30.0),
                    (_days_ago(0), 40.0),
                ]
            ),
        )
        finding = self._run(check_context, api)
        assert finding.evidence["growth_calls_per_week"] == pytest.approx(3.33, abs=0.01)
        assert finding.evidence["weeks_observed"] == 4
        assert finding.evidence["weeks_spanned"] == 10
        assert finding.evidence["weekly_peaks"] == [
            {"week_index": 0, "peak": 10.0},
            {"week_index": 3, "peak": 20.0},
            {"week_index": 6, "peak": 30.0},
            {"week_index": 9, "peak": 40.0},
        ]
        assert finding.evidence["projected_weeks_to_quota"] == pytest.approx(18.0, abs=0.5)

    def test_stale_history_is_not_projected_as_a_current_forecast(self, check_context):
        # Four rising peaks that stop eight weeks ago, then silence. The trend is
        # real but it is not running: projecting "the quota is reached in about
        # six weeks" from a two-month-old peak names a deadline in the past.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response(
                [
                    (_days_ago(77), 63.0),
                    (_days_ago(70), 70.0),
                    (_days_ago(63), 77.0),
                    (_days_ago(56), 84.0),
                ]
            ),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.NOT_APPLICABLE
        assert finding.evidence["latest_datapoint_age_days"] == 56
        assert len(finding.evidence["weekly_peaks"]) == 4
        assert finding.evidence["staleness_tolerance_days"] == 14
        assert "projected_weeks_to_quota" not in finding.evidence

    def test_one_missing_week_is_still_a_current_forecast(self, check_context):
        # The tolerance is two buckets, because CloudWatch routinely returns no
        # datapoint for a single quiet week. That must not suppress the check.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response(
                [
                    (_days_ago(28), 30.0),
                    (_days_ago(21), 40.0),
                    (_days_ago(14), 50.0),
                    (_days_ago(7), 60.0),
                ]
            ),
        )
        finding = self._run(check_context, api)
        assert finding.status is CheckStatus.FAIL
        assert finding.evidence["latest_datapoint_age_days"] == 7

    def test_a_quiet_final_week_does_not_extend_the_runway(self, check_context):
        # Five weeks climbing 10/week to 70, then a final week that drops to 20
        # — a holiday, an outage, a partial bucket. Anchoring the projection on
        # that raw 20 reports 80 calls of headroom against the 100-call quota
        # and moves the instance out of the horizon; the fitted level at the
        # latest week keeps it in.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=self._weekly([30, 40, 50, 60, 70, 20]),
        )
        finding = self._run(check_context, api)
        assert finding.evidence["latest_weekly_peak"] == 20.0
        # The fit still slopes up, so the baseline sits well above the dip.
        assert finding.evidence["trend_value_at_latest_week"] > 20.0
        assert finding.evidence["growth_calls_per_week"] > 0

    def test_projection_divides_by_the_raw_slope_not_the_rounded_one(self, check_context):
        # Peaks of 20/22.5/25/27.5 at weeks 0, 3, 6 and 9 fit a slope of 0.8333
        # calls/week and a latest fitted level of 27.5, leaving 72.5 of the
        # 100-call quota. The runway is 72.5 / 0.8333 = 87.0 weeks. Dividing by
        # the two-decimal display slope (0.83) instead gives 87.3 — a skew that
        # grows as the slope shrinks and can flip a finding at the horizon or
        # severity boundary. The displayed rate is still rounded; only the
        # projection must use the raw slope.
        api = _Api(
            **_quota_responses(),
            get_metric_statistics=_metric_response(
                [
                    (_days_ago(63), 20.0),
                    (_days_ago(42), 22.5),
                    (_days_ago(21), 25.0),
                    (_days_ago(0), 27.5),
                ]
            ),
        )
        finding = self._run(check_context, api)
        assert finding.evidence["growth_calls_per_week"] == 0.83
        # 87.0 (raw) is inside pytest's window; 87.3 (rounded slope) is not.
        assert finding.evidence["projected_weeks_to_quota"] == pytest.approx(87.0, abs=0.1)


class TestRegistration:
    def test_all_three_checks_register_under_resilience(self):
        registry = CheckRegistry()
        register_capacity_checks(registry)
        checks = registry.get_all_checks()
        assert {c.check_id for c in checks} == {
            "res-quota-config-001",
            "res-quota-headroom-001",
            "res-quota-growth-001",
        }
        # Well-Architected REL01 owns quota management, so these belong to
        # Resilience rather than to a separate capacity pillar.
        assert {c.pillar.value for c in checks} == {"resilience"}
