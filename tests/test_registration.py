"""
Integration tests for check registration (Task 14).

Verifies:
- All checks register without error and hit an expected minimum count
- Pillar filtering works
- skip_flow_analysis flag works
- Original 10 MVP checks are always present (backward compat)
"""

from unittest.mock import patch

from amazon_connect_assessment.checks.mvp_checks import get_mvp_checks
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry


def test_register_all_checks_meets_expected_count():
    # Use a floor rather than an exact count so growing the catalog doesn't
    # require touching this test on every addition. If the count drops
    # below the floor, something has been silently unregistered.
    # 55 before the Multi-AZ / DR removals, 53 before FailoverMechanism,
    # 52 before NetworkSecurityCheck + EncryptionConfigurationCheck. Floor
    # of 50 reflects the current baseline. See security_checks.py and
    # resilience_checks (deleted) module docstrings for what and why.
    registry = CheckRegistry()
    register_all_checks(registry)
    assert len(registry) >= 50


def test_original_10_mvp_checks_present():
    registry = CheckRegistry()
    register_all_checks(registry)
    mvp_ids = {c.check_id for c in get_mvp_checks()}
    registered_ids = set(registry.list_check_ids())
    assert mvp_ids <= registered_ids


def test_pillar_filter_security_only():
    registry = CheckRegistry()
    register_all_checks(registry, pillars={"security"})
    for check in registry.get_all_checks():
        assert check.pillar.value == "security"
    assert len(registry) > 0


def test_pillar_filter_excludes_others():
    registry = CheckRegistry()
    register_all_checks(registry, pillars={"resilience", "cost_optimization"})
    for check in registry.get_all_checks():
        assert check.pillar.value in ("resilience", "cost_optimization")


def test_skip_flow_analysis_reduces_count():
    full = CheckRegistry()
    register_all_checks(full)

    skipped = CheckRegistry()
    register_all_checks(skipped, skip_flow_analysis=True)

    assert len(skipped) < len(full)
    # The flow-analysis modules contain checks that are absent.
    assert "sec-prompt-inject-001" not in skipped
    assert "perf-lambda-count-001" not in skipped
    assert "ops-acxd-handoff-001" not in skipped
    assert "ops-acxd-escalation-001" not in skipped
    assert "res-acxd-error-routing-001" not in skipped
    # Instance-level checks still present.
    assert "sec-iam-deep-001" in skipped
    assert "ops-logging-001" in skipped


def test_unregister_check():
    registry = CheckRegistry()
    register_all_checks(registry)
    assert "ops-logging-001" in registry
    registry.unregister_check("ops-logging-001")
    assert "ops-logging-001" not in registry


# ---------------------------------------------------------------------------
# Regression tests: --severity / --checks / --exclude-checks used to be
# parsed by the CLI, stored in config, and then never applied — registration
# only respected pillars and skip_flow_analysis. A smoke run of
# `--severity critical --list-checks` or `--checks security-encryption-001
# --list-checks` still listed every registered check. register_all_checks
# now accepts severities/check_ids/exclude_check_ids and cli.py wires the
# CLI args through to them.
# ---------------------------------------------------------------------------


def test_severity_filter_critical_only():
    registry = CheckRegistry()
    register_all_checks(registry, severities={"critical"})
    assert len(registry) > 0
    for check in registry.get_all_checks():
        assert check.severity.value == "critical"


def test_severity_filter_excludes_other_levels():
    registry = CheckRegistry()
    register_all_checks(registry, severities={"critical", "high"})
    for check in registry.get_all_checks():
        assert check.severity.value in ("critical", "high")
    # Sanity: there really are medium/low checks in the full catalog, so
    # this filter is doing real work, not vacuously passing.
    full = CheckRegistry()
    register_all_checks(full)
    full_severities = {c.severity.value for c in full.get_all_checks()}
    assert "medium" in full_severities or "low" in full_severities


def test_check_ids_allowlist_returns_only_requested_ids():
    registry = CheckRegistry()
    register_all_checks(registry, check_ids={"security-iam-001"})
    assert registry.list_check_ids() == ["security-iam-001"]


def test_check_ids_allowlist_with_multiple_ids():
    registry = CheckRegistry()
    register_all_checks(registry, check_ids={"security-iam-001", "ops-logging-001"})
    assert set(registry.list_check_ids()) == {"security-iam-001", "ops-logging-001"}


def test_exclude_check_ids_removes_specific_checks():
    registry = CheckRegistry()
    register_all_checks(registry, exclude_check_ids={"ops-logging-001"})
    assert "ops-logging-001" not in registry
    # Nothing else should have been removed.
    full = CheckRegistry()
    register_all_checks(full)
    assert len(registry) == len(full) - 1


def test_severity_and_check_ids_filters_combine_with_and_semantics():
    # This is the exact scenario the vulnerability report called out:
    # --severity critical --checks security-encryption-001 should behave
    # as "critical AND that ID", not silently apply only one filter.
    # security-encryption-001 no longer exists (removed as a noise
    # generator elsewhere), so use a real critical check plus a real
    # non-critical one to prove the AND behavior.
    registry = CheckRegistry()
    register_all_checks(
        registry,
        severities={"critical"},
        check_ids={"security-iam-001", "ops-logging-001"},
    )
    # security-iam-001 is critical and in the allowlist -> survives.
    # ops-logging-001 is not critical -> removed by the severity filter
    # even though it's in the allowlist, because severity is applied
    # before the check_ids allowlist.
    remaining = set(registry.list_check_ids())
    assert "security-iam-001" in remaining
    assert "ops-logging-001" not in remaining


def test_pillar_severity_and_exclude_all_combine():
    registry = CheckRegistry()
    register_all_checks(
        registry,
        pillars={"security"},
        severities={"critical", "high"},
        exclude_check_ids={"security-iam-001"},
    )
    for check in registry.get_all_checks():
        assert check.pillar.value == "security"
        assert check.severity.value in ("critical", "high")
    assert "security-iam-001" not in registry


def test_registration_alias_include_selects_canonical_journey_control_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(
        registry,
        check_ids={"journey-sec-001", "sec-flow-auth-001"},
    )

    # Assert
    assert registry.list_check_ids() == []
    assert registry.list_control_ids() == ["sec-flow-auth-001"]
    assert registry.list_selected_journey_control_ids() == ["sec-flow-auth-001"]


def test_registration_legacy_alias_exclusion_removes_canonical_base_check():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry, exclude_check_ids={"journey-cost-001"})

    # Assert
    assert "cost-containment-001" not in registry
    assert "journey-cost-001" not in registry.list_check_ids()


def test_registration_journey_severity_override_warns_and_keeps_catalog_expected_result():
    # Arrange
    registry = CheckRegistry()
    register_all_checks(registry)

    # Act
    with patch.object(registry.logger, "warning") as warning:
        registry.load_checks_from_config({"journey-sec-001": {"severity": "high"}})

    # Assert
    assert registry.get_control_severity("sec-flow-auth-001").value == "low"
    assert "not supported" in warning.call_args.args[0]


def test_registration_existing_filters_keep_hydrated_metadata_on_selected_checks():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(
        registry,
        pillars={"security"},
        severities={"critical", "high"},
        exclude_check_ids={"security-iam-001"},
    )

    # Assert
    assert registry.get_all_checks()
    assert all(check.pillar.value == "security" for check in registry.get_all_checks())
    assert all(check.severity.value in {"critical", "high"} for check in registry.get_all_checks())
    assert all(check.methodology is not None for check in registry.get_all_checks())


def test_registration_acxd_controls_enabled_flow_analysis_registers_all_expected_result():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry)

    # Assert
    assert {
        "ops-acxd-handoff-001",
        "ops-acxd-escalation-001",
        "res-acxd-error-routing-001",
    } <= set(registry.list_check_ids())
