"""Focused tests for the Increment 2A atomic control catalog."""

from collections import Counter
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from amazon_connect_assessment.checks.control_registry import (
    AtomicControl,
    AtomicControlRegistry,
    ExecutionSource,
    get_atomic_control_registry,
)
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import FindingDisposition, FindingMethodology


def _catalog_controls() -> tuple[AtomicControl, ...]:
    return get_atomic_control_registry().controls


def test_atomic_catalog_current_inventory_has_exact_approved_totals():
    # Arrange
    registry = get_atomic_control_registry()

    # Act
    disposition_counts = Counter(control.disposition for control in registry)

    # Assert
    assert len(registry) == 64
    assert disposition_counts == {
        FindingDisposition.CONTROL: 23,
        FindingDisposition.MANUAL_REVIEW: 25,
        FindingDisposition.INFORMATIONAL: 16,
    }


def test_atomic_catalog_every_canonical_control_has_complete_specific_methodology():
    # Arrange
    registry = get_atomic_control_registry()
    methodology_fields = (
        "reason",
        "evidence_source",
        "proof_limitations",
        "developer_admin_meaning",
        "verification_criteria",
    )

    # Act
    missing = [
        (control.control_id, field_name)
        for control in registry
        for field_name in methodology_fields
        if not getattr(control.methodology, field_name).strip()
    ]
    methodology_identities = {
        (
            control.methodology.reason,
            control.methodology.evidence_source,
            control.methodology.proof_limitations,
            control.methodology.developer_admin_meaning,
            control.methodology.verification_criteria,
        )
        for control in registry
    }

    # Assert
    assert missing == []
    assert len(methodology_identities) == 64


def test_atomic_catalog_root_conditions_are_unique_for_canonical_controls():
    # Arrange
    registry = get_atomic_control_registry()

    # Act
    roots = [control.root_condition_key for control in registry]

    # Assert
    assert len(roots) == 64
    assert len(set(roots)) == 64


def test_atomic_catalog_legacy_aliases_resolve_and_deduplicate_canonical_selection():
    # Arrange
    registry = get_atomic_control_registry()
    requested_ids = [
        "journey-sec-001",
        "sec-flow-auth-001",
        "journey-cost-001",
        "cost-containment-001",
    ]

    # Act
    selected = registry.select(requested_ids)

    # Assert
    assert registry.resolve_id("journey-sec-001") == "sec-flow-auth-001"
    assert registry.resolve_id("journey-cost-001") == "cost-containment-001"
    assert [control.control_id for control in selected] == [
        "sec-flow-auth-001",
        "cost-containment-001",
    ]
    assert "journey-sec-001" not in {control.control_id for control in registry}
    assert "journey-cost-001" not in {control.control_id for control in registry}


def test_atomic_catalog_error_routing_ownership_is_exact():
    # Arrange
    registry = get_atomic_control_registry()

    # Act
    flow_control = registry.get("res-flow-errors-001")
    lambda_control = registry.get("res-lambda-dependency-001")

    # Assert
    assert flow_control.name == "Non-Lambda Error Routing Completeness"
    assert flow_control.root_condition_key == "connect.flow.non_lambda_error_transition_missing"
    assert "Lambda actions are excluded" in flow_control.methodology.evidence_source
    assert "without a tolerance threshold" in flow_control.methodology.developer_admin_meaning
    assert lambda_control.name == "Lambda Error Routing Completeness"
    assert lambda_control.root_condition_key == "connect.flow.lambda_error_transition_missing"
    assert "GetFunction/VPC data add context only" in lambda_control.methodology.evidence_source
    assert "regardless of target resolution" in lambda_control.methodology.developer_admin_meaning
    assert flow_control.root_condition_key != lambda_control.root_condition_key


def test_atomic_catalog_records_and_registry_views_are_immutable():
    # Arrange
    registry = get_atomic_control_registry()
    control = registry.get("security-iam-001")

    # Act / Assert
    with pytest.raises(FrozenInstanceError):
        control.name = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        registry.aliases["new-alias"] = "security-iam-001"  # type: ignore[index]
    with pytest.raises(AttributeError, match="immutable"):
        registry._controls = ()  # type: ignore[attr-defined]


def test_atomic_catalog_duplicate_canonical_id_is_rejected():
    # Arrange
    first, second = _catalog_controls()[:2]
    duplicate = replace(second, control_id=first.control_id)

    # Act / Assert
    with pytest.raises(ValueError, match="Duplicate canonical control ID"):
        AtomicControlRegistry((first, duplicate))


def test_atomic_catalog_alias_collision_with_canonical_id_is_rejected():
    # Arrange
    first, second = _catalog_controls()[:2]
    colliding = replace(second, legacy_aliases=(first.control_id,))

    # Act / Assert
    with pytest.raises(ValueError, match="Alias collides with canonical"):
        AtomicControlRegistry((first, colliding))


def test_atomic_catalog_alias_owned_by_multiple_controls_is_rejected():
    # Arrange
    first, second = _catalog_controls()[:2]
    first_with_alias = replace(first, legacy_aliases=("old-check-id",))
    second_with_alias = replace(second, legacy_aliases=("old-check-id",))

    # Act / Assert
    with pytest.raises(ValueError, match="Alias is owned by multiple controls"):
        AtomicControlRegistry((first_with_alias, second_with_alias))


def test_atomic_catalog_duplicate_root_condition_ownership_is_rejected():
    # Arrange
    first, second = _catalog_controls()[:2]
    duplicate_root = replace(second, root_condition_key=first.root_condition_key)

    # Act / Assert
    with pytest.raises(ValueError, match="Duplicate root condition ownership"):
        AtomicControlRegistry((first, duplicate_root))


def test_atomic_catalog_primary_lens_repeated_as_secondary_is_rejected():
    # Arrange
    control = _catalog_controls()[0]
    methodology = replace(control.methodology, primary_lens_reference="SEC-1")
    duplicate_lens = replace(
        control,
        methodology=methodology,
        secondary_lens_references=("SEC-1",),
    )

    # Act / Assert
    with pytest.raises(ValueError, match="repeats its primary lens"):
        AtomicControlRegistry((duplicate_lens,))


def test_atomic_catalog_blank_methodology_field_is_rejected():
    # Arrange
    control = _catalog_controls()[0]
    incomplete_methodology = replace(control.methodology, proof_limitations="  ")
    incomplete = replace(control, methodology=incomplete_methodology)

    # Act / Assert
    with pytest.raises(ValueError, match="blank methodology.proof_limitations"):
        AtomicControlRegistry((incomplete,))


def test_atomic_catalog_executor_source_mismatch_is_rejected():
    # Arrange
    control = _catalog_controls()[0]
    mismatched = replace(control, execution_source=ExecutionSource.JOURNEY)

    # Act / Assert
    with pytest.raises(ValueError, match="mismatched Journey executor metadata"):
        AtomicControlRegistry((mismatched,))


def test_atomic_catalog_all_registered_base_checks_are_hydrated_from_catalog():
    # Arrange
    catalog = get_atomic_control_registry()
    registry = CheckRegistry()

    # Act
    register_all_checks(registry)

    # Assert
    assert len(registry) == 60
    for check in registry.get_all_checks():
        control = catalog.get(check.check_id)
        executor_key = f"{type(check).__module__}.{type(check).__qualname__}"
        assert check.disposition == control.disposition
        assert check.methodology is control.methodology
        assert check.pillar == control.pillar
        assert check.severity == control.default_severity
        assert executor_key == control.executor_key


def test_atomic_catalog_public_metadata_has_no_customer_owner_or_team_fields():
    # Arrange
    atomic_fields = {field.name for field in fields(AtomicControl)}
    methodology_fields = {field.name for field in fields(FindingMethodology)}

    # Act
    prohibited_atomic = atomic_fields & {"owner", "team", "customer_owner", "customer_team"}
    prohibited_methodology = methodology_fields & {
        "owner",
        "team",
        "customer_owner",
        "customer_team",
    }

    # Assert
    assert prohibited_atomic == set()
    assert prohibited_methodology == set()
    assert "responsible_function" in methodology_fields


def test_atomic_catalog_base_check_metadata_mismatch_is_rejected_before_hydration():
    # Arrange
    catalog = get_atomic_control_registry()
    registry = CheckRegistry()
    register_all_checks(registry)
    checks = registry.get_all_checks()
    check = registry.get_check("security-iam-001")
    check.severity = catalog.get("security-data-001").default_severity

    # Act / Assert
    with pytest.raises(ValueError, match="Executor metadata mismatch.*severity"):
        catalog.hydrate_base_checks(checks)


def test_atomic_catalog_execution_sources_match_increment_2b_expected_result():
    # Arrange
    registry = get_atomic_control_registry()

    # Act
    source_ids = {
        source: {control.control_id for control in registry if control.execution_source == source}
        for source in ExecutionSource
    }

    # Assert
    assert len(source_ids[ExecutionSource.BASE_CHECK]) == 60
    assert source_ids[ExecutionSource.JOURNEY] == {
        "sec-flow-auth-001",
        "cost-containment-001",
        "journey-res-001",
        "journey-scope-001",
    }


def test_atomic_control_registry_hardcoded_routing_requires_flow_analysis_expected_result():
    # Arrange
    registry = get_atomic_control_registry()

    # Act
    control = registry.get("res-hardcoded-routing-001")

    # Assert
    assert control.requires_flow_analysis is True
