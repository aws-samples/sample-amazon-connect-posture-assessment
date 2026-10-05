"""Central registration and canonical control selection."""

import logging
from typing import Any, Mapping, Optional, Set

from ..models import Severity
from .control_registry import ExecutionSource, get_atomic_control_registry
from .registry import CheckRegistry

logger = logging.getLogger("check_registration")


class UnknownControlSelectionError(ValueError):
    """Raised when an explicit control selection contains unknown IDs."""


def _normalize_ids(
    control_ids: Optional[Set[str]],
) -> Optional[set[str]]:
    """Resolve an explicit selection to canonical IDs without dropping typos."""
    if not control_ids:
        return None
    normalized: set[str] = set()
    unknown: set[str] = set()
    catalog = get_atomic_control_registry()
    for requested_id in control_ids:
        try:
            normalized.add(catalog.resolve_id(requested_id))
        except KeyError:
            unknown.add(requested_id)
    if unknown:
        raise UnknownControlSelectionError(
            f"Unknown check ID(s): {', '.join(sorted(unknown))}; run --list-checks to see valid IDs"
        )
    return normalized


def _normalize_config(
    checks_config: Optional[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    catalog = get_atomic_control_registry()
    normalized: dict[str, Mapping[str, Any]] = {}
    for requested_id, value in (checks_config or {}).items():
        if not isinstance(value, Mapping):
            logger.warning("Config for control '%s' must be an object; ignoring it", requested_id)
            continue
        try:
            canonical_id = catalog.resolve_id(requested_id)
        except KeyError:
            logger.warning("Config references unknown control '%s'; ignoring it", requested_id)
            continue
        normalized[canonical_id] = value
    return normalized


def apply_live_check_config(
    registry: CheckRegistry,
    checks_config: Optional[Mapping[str, Any]],
) -> None:
    """Apply compatibility overrides to an already-built live registry."""
    if not checks_config:
        return

    normalized_config = _normalize_config(checks_config)
    disabled_count = 0
    severity_override_count = 0
    catalog = registry.get_atomic_control_registry() or get_atomic_control_registry()

    for control_id, control_config in normalized_config.items():
        control = catalog.get(control_id)
        enabled = control_config.get("enabled", True)
        if enabled is False:
            if control_id in registry:
                registry.unregister_check(control_id)
            else:
                registry._remove_selected_control(control_id)
            disabled_count += 1
            continue
        if not isinstance(enabled, bool):
            registry.logger.warning(
                "Ignoring non-boolean enabled override for control '%s'", control_id
            )

        severity_name = control_config.get("severity")
        if severity_name:
            try:
                new_severity = Severity(str(severity_name).lower())
            except ValueError:
                registry.logger.warning(
                    "Ignoring invalid severity override '%s' for control '%s'; must be one of %s",
                    severity_name,
                    control_id,
                    [severity.value for severity in Severity],
                )
            else:
                if control.execution_source == ExecutionSource.JOURNEY:
                    registry.logger.warning(
                        "Severity override for Journey control '%s' is not supported; "
                        "using catalog severity '%s'.",
                        control_id,
                        control.default_severity.value,
                    )
                elif registry._override_base_check_severity(control_id, new_severity):
                    severity_override_count += 1

        unsupported_keys = set(control_config) - {"enabled", "severity"}
        if unsupported_keys:
            registry.logger.warning(
                "Control '%s' config has unsupported override key(s) %s; only 'enabled' "
                "and BaseCheck 'severity' are currently applied.",
                control_id,
                sorted(unsupported_keys),
            )

    registry.logger.info(
        "Configuration overrides applied: %d control(s) disabled, %d severity override(s)",
        disabled_count,
        severity_override_count,
    )


def register_all_checks(
    registry: CheckRegistry,
    pillars: Optional[Set[str]] = None,
    severities: Optional[Set[str]] = None,
    check_ids: Optional[Set[str]] = None,
    exclude_check_ids: Optional[Set[str]] = None,
    skip_flow_analysis: bool = False,
    checks_config: Optional[Mapping[str, Any]] = None,
) -> None:
    """Register BaseChecks and store one catalog-derived canonical execution plan.

    Selection uses AND semantics in this order: flow-analysis availability,
    pillar, effective declared severity, explicit inclusion, exclusion, and
    config disablement. IDs and legacy aliases are normalized before filtering.
    """
    from .acxd_checks import register_acxd_checks
    from .ai_agent_security_checks import register_ai_agent_security_checks
    from .ai_ops_maturity_checks import register_ai_ops_maturity_checks
    from .capacity_checks import register_capacity_checks
    from .contact_flow_behavior_checks import register_contact_flow_behavior_checks
    from .contact_flow_security_checks import register_contact_flow_security_checks
    from .cost_containment_checks import register_cost_containment_checks
    from .cost_intelligence_checks import register_cost_intelligence_checks
    from .lex_security_checks import register_lex_security_checks
    from .mvp_checks import register_mvp_checks
    from .operational_excellence_checks import register_operational_excellence_checks
    from .performance_efficiency_checks import register_performance_efficiency_checks
    from .resilience_advanced_checks import register_advanced_resilience_checks
    from .security_deep_checks import register_security_deep_checks

    register_mvp_checks(registry)
    register_security_deep_checks(registry)
    register_cost_intelligence_checks(registry)
    register_operational_excellence_checks(registry)
    register_ai_ops_maturity_checks(registry)
    register_lex_security_checks(registry)
    register_capacity_checks(registry)
    register_advanced_resilience_checks(registry, include_flow_checks=not skip_flow_analysis)
    register_cost_containment_checks(registry, include_flow_checks=not skip_flow_analysis)
    if skip_flow_analysis and "res-hardcoded-routing-001" in registry:
        registry.unregister_check("res-hardcoded-routing-001")

    if not skip_flow_analysis:
        register_acxd_checks(registry)
        register_contact_flow_security_checks(registry)
        register_ai_agent_security_checks(registry)
        register_contact_flow_behavior_checks(registry)
        register_performance_efficiency_checks(registry)
    else:
        logger.info("Skipping flow-analysis checks (--skip-flow-analysis)")

    catalog = get_atomic_control_registry()
    catalog.hydrate_base_checks(
        registry.get_all_checks(), include_flow_analysis=not skip_flow_analysis
    )
    registry.set_atomic_control_registry(catalog)

    included_ids = _normalize_ids(check_ids)
    excluded_ids = _normalize_ids(exclude_check_ids) or set()
    normalized_config = _normalize_config(checks_config)

    effective_severities = {
        control.control_id: control.default_severity for control in catalog.controls
    }
    for control_id, control_config in normalized_config.items():
        severity_name = control_config.get("severity")
        if severity_name:
            try:
                configured_severity = Severity(str(severity_name).lower())
            except ValueError:
                logger.warning(
                    "Ignoring invalid severity override '%s' for control '%s'; must be one of %s",
                    severity_name,
                    control_id,
                    [severity.value for severity in Severity],
                )
            else:
                control = catalog.get(control_id)
                if control.execution_source == ExecutionSource.JOURNEY:
                    logger.warning(
                        "Severity override for Journey control '%s' is not supported; "
                        "using catalog severity '%s'.",
                        control_id,
                        control.default_severity.value,
                    )
                else:
                    effective_severities[control_id] = configured_severity
                    registry._override_base_check_severity(control_id, configured_severity)

        unsupported_keys = set(control_config) - {"enabled", "severity"}
        if unsupported_keys:
            logger.warning(
                "Control '%s' config has unsupported override key(s) %s; only 'enabled' "
                "and BaseCheck 'severity' are currently applied.",
                control_id,
                sorted(unsupported_keys),
            )

    selected_ids: list[str] = []
    for control in catalog.controls:
        control_id = control.control_id
        if skip_flow_analysis and control.requires_flow_analysis:
            continue
        if pillars and control.pillar.value not in pillars:
            continue
        if severities and effective_severities[control_id].value not in severities:
            continue
        if included_ids is not None and control_id not in included_ids:
            continue
        if control_id in excluded_ids:
            continue
        if not normalized_config.get(control_id, {}).get("enabled", True):
            continue
        selected_ids.append(control_id)

    registry.set_selected_controls(selected_ids)
    selected_base_ids = {
        control_id
        for control_id in selected_ids
        if catalog.get(control_id).execution_source == ExecutionSource.BASE_CHECK
    }
    for check in registry.get_all_checks():
        if check.check_id not in selected_base_ids:
            registry.unregister_check(check.check_id)

    if included_ids is not None:
        missing = included_ids - set(selected_ids)
        if missing:
            logger.warning(
                "Requested control ID(s) not selected after all filters: %s", sorted(missing)
            )

    logger.info(
        "Selected %d canonical controls (%d BaseCheck, %d Journey)",
        len(registry.list_control_ids()),
        len(registry.list_check_ids()),
        len(registry.list_selected_journey_control_ids()),
    )
