"""
Check registry system for managing assessment checks.

Provides centralized registration and discovery of assessment checks
with filtering capabilities by pillar and severity.
"""

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List, Optional

from ..models import Pillar, Severity
from .base import BaseCheck

if TYPE_CHECKING:
    from .control_registry import AtomicControl, AtomicControlRegistry


class CheckRegistry:
    """
    Registry for managing and organizing assessment checks.

    Provides centralized storage and retrieval of checks with filtering
    capabilities to support different assessment scenarios and configurations.
    """

    def __init__(self):
        """Initialize an empty check registry."""
        self._checks: Dict[str, BaseCheck] = {}
        self._checks_by_pillar: Dict[Pillar, List[BaseCheck]] = defaultdict(list)
        self._checks_by_severity: Dict[Severity, List[BaseCheck]] = defaultdict(list)
        self._atomic_control_registry: Optional[AtomicControlRegistry] = None
        self._selected_control_ids: List[str] = []
        self._selected_journey_control_ids: List[str] = []
        self.logger = logging.getLogger("check_registry")

    def set_atomic_control_registry(self, registry: "AtomicControlRegistry") -> None:
        """Attach the immutable canonical catalog used to resolve control IDs."""
        self._atomic_control_registry = registry

    def set_selected_controls(self, control_ids: List[str]) -> None:
        """Store the canonical execution plan for BaseCheck and Journey controls."""
        if self._atomic_control_registry is None:
            raise RuntimeError("Atomic control registry must be attached before selection")

        from .control_registry import ExecutionSource

        selected = self._atomic_control_registry.select(control_ids)
        self._selected_control_ids = [control.control_id for control in selected]
        self._selected_journey_control_ids = [
            control.control_id
            for control in selected
            if control.execution_source == ExecutionSource.JOURNEY
        ]

    def resolve_control_id(self, control_id: str) -> str:
        """Resolve any canonical control ID or legacy alias."""
        if self._atomic_control_registry is None:
            return control_id
        try:
            return self._atomic_control_registry.resolve_id(control_id)
        except KeyError:
            return control_id

    def resolve_check_id(self, check_id: str) -> str:
        """Backward-compatible alias for canonical control ID resolution."""
        return self.resolve_control_id(check_id)

    def register_check(self, check: BaseCheck) -> None:
        """
        Register a new assessment check.

        Args:
            check: BaseCheck instance to register

        Raises:
            ValueError: If a check with the same ID is already registered
        """
        if self._atomic_control_registry is not None:
            from .control_registry import ExecutionSource

            canonical_id = self.resolve_control_id(check.check_id)
            if canonical_id != check.check_id:
                raise ValueError(f"BaseCheck cannot register legacy alias ID '{check.check_id}'")
            try:
                control = self._atomic_control_registry.get(check.check_id)
            except KeyError:
                control = None
            if control is not None and control.execution_source != ExecutionSource.BASE_CHECK:
                raise ValueError(f"Control '{check.check_id}' is owned by the Journey executor")

        if check.check_id in self._checks:
            raise ValueError(f"Check with ID '{check.check_id}' is already registered")

        self._checks[check.check_id] = check
        self._checks_by_pillar[check.pillar].append(check)
        self._checks_by_severity[check.severity].append(check)

        self.logger.debug(f"Registered check: {check.check_id}")

    def unregister_check(self, check_id: str) -> None:
        """
        Remove a check from the registry by ID.

        Args:
            check_id: Unique identifier of the check to remove.

        Raises:
            KeyError: If no check with the given ID is registered.
        """
        canonical_id = self.resolve_check_id(check_id)
        if canonical_id not in self._checks:
            raise KeyError(f"No check registered with ID '{check_id}'")
        check = self._checks.pop(canonical_id)
        pillar_list = self._checks_by_pillar.get(check.pillar, [])
        self._checks_by_pillar[check.pillar] = [
            c for c in pillar_list if c.check_id != canonical_id
        ]
        severity_list = self._checks_by_severity.get(check.severity, [])
        self._checks_by_severity[check.severity] = [
            c for c in severity_list if c.check_id != canonical_id
        ]
        self.logger.debug(f"Unregistered check: {canonical_id}")

    def get_check(self, check_id: str) -> BaseCheck:
        """
        Retrieve a specific check by ID.

        Args:
            check_id: Unique identifier of the check

        Returns:
            BaseCheck: The requested check

        Raises:
            KeyError: If no check with the given ID is registered
        """
        canonical_id = self.resolve_check_id(check_id)
        if canonical_id not in self._checks:
            raise KeyError(f"No check registered with ID '{check_id}'")
        return self._checks[canonical_id]

    def get_all_checks(self) -> List[BaseCheck]:
        """
        Get all registered checks.

        Returns:
            List[BaseCheck]: All registered checks
        """
        return list(self._checks.values())

    def get_checks_by_pillar(self, pillar: Pillar) -> List[BaseCheck]:
        """
        Get all checks for a specific pillar.

        Args:
            pillar: AWS Well-Architected Framework pillar

        Returns:
            List[BaseCheck]: Checks for the specified pillar
        """
        return self._checks_by_pillar[pillar].copy()

    def get_checks_by_severity(self, severity: Severity) -> List[BaseCheck]:
        """
        Get all checks with a specific severity level.

        Args:
            severity: Severity level to filter by

        Returns:
            List[BaseCheck]: Checks with the specified severity
        """
        return self._checks_by_severity[severity].copy()

    def get_checks_by_pillars(self, pillars: List[Pillar]) -> List[BaseCheck]:
        """
        Get all checks for multiple pillars.

        Args:
            pillars: List of pillars to include

        Returns:
            List[BaseCheck]: Checks for any of the specified pillars
        """
        checks = []
        for pillar in pillars:
            checks.extend(self._checks_by_pillar[pillar])
        return checks

    def get_checks_by_severities(self, severities: List[Severity]) -> List[BaseCheck]:
        """
        Get all checks with any of the specified severity levels.

        Args:
            severities: List of severity levels to include

        Returns:
            List[BaseCheck]: Checks with any of the specified severities
        """
        checks = []
        for severity in severities:
            checks.extend(self._checks_by_severity[severity])
        return checks

    def get_filtered_checks(
        self,
        pillars: List[Pillar] = None,
        severities: List[Severity] = None,
        check_ids: List[str] = None,
    ) -> List[BaseCheck]:
        """
        Get checks filtered by multiple criteria.

        Args:
            pillars: Optional list of pillars to include
            severities: Optional list of severities to include
            check_ids: Optional list of specific check IDs to include

        Returns:
            List[BaseCheck]: Checks matching all specified criteria
        """
        # Start with all checks and apply every supplied criterion with AND semantics.
        candidate_checks = set(self._checks.values())

        if pillars is not None:
            pillar_checks = set()
            for pillar in pillars:
                pillar_checks.update(self._checks_by_pillar[pillar])
            candidate_checks &= pillar_checks

        if severities is not None:
            severity_checks = set()
            for severity in severities:
                severity_checks.update(self._checks_by_severity[severity])
            candidate_checks &= severity_checks

        if check_ids is not None:
            requested_ids = {self.resolve_control_id(check_id) for check_id in check_ids}
            missing = requested_ids - set(self._checks)
            for check_id in sorted(missing):
                self.logger.warning(f"Requested check ID '{check_id}' not found")
            candidate_checks = {
                check for check in candidate_checks if check.check_id in requested_ids
            }

        return [check for check in self._checks.values() if check in candidate_checks]

    def get_check_count(self) -> int:
        """
        Get the total number of registered checks.

        Returns:
            int: Number of registered checks
        """
        return len(self._checks)

    def get_pillar_counts(self) -> Dict[Pillar, int]:
        """
        Get count of checks per pillar.

        Returns:
            Dict[Pillar, int]: Count of checks for each pillar
        """
        return {pillar: len(checks) for pillar, checks in self._checks_by_pillar.items()}

    def get_severity_counts(self) -> Dict[Severity, int]:
        """
        Get count of checks per severity level.

        Returns:
            Dict[Severity, int]: Count of checks for each severity level
        """
        return {severity: len(checks) for severity, checks in self._checks_by_severity.items()}

    def list_check_ids(self) -> List[str]:
        """Return selected BaseCheck executor IDs for backward compatibility."""
        return list(self._checks.keys())

    def list_control_ids(self) -> List[str]:
        """Return every selected canonical control ID in catalog order."""
        return self._selected_control_ids.copy()

    def list_selected_journey_control_ids(self) -> List[str]:
        """Return selected canonical controls owned by Journey execution."""
        return self._selected_journey_control_ids.copy()

    def get_selected_controls(self) -> List["AtomicControl"]:
        """Return selected canonical control metadata in execution-plan order."""
        if self._atomic_control_registry is None:
            return []
        return [
            self._atomic_control_registry.get(control_id)
            for control_id in self._selected_control_ids
        ]

    def get_atomic_control_registry(self) -> Optional["AtomicControlRegistry"]:
        """Return the attached immutable catalog, if registration configured one."""
        return self._atomic_control_registry

    def is_journey_control(self, control_id: str) -> bool:
        """Return whether a known control is owned by Journey execution."""
        if self._atomic_control_registry is None:
            return control_id.startswith("journey-")
        from .control_registry import ExecutionSource

        try:
            return (
                self._atomic_control_registry.get(control_id).execution_source
                == ExecutionSource.JOURNEY
            )
        except KeyError:
            return control_id.startswith("journey-")

    def get_control_severity(self, control_id: str) -> Severity:
        """Return the effective selected severity for a canonical control."""
        canonical_id = self.resolve_control_id(control_id)
        if canonical_id in self._checks:
            return self._checks[canonical_id].severity
        if self._atomic_control_registry is None:
            raise KeyError(f"Unknown control ID: {control_id}")
        return self._atomic_control_registry.get(canonical_id).default_severity

    def _remove_selected_control(self, control_id: str) -> None:
        canonical_id = self.resolve_control_id(control_id)
        self._selected_control_ids = [
            selected_id for selected_id in self._selected_control_ids if selected_id != canonical_id
        ]
        self._selected_journey_control_ids = [
            selected_id
            for selected_id in self._selected_journey_control_ids
            if selected_id != canonical_id
        ]

    def _override_base_check_severity(self, check_id: str, new_severity: Severity) -> bool:
        canonical_id = self.resolve_control_id(check_id)
        check = self._checks.get(canonical_id)
        if check is None or check.severity == new_severity:
            return False
        old_severity = check.severity
        old_list = self._checks_by_severity.get(old_severity, [])
        self._checks_by_severity[old_severity] = [
            candidate for candidate in old_list if candidate.check_id != canonical_id
        ]
        check.severity = new_severity
        self._checks_by_severity[new_severity].append(check)
        return True

    def clear(self) -> None:
        """Clear all registered checks."""
        self._checks.clear()
        self._checks_by_pillar.clear()
        self._checks_by_severity.clear()
        self._selected_control_ids.clear()
        self._selected_journey_control_ids.clear()
        self.logger.debug("Cleared all registered checks")

    def load_checks_from_config(self, checks_config: Dict[str, Dict]) -> None:
        """
        Apply per-check configuration overrides to already-registered checks.

        By the time this runs (called from ``cli.initialize_assessment_components``
        after ``register_all_checks``), every check is already a live
        ``BaseCheck`` instance sitting in this registry — checks are Python
        classes registered via each module's ``register_*()`` function, not
        built dynamically from config. So "loading checks from config" can't
        mean constructing new check objects; it means applying config-file
        overrides to the ones that already exist. That's what this method
        now actually does:

        - ``enabled: false`` → unregisters the check entirely (matches what
          ``--exclude-checks`` does at the registration layer).
        - ``severity: "<level>"`` → overrides the check's severity in place,
          so findings from that check report at the configured level instead
          of the class's built-in default.

        Previously this method only logged what it *would* do and never
        mutated the registry or any check — every value under ``checks:`` in
        assessment_config.yaml was silently a no-op despite the config
        README documenting both fields as live behavior.

        ``parameters``, ``remediation_template``, and ``description``
        overrides are intentionally not yet implemented — they would need
        each concrete check's ``execute()`` to consult
        ``context.config["checks"][self.check_id]["parameters"]`` and none
        currently do, so silently accepting those keys here would repeat
        the same "documented but does nothing" problem for a subset of the
        surface. They're logged as ignored so a config author notices.

        Args:
            checks_config: Dictionary containing check configurations, keyed
                by check_id. Each value may have ``enabled`` (bool) and/or
                ``severity`` (one of "critical"/"high"/"medium"/"low").
        """
        if not checks_config:
            return

        self.logger.info(f"Applying configuration overrides for {len(checks_config)} check(s)")

        disabled_count = 0
        severity_override_count = 0

        for requested_check_id, check_config in checks_config.items():
            if not isinstance(check_config, dict):
                continue

            check_id = self.resolve_control_id(requested_check_id)
            control = None
            if self._atomic_control_registry is not None:
                try:
                    control = self._atomic_control_registry.get(check_id)
                except KeyError:
                    pass
            if check_id not in self._checks and control is None:
                self.logger.warning(
                    f"Config references check '{requested_check_id}' which is unknown; "
                    "ignoring its configuration."
                )
                continue

            enabled = check_config.get("enabled", True)
            if not enabled:
                if check_id in self._checks:
                    self.unregister_check(check_id)
                self._remove_selected_control(check_id)
                disabled_count += 1
                self.logger.debug(f"Control {check_id} disabled via configuration")
                continue

            severity_name = check_config.get("severity")
            if severity_name:
                try:
                    new_severity = Severity(severity_name.lower())
                except (AttributeError, ValueError):
                    self.logger.warning(
                        f"Ignoring invalid severity override '{severity_name}' "
                        f"for check '{check_id}'; must be one of "
                        f"{[s.value for s in Severity]}"
                    )
                else:
                    from .control_registry import ExecutionSource

                    if control is not None and control.execution_source == ExecutionSource.JOURNEY:
                        self.logger.warning(
                            "Severity override for Journey control '%s' is not supported; "
                            "using catalog severity '%s'.",
                            check_id,
                            control.default_severity.value,
                        )
                    elif self._override_base_check_severity(check_id, new_severity):
                        severity_override_count += 1
                        self.logger.debug(
                            "Check %s severity overridden to %s",
                            check_id,
                            new_severity.value,
                        )

            unsupported_keys = set(check_config.keys()) - {"enabled", "severity"}
            if unsupported_keys:
                self.logger.warning(
                    f"Check '{check_id}' config has unsupported override "
                    f"key(s) {sorted(unsupported_keys)}; only 'enabled' and "
                    "'severity' are currently applied."
                )

        self.logger.info(
            f"Configuration overrides applied: {disabled_count} check(s) "
            f"disabled, {severity_override_count} severity override(s)"
        )

    def __len__(self) -> int:
        """Return the number of registered checks."""
        return len(self._checks)

    def __contains__(self, check_id: str) -> bool:
        """Check if a canonical check ID or supported legacy alias is registered."""
        return self.resolve_check_id(check_id) in self._checks

    def __str__(self) -> str:
        """String representation of the registry."""
        return f"CheckRegistry({len(self._checks)} checks)"

    def __repr__(self) -> str:
        """Detailed string representation of the registry."""
        pillar_counts = self.get_pillar_counts()
        severity_counts = self.get_severity_counts()
        return (
            f"CheckRegistry(total={len(self._checks)}, "
            f"pillars={dict(pillar_counts)}, "
            f"severities={dict(severity_counts)})"
        )
