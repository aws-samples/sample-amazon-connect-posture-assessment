"""Generate a catalog from the selected atomic assessment controls.

This generator is intended for derived catalogs and test fixtures. The curated
``docs/check-catalog.md`` includes additional explanatory material and must not
be overwritten by routine generation.
"""

from collections import defaultdict
from typing import Iterable

from .checks.control_registry import AtomicControl
from .checks.registry import CheckRegistry
from .models import Pillar


class DocsGenerator:
    """Generate deterministic control-catalog documentation from a registry."""

    def generate_catalog(self, registry: CheckRegistry, output_path: str) -> None:
        """Generate Markdown for the registry's unified selected controls."""
        controls = registry.get_selected_controls()
        controls_by_pillar = self._group_by_pillar(controls)

        lines = [
            "# Amazon Connect Customer Posture Assessment Tool — Control Catalog",
            "",
            (
                f"This generated catalog contains {len(controls)} selected canonical controls. "
                "BaseCheck and Journey-backed controls share one identity and metadata model."
            ),
            "",
            "## Summary Table",
            "",
            self._generate_summary_table(controls),
            "",
        ]

        for pillar in Pillar:
            pillar_controls = controls_by_pillar.get(pillar, [])
            if not pillar_controls:
                continue
            lines.append(f"## {pillar.value.replace('_', ' ').title()}")
            lines.append("")
            for control in sorted(pillar_controls, key=lambda item: item.control_id):
                lines.append(self._format_control_entry(control))
            lines.append("")

        with open(output_path, "w", encoding="utf-8") as catalog_file:
            catalog_file.write("\n".join(lines))

    @staticmethod
    def _group_by_pillar(
        controls: Iterable[AtomicControl],
    ) -> dict[Pillar, list[AtomicControl]]:
        grouped: dict[Pillar, list[AtomicControl]] = defaultdict(list)
        for control in controls:
            grouped[control.pillar].append(control)
        return dict(grouped)

    @staticmethod
    def _generate_summary_table(controls: Iterable[AtomicControl]) -> str:
        rows = [
            "| Control ID | Pillar | Severity | Disposition | Executor | Name |",
            "|---|---|---|---|---|---|",
        ]
        for control in sorted(
            controls,
            key=lambda item: (item.pillar.value, item.control_id),
        ):
            rows.append(
                f"| `{control.control_id}` | "
                f"{control.pillar.value.replace('_', ' ').title()} | "
                f"{control.default_severity.value.title()} | "
                f"{control.disposition.value.replace('_', ' ').title()} | "
                f"{control.execution_source.value.replace('_', ' ').title()} | "
                f"{control.name} |"
            )
        return "\n".join(rows)

    @staticmethod
    def _format_control_entry(control: AtomicControl) -> str:
        methodology = control.methodology
        aliases = ", ".join(f"`{alias}`" for alias in control.legacy_aliases) or "None"
        primary_lens = methodology.primary_lens_reference or "Not assigned"
        responsible_function = methodology.responsible_function or "Not assigned"
        return "\n".join(
            [
                f"### `{control.control_id}` — {control.name}",
                "",
                f"- **Root condition:** `{control.root_condition_key}`",
                f"- **Severity:** {control.default_severity.value.title()}",
                f"- **Disposition:** {control.disposition.value.replace('_', ' ').title()}",
                f"- **Executor:** {control.execution_source.value.replace('_', ' ').title()}",
                f"- **Requires flow analysis:** {'Yes' if control.requires_flow_analysis else 'No'}",
                f"- **Accepted legacy aliases:** {aliases}",
                f"- **Why this is assessed:** {methodology.reason}",
                f"- **Evidence source:** {methodology.evidence_source}",
                f"- **What the evidence cannot prove:** {methodology.proof_limitations}",
                f"- **Developer/admin meaning:** {methodology.developer_admin_meaning}",
                f"- **Verification and closure:** {methodology.verification_criteria}",
                f"- **Responsible function:** {responsible_function}",
                f"- **Primary lens reference:** {primary_lens}",
                "",
            ]
        )
