"""
Findings diff — compare two assessment runs and show what changed.

Confirmed failed controls and manual-review candidates are compared separately.
Informational records never participate in the actionable diff.
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..checks.control_registry import get_atomic_control_registry

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    resolved: List[Dict[str, Any]]
    new: List[Dict[str, Any]]
    persistent: List[Dict[str, Any]]
    baseline_total: int
    current_total: int
    manual_review_resolved: List[Dict[str, Any]] = field(default_factory=list)
    manual_review_new: List[Dict[str, Any]] = field(default_factory=list)
    manual_review_persistent: List[Dict[str, Any]] = field(default_factory=list)
    baseline_manual_review_total: int = 0
    current_manual_review_total: int = 0

    @property
    def summary(self) -> str:
        lines = [
            (
                f"Baseline: {self.baseline_total} failed controls | "
                f"Current: {self.current_total} failed controls"
            ),
            f"  Resolved: {len(self.resolved)}",
            f"  New:      {len(self.new)}",
            f"  Persistent: {len(self.persistent)}",
            (
                f"Manual-review candidates: {self.baseline_manual_review_total} baseline | "
                f"{self.current_manual_review_total} current"
            ),
            f"  Review resolved: {len(self.manual_review_resolved)}",
            f"  Review new:      {len(self.manual_review_new)}",
            f"  Review persistent: {len(self.manual_review_persistent)}",
        ]
        return "\n".join(lines)

    @property
    def resolved_manual_reviews(self) -> List[Dict[str, Any]]:
        """Backward-compatible readable alias for manual review results."""
        return self.manual_review_resolved

    @property
    def new_manual_reviews(self) -> List[Dict[str, Any]]:
        """Backward-compatible readable alias for manual review results."""
        return self.manual_review_new

    @property
    def persistent_manual_reviews(self) -> List[Dict[str, Any]]:
        """Backward-compatible readable alias for manual review results."""
        return self.manual_review_persistent


def _canonical_check_id(check_id: Any) -> str:
    normalized = str(check_id or "").lower()
    try:
        return get_atomic_control_registry().resolve_id(normalized)
    except KeyError:
        return normalized


def _legacy_key(finding: Dict[str, Any]) -> str:
    return f"{_canonical_check_id(finding.get('check_id'))}::{finding.get('resource_id', '')}"


def _finding_key(finding: Dict[str, Any]) -> str:
    """Match canonical controls by instance, falling back to legacy resource identity."""
    identity = finding.get("instance_id") or finding.get("resource_id", "")
    return f"{_canonical_check_id(finding.get('check_id'))}::{identity}"


def _legacy_identity_keys(*finding_lists: List[Dict[str, Any]]) -> set[str]:
    """Resource-identity keys of records that carry no instance_id (older reports)."""
    return {
        _legacy_key(f)
        for findings in finding_lists
        for f in findings
        if isinstance(f, dict) and not f.get("instance_id")
    }


def load_findings_from_json(filepath: str) -> List[Dict[str, Any]]:
    """Load findings from a previously generated JSON report.

    Non-dict entries are skipped with a logged warning. A report whose findings
    container is not a list raises ``ValueError``.
    """
    with open(filepath) as f:
        data = json.load(f)

    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        return []
    if not isinstance(findings, list):
        raise ValueError(f"{filepath}: 'findings' must be a list, got {type(findings).__name__}")
    valid = [item for item in findings if isinstance(item, dict)]
    skipped = len(findings) - len(valid)
    if skipped:
        logger.warning("%s: skipped %d non-object finding entries", filepath, skipped)
    return valid


def _actionable_groups(
    findings: List[Dict[str, Any]],
    disposition: str,
    legacy_keys: set[str] | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("status") or "").lower()
        finding_disposition = str(finding.get("disposition") or "control").lower()
        if status == "fail" and finding_disposition == disposition:
            # If either report lacks instance_id for this resource, match on
            # resource identity so old baselines don't yield resolved+new pairs.
            if legacy_keys and _legacy_key(finding) in legacy_keys:
                key = _legacy_key(finding)
            else:
                key = _finding_key(finding)
            groups[key].append(finding)
    return groups


def _compare_groups(
    baseline_groups: Dict[str, List[Dict[str, Any]]],
    current_groups: Dict[str, List[Dict[str, Any]]],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    resolved: List[Dict[str, Any]] = []
    new: List[Dict[str, Any]] = []
    persistent: List[Dict[str, Any]] = []
    for key in sorted(set(baseline_groups) | set(current_groups)):
        baseline_records = baseline_groups.get(key, [])
        current_records = current_groups.get(key, [])
        shared_count = min(len(baseline_records), len(current_records))
        persistent.extend(current_records[:shared_count])
        resolved.extend(baseline_records[shared_count:])
        new.extend(current_records[shared_count:])
    return resolved, new, persistent


def compute_diff(
    baseline_findings: List[Dict[str, Any]],
    current_findings: List[Dict[str, Any]],
) -> DiffResult:
    """Compare confirmed failed controls and review candidates independently."""
    legacy = _legacy_identity_keys(baseline_findings, current_findings)
    baseline_controls = _actionable_groups(baseline_findings, "control", legacy)
    current_controls = _actionable_groups(current_findings, "control", legacy)
    resolved, new, persistent = _compare_groups(baseline_controls, current_controls)

    baseline_reviews = _actionable_groups(baseline_findings, "manual_review", legacy)
    current_reviews = _actionable_groups(current_findings, "manual_review", legacy)
    review_resolved, review_new, review_persistent = _compare_groups(
        baseline_reviews, current_reviews
    )

    return DiffResult(
        resolved=resolved,
        new=new,
        persistent=persistent,
        baseline_total=sum(len(records) for records in baseline_controls.values()),
        current_total=sum(len(records) for records in current_controls.values()),
        manual_review_resolved=review_resolved,
        manual_review_new=review_new,
        manual_review_persistent=review_persistent,
        baseline_manual_review_total=sum(len(records) for records in baseline_reviews.values()),
        current_manual_review_total=sum(len(records) for records in current_reviews.values()),
    )


def diff_from_files(baseline_path: str, current_path: str) -> DiffResult:
    """Load two JSON reports and compute their diff."""
    baseline = load_findings_from_json(baseline_path)
    current = load_findings_from_json(current_path)
    return compute_diff(baseline, current)


def _print_item(prefix: str, finding: Dict[str, Any]) -> None:
    severity = str(finding.get("severity", "?")).upper()
    check_id = _canonical_check_id(finding.get("check_id"))
    identity = finding.get("instance_id") or finding.get("resource_id")
    print(f"  [{prefix} {severity}] {check_id}: {identity}")
    action = finding.get("remediation") or finding.get("action")
    methodology = finding.get("methodology") or {}
    verification = finding.get("verification_criteria") or methodology.get("verification_criteria")
    if action:
        print(f"    Action: {action}")
    if verification:
        print(f"    Verification: {verification}")


def _print_section(title: str, prefix: str, findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    print(f"\n--- {title} ({len(findings)}) ---")
    for finding in findings[:20]:
        _print_item(prefix, finding)
    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more")


def print_diff(diff: DiffResult) -> None:
    """Print a human-readable, disposition-aware diff summary to stdout."""
    print("\n=== Assessment Findings Diff ===")
    print(diff.summary)
    _print_section("Resolved failed controls", "RESOLVED", diff.resolved)
    _print_section("New failed controls", "NEW", diff.new)
    _print_section(
        "Resolved manual-review candidates", "REVIEW RESOLVED", diff.manual_review_resolved
    )
    _print_section("New manual-review candidates", "REVIEW NEW", diff.manual_review_new)

    if not any((diff.resolved, diff.new, diff.manual_review_resolved, diff.manual_review_new)):
        print("\n  No changes between runs.")
