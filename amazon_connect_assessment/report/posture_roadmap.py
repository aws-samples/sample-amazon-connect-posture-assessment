"""
Posture Improvement Roadmap generator (Phase 7 / Task 15 / Requirement 37).

Computes per-pillar posture scores, maturity levels, and a prioritized
list of prescriptive improvement actions from the aggregate findings.
This module is independent of the main report generator so it can evolve
separately and be tested in isolation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import Finding, Pillar, Severity
from ..score_policy import compute_scored_control_counts, is_control_failure


@dataclass
class PostureScore:
    """Posture assessment for a single pillar."""

    pillar: Pillar
    total_checks: int
    passed_checks: int
    scored_control_denominator: int
    pass_rate: Optional[float]  # 0.0 - 100.0, or None when not assessed
    maturity_level: str  # "Not assessed" | "Basic" | "Intermediate" | "Advanced"
    improvement_actions: List[Dict] = field(default_factory=list)


# Maturity thresholds.
_BASIC_THRESHOLD = 50.0
_INTERMEDIATE_THRESHOLD = 80.0


def _maturity(pass_rate: Optional[float]) -> str:
    if pass_rate is None:
        return "Not assessed"
    if pass_rate >= _INTERMEDIATE_THRESHOLD:
        return "Advanced"
    if pass_rate >= _BASIC_THRESHOLD:
        return "Intermediate"
    return "Basic"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_EFFORT_MAP_HIGH = {
    # ACGR audit findings all carry architectural weight — remediating
    # them typically involves identity migration or multi-region
    # replication work, not a self-service toggle.
    "res-acgr-identity-001",
    "res-acgr-tdg-status-001",
    "res-acgr-traffic-dist-001",
    "res-acgr-failover-test-001",
    "res-acgr-numbers-001",
    "sec-excessive-agency-001",
}
_EFFORT_MAP_LOW = {
    "ops-logging-001",
    "sec-origins-001",
    "sec-federation-001",
    "ops-early-media-001",
}


def _estimate_effort(check_id: str) -> str:
    if check_id in _EFFORT_MAP_HIGH:
        return "High"
    if check_id in _EFFORT_MAP_LOW:
        return "Low"
    return "Medium"


def generate_posture_roadmap(findings: List[Finding]) -> Dict[str, PostureScore]:
    """
    Generate per-pillar posture scores and improvement roadmap.

    Returns a dict keyed by pillar value string.
    """
    roadmap: Dict[str, PostureScore] = {}

    for pillar in Pillar:
        pillar_findings = [f for f in findings if f.pillar == pillar]
        if not pillar_findings:
            continue

        # Preserve all findings for display while scoring only evaluated controls.
        total = len(pillar_findings)
        passed, scored_total = compute_scored_control_counts(pillar_findings)
        pass_rate = (passed / scored_total * 100) if scored_total > 0 else None
        maturity = _maturity(pass_rate)

        # Prioritize improvement actions from failed controls only.
        failed = [finding for finding in pillar_findings if is_control_failure(finding)]
        failed.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 4))
        actions = []
        for f in failed[:10]:
            actions.append(
                {
                    "check_id": f.check_id,
                    "title": f.check_name,
                    "severity": f.severity.value,
                    "guidance": (
                        f.structured_remediation.summary
                        if f.structured_remediation
                        else f.remediation[:200]
                    ),
                    "effort": _estimate_effort(f.check_id),
                    "impact": (
                        "High" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "Medium"
                    ),
                }
            )

        roadmap[pillar.value] = PostureScore(
            pillar=pillar,
            total_checks=total,
            passed_checks=passed,
            scored_control_denominator=scored_total,
            pass_rate=round(pass_rate, 1) if pass_rate is not None else None,
            maturity_level=maturity,
            improvement_actions=actions,
        )

    return roadmap
