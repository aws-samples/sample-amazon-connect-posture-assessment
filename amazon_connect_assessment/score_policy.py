"""Shared methodology policy for classifying and scoring findings."""

from enum import Enum
from typing import Iterable, Optional, Tuple

from .models import CheckStatus, Finding, FindingDisposition


class FindingScoreClassification(Enum):
    """Mutually exclusive scoring treatment for one finding."""

    SCORED_PASS = "scored_pass"  # nosec B105 - enum label, not a credential
    SCORED_FAIL = "scored_fail"
    UNEVALUATED_CONTROL = "unevaluated_control"
    NOT_APPLICABLE = "not_applicable"
    NON_SCORING = "non_scoring"


def classify_finding(finding: Finding) -> FindingScoreClassification:
    """Classify a finding according to its disposition and execution status."""
    if finding.status == CheckStatus.NOT_APPLICABLE:
        return FindingScoreClassification.NOT_APPLICABLE
    if finding.disposition != FindingDisposition.CONTROL:
        return FindingScoreClassification.NON_SCORING
    if finding.status == CheckStatus.PASS:
        return FindingScoreClassification.SCORED_PASS
    if finding.status == CheckStatus.FAIL:
        return FindingScoreClassification.SCORED_FAIL
    return FindingScoreClassification.UNEVALUATED_CONTROL


def compute_scored_control_counts(findings: Iterable[Finding]) -> Tuple[int, int]:
    """Return the scored-control numerator and denominator."""
    numerator = 0
    denominator = 0
    for finding in findings:
        classification = classify_finding(finding)
        if classification == FindingScoreClassification.SCORED_PASS:
            numerator += 1
            denominator += 1
        elif classification == FindingScoreClassification.SCORED_FAIL:
            denominator += 1
    return numerator, denominator


def compute_scored_control_pass_rate(findings: Iterable[Finding]) -> Optional[float]:
    """Return a percentage pass rate, or ``None`` when no controls were scored."""
    numerator, denominator = compute_scored_control_counts(findings)
    if denominator == 0:
        return None
    return numerator / denominator * 100


def is_control_failure(finding: Finding) -> bool:
    """Return whether a finding is a failed scored control."""
    return classify_finding(finding) == FindingScoreClassification.SCORED_FAIL
