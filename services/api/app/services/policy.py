"""Deterministic security policy evaluator for CodeFort scans."""

from typing import List, Tuple
from app.schemas.common import EngineStatus, Severity, Verdict
from app.schemas.finding import FindingBase
from app.schemas.scan import CoverageInfo


def evaluate_policy(
    findings: List[FindingBase],
    coverage: CoverageInfo,
    require_static: bool = True,
    require_dependency: bool = True,
) -> Tuple[Verdict, int]:
    """
    Evaluates scan findings and engine coverage to compute a deterministic verdict and risk score (0-100).
    
    Rules:
    - Never report PASS if required checks failed.
    - If required check failed -> SCAN_ERROR or REVIEW_REQUIRED.
    - CRITICAL findings -> BLOCKED (or high risk score).
    - HIGH findings -> REVIEW_REQUIRED.
    """
    # Check coverage failures
    if require_static and coverage.static_analysis == EngineStatus.FAILED:
        return Verdict.SCAN_ERROR, 50
    if require_dependency and coverage.dependency_intel == EngineStatus.FAILED:
        return Verdict.SCAN_ERROR, 50

    # Calculate risk score
    # Info: 0, Low: 5, Medium: 15, High: 35, Critical: 75
    score = 0
    has_critical = False
    has_high = False

    for f in findings:
        if f.severity == Severity.CRITICAL:
            score += 75
            has_critical = True
        elif f.severity == Severity.HIGH:
            score += 35
            has_high = True
        elif f.severity == Severity.MEDIUM:
            score += 15
        elif f.severity == Severity.LOW:
            score += 5

    # Clamp score to 100
    risk_score = min(score, 100)

    # Determine verdict
    if has_critical or risk_score >= 70:
        verdict = Verdict.BLOCKED
    elif has_high or risk_score >= 25:
        verdict = Verdict.REVIEW_REQUIRED
    else:
        verdict = Verdict.PASS

    return verdict, risk_score
