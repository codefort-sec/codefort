"""Deterministic security policy evaluator and backend risk scoring system for CodeFort scans."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from app.schemas.common import EngineStatus, Severity, Verdict
from app.schemas.finding import FindingBase
from app.schemas.scan import CoverageInfo

# Illustrative project base severity weights (per Step 4 specification)
SEVERITY_BASE_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def calculate_backend_risk_score(findings: List[Any]) -> Tuple[int, str]:
    """
    Computes deterministic risk score (0-100) and risk classification based on verified findings.
    BARQAI/Qwen explains the result, but the backend strictly determines the score.

    Weights:
      Critical: 10
      High: 7
      Medium: 4
      Low: 1
    """
    if not findings:
        return 0, "CLEAN"

    has_critical = False
    has_high = False
    has_medium = False
    raw_points = 0

    for f in findings:
        sev = getattr(f, "severity", None)
        if sev is None and isinstance(f, dict):
            sev = f.get("severity")
        if isinstance(sev, str):
            try:
                sev = Severity(sev.upper())
            except ValueError:
                sev = Severity.MEDIUM

        weight = SEVERITY_BASE_WEIGHTS.get(sev, 0)
        raw_points += weight
        if sev == Severity.CRITICAL:
            has_critical = True
        elif sev == Severity.HIGH:
            has_high = True
        elif sev == Severity.MEDIUM:
            has_medium = True

    # Deterministic mapping to 0-100 score and risk classification
    if has_critical:
        # Scale to 75 - 100
        risk_score = min(100, 85 + max(0, raw_points - 10) * 3)
        risk_level = "CRITICAL" if risk_score >= 90 else "HIGH"
    elif has_high:
        # Scale to 70 - 74 (High risk base score, illustrative 74/100)
        risk_score = min(74, 74 + max(0, raw_points - 7) * 2)
        risk_level = "HIGH"
    elif has_medium:
        # Scale to 30 - 49
        risk_score = min(49, 30 + max(0, raw_points - 4) * 3)
        risk_level = "MEDIUM"
    else:
        # Scale to 1 - 25
        risk_score = min(25, max(1, raw_points * 3))
        risk_level = "LOW"

    return risk_score, risk_level


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
    - CRITICAL findings -> BLOCKED (or high risk score >= 70).
    - HIGH findings -> REVIEW_REQUIRED.
    """
    # Check coverage failures
    if require_static and coverage.static_analysis == EngineStatus.FAILED:
        return Verdict.SCAN_ERROR, 50
    if require_dependency and coverage.dependency_intel == EngineStatus.FAILED:
        return Verdict.SCAN_ERROR, 50

    risk_score, risk_level = calculate_backend_risk_score(findings)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_high = any(f.severity == Severity.HIGH for f in findings)

    # Determine verdict
    if has_critical or risk_score >= 70:
        verdict = Verdict.BLOCKED
    elif has_high or risk_score >= 25:
        verdict = Verdict.REVIEW_REQUIRED
    else:
        verdict = Verdict.PASS

    return verdict, risk_score
