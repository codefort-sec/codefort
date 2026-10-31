"""Scan schemas matching CodeFort API specification and BARQAI explanation engine."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from app.schemas.common import EngineStatus, ScanStatus, Verdict
from app.schemas.finding import FindingResponse


class CoverageInfo(BaseModel):
    static_analysis: EngineStatus = EngineStatus.NOT_CONFIGURED
    dependency_intel: EngineStatus = EngineStatus.NOT_CONFIGURED
    workflow_linter: EngineStatus = EngineStatus.NOT_CONFIGURED
    dynamic_sandbox: EngineStatus = EngineStatus.NOT_CONFIGURED


class SandboxTelemetry(BaseModel):
    spawned_processes: List[str] = Field(default_factory=list, description="Processes spawned during sandbox execution")
    network_calls: List[str] = Field(default_factory=list, description="Outbound socket and DNS network requests")
    file_modifications: List[str] = Field(default_factory=list, description="Files touched outside sandbox boundary")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Runtime sandbox threat flags")


class ScanSummary(BaseModel):
    model_config = {"extra": "allow"}

    what_changed: str = Field(..., description="High-level description of modified files or logic")
    evidence_observed: List[str] = Field(default_factory=list, description="Specific observed indicators")
    why_it_matters: str = Field(..., description="Risk impact and context")
    recommended_actions: Optional[List[str]] = Field(default_factory=list, description="Next steps for reviewer")
    clean_patch: Optional[str] = Field(None, description="Automated 1-click clean remediation unified git diff")

    # Standardized BARQAI output format
    analysis: Optional[Dict[str, Any]] = Field(None, description="Standardized BARQAI analysis object")
    risk_level: Optional[str] = Field("MEDIUM", description="Categorical risk classification: LOW, MEDIUM, HIGH, CRITICAL, CLEAN")
    unknowns: List[str] = Field(default_factory=list, description="Identified missing evidence or unverified items")
    remediation_status: str = Field("NOT_TESTED", description="Remediation status: NOT_TESTED, VERIFIED, FAILED")
    evidence_verification: str = Field("Validated", description="Evidence verification status: Validated, Rejected")
    patch_verification: str = Field("Not tested", description="Patch verification status: Validated, Not tested, Failed")

    # Compatibility fields for BARQAI explanation & benchmark suite
    what_happened: Optional[str] = Field(None, description="Detailed runtime or sandbox execution telemetry summary")
    why_dangerous: Optional[str] = Field(None, description="Detailed technical security risk analysis")
    risk_factors: List[str] = Field(default_factory=list, description="Identified threat signals and risk factors")
    recommended_action: Optional[str] = Field(None, description="Primary recommended action: block, review, or pass")
    confidence: float = Field(0.99, description="Model evaluation confidence (0.0 - 1.0)")

    @model_validator(mode="after")
    def sync_dual_fields(self) -> ScanSummary:
        # Sync why_it_matters <-> why_dangerous
        if not self.why_dangerous and self.why_it_matters:
            self.why_dangerous = self.why_it_matters
        elif not self.why_it_matters and self.why_dangerous:
            self.why_it_matters = self.why_dangerous

        # Sync evidence_observed <-> risk_factors
        if not self.risk_factors and self.evidence_observed:
            self.risk_factors = list(self.evidence_observed)
        elif not self.evidence_observed and self.risk_factors:
            self.evidence_observed = list(self.risk_factors)

        # Sync recommended_actions <-> recommended_action
        if not self.recommended_action and self.recommended_actions:
            first = self.recommended_actions[0].split()[0].lower()
            self.recommended_action = first if first in ("block", "review", "pass") else "review"
        elif not self.recommended_actions and self.recommended_action:
            self.recommended_actions = [self.recommended_action.upper()]

        return self


# Backward-compatible alias for the BARQAI Engine model
BARQAIExplanation = ScanSummary


class ScanResponse(BaseModel):
    model_config = {"extra": "allow"}

    id: str = Field(..., description="Scan UUID")
    repository: str = Field(..., description="Full repository name: owner/repo")
    pull_request: int = Field(..., description="Pull request number")
    status: ScanStatus = Field(..., description="Scan execution status")
    verdict: Verdict = Field(..., description="Security verdict")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Risk score from 0 to 100")
    risk_level: Optional[str] = Field("HIGH", description="Categorical risk level: LOW, MEDIUM, HIGH, CRITICAL, CLEAN")
    coverage: CoverageInfo = Field(default_factory=CoverageInfo, description="Per-engine run status")
    summary: Optional[ScanSummary] = Field(None, description="BARQAI explanation summary")
    created_at: datetime = Field(..., description="Scan creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    findings: List[FindingResponse] = Field(default_factory=list, description="Detected security findings")
    sandbox_telemetry: Optional[SandboxTelemetry] = Field(
        default_factory=SandboxTelemetry, description="Runtime sandbox telemetry"
    )


class ScanCreateRequest(BaseModel):
    head_sha: Optional[str] = Field(None, description="Target commit SHA to scan")
    files: Optional[Dict[str, str]] = Field(None, description="Optional map of file paths to content for scanning")
    diff: Optional[str] = Field(None, description="Optional raw git diff content")
    packages: Optional[List[Dict[str, Any]]] = Field(None, description="Optional list of package dependencies")
