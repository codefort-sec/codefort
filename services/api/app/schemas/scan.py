"""Scan schemas matching CodeFort API specification."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.common import EngineStatus, ScanStatus, Verdict


class CoverageInfo(BaseModel):
    static_analysis: EngineStatus = EngineStatus.NOT_CONFIGURED
    dependency_intel: EngineStatus = EngineStatus.NOT_CONFIGURED
    workflow_linter: EngineStatus = EngineStatus.NOT_CONFIGURED
    dynamic_sandbox: EngineStatus = EngineStatus.NOT_CONFIGURED


class ScanSummary(BaseModel):
    what_changed: str = Field(..., description="High-level description of modified files or logic")
    evidence_observed: List[str] = Field(default_factory=list, description="Specific observed indicators")
    why_it_matters: str = Field(..., description="Risk impact and context")
    recommended_actions: Optional[List[str]] = Field(default_factory=list, description="Next steps for reviewer")


class ScanResponse(BaseModel):
    id: str = Field(..., description="Scan UUID")
    repository: str = Field(..., description="Full repository name: owner/repo")
    pull_request: int = Field(..., description="Pull request number")
    status: ScanStatus = Field(..., description="Scan execution status")
    verdict: Verdict = Field(..., description="Security verdict")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Risk score from 0 to 100")
    coverage: CoverageInfo = Field(default_factory=CoverageInfo, description="Per-engine run status")
    summary: Optional[ScanSummary] = Field(None, description="BARQAI explanation summary")
    created_at: datetime = Field(..., description="Scan creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")


class ScanCreateRequest(BaseModel):
    head_sha: Optional[str] = Field(None, description="Target commit SHA to scan")
    files: Optional[Dict[str, str]] = Field(None, description="Optional map of file paths to content for scanning")
