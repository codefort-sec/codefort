"""Chrome Extension API schemas for CodeFort Guard."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict
from app.schemas.scan import CoverageInfo, ScanSummary


class FindingsCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


ExtensionFindingsCount = FindingsCount


class ExtensionPRStatusResponse(BaseModel):
    repository: str = Field(..., description="Repository full name, e.g. owner/repo")
    pull_request: int = Field(..., description="PR number")
    status: ScanStatus = Field(..., description="Scan status")
    verdict: Verdict = Field(..., description="Calculated verdict")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Risk score 0-100")
    findings_count: FindingsCount = Field(default_factory=FindingsCount)
    coverage: CoverageInfo = Field(default_factory=CoverageInfo)
    last_scanned_at: Optional[datetime] = Field(None, description="Timestamp of most recent scan")


class ExtensionLineFinding(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    title: str
    file_path: str
    line_start: int
    line_end: int
    recommendation: Optional[str] = None


class ExtensionFindingsResponse(BaseModel):
    repository: str
    pull_request: int
    findings: List[ExtensionLineFinding] = Field(default_factory=list)


ExtensionFindingsListResponse = ExtensionFindingsResponse


class ExtensionSummaryResponse(BaseModel):
    repository: str
    pull_request: int
    verdict: Verdict
    risk_score: Optional[int] = None
    summary: Optional[ScanSummary] = None


class PairingTokenResponse(BaseModel):
    pairing_token: str
    expires_in_seconds: int = 300


class ExtensionPairRequest(BaseModel):
    pairing_token: str = Field(..., description="Single-use pairing token from web dashboard")


class ExtensionPairResponse(BaseModel):
    access_token: str = Field(..., description="Scoped extension bearer token")
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Seconds until expiration")
