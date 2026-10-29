"""Finding schemas matching CodeFort specification."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.common import Severity


class FindingBase(BaseModel):
    rule_id: str = Field(..., description="Unique analyzer rule identifier")
    title: str = Field(..., description="Short finding title")
    description: Optional[str] = Field(None, description="Detailed finding explanation")
    severity: Severity = Field(..., description="Finding severity")
    file_path: Optional[str] = Field(None, description="Affected file path")
    line_start: Optional[int] = Field(None, description="Starting line number")
    line_end: Optional[int] = Field(None, description="Ending line number")
    evidence_id: Optional[str] = Field(None, description="Linked evidence ID")
    recommendation: Optional[str] = Field(None, description="Recommended remediation action")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score")


class FindingResponse(FindingBase):
    id: str = Field(..., description="Unique finding UUID")
    scan_id: str = Field(..., description="Associated scan ID")
    fingerprint: str = Field(..., description="Unique hash for deduplication")
    created_at: datetime = Field(..., description="Timestamp of finding creation")


class FindingListResponse(BaseModel):
    findings: List[FindingResponse]
    total: int
    limit: int
    cursor: Optional[str] = None
