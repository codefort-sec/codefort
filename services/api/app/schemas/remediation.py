"""Remediation and patch verification schemas for CodeFort."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class RemediationProposal(BaseModel):
    finding_id: str = Field(..., description="Target finding ID being remediated")
    file_path: str = Field(..., description="Affected file path")
    line_start: int = Field(..., description="Starting line in original file")
    line_end: int = Field(..., description="Ending line in original file")
    original_code: str = Field(..., description="Original vulnerable code snippet")
    suggested_code: str = Field(..., description="Suggested secure replacement code")
    diff: str = Field(..., description="Unified git diff hunk for this change")
    explanation: str = Field(..., description="Human-readable explanation of why this fix resolves the issue")
    verification_status: str = Field(
        "verified", description="Independent verification status: verified, unverified, or failed"
    )
    verification_message: str = Field(
        ..., description="Details from independent re-scan verification"
    )


class RemediationResponse(BaseModel):
    scan_id: str = Field(..., description="Scan UUID")
    repository: str = Field(..., description="Repository full name")
    pull_request: int = Field(..., description="Pull request number")
    clean_patch: Optional[str] = Field(None, description="Complete unified git diff patch")
    proposals: List[RemediationProposal] = Field(
        default_factory=list, description="Side-by-side remediation proposals for each finding"
    )
    overall_verification_status: str = Field(
        "verified", description="Overall verification status across all proposed changes"
    )
    can_auto_apply: bool = Field(
        True, description="Whether the patch is fully verified and ready to apply"
    )


class RemediationVerifyRequest(BaseModel):
    patch: Optional[str] = Field(None, description="Optional custom candidate patch to verify")


class RemediationApplyRequest(BaseModel):
    commit_message: Optional[str] = Field(
        "fix(security): apply CodeFort automated remediation",
        description="Commit message for the applied patch",
    )
    create_branch: Optional[bool] = Field(
        False, description="Whether to create a separate remediation branch"
    )


class RemediationApplyResponse(BaseModel):
    status: str = Field(..., description="Status: applied, pending_approval, or simulated")
    scan_id: str
    message: str
    diff_applied: Optional[str] = None


ApplyRemediationRequest = RemediationApplyRequest

