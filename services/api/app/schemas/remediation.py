"""Remediation and patch verification schemas for CodeFort."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
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


# ============================================================================
# PHASE 3: AI-POWERED REMEDIATION & PATCH VERIFICATION SCHEMAS
# ============================================================================

class RemediationChecks(BaseModel):
    """Status checklist for independent verification gates."""
    patch_format: str = Field("Passed", description="Unified diff syntax check (Passed/Failed)")
    file_validation: str = Field("Passed", description="Path traversal and modified file scope check")
    syntax_check: str = Field("Passed", description="AST / JSON / YAML syntax check (Passed/Failed)")
    unit_tests: str = Field("Pending", description="Isolated test execution check (Passed/Pending/Failed)")
    security_retest: str = Field("Pending", description="Semgrep/Static security re-scan check (Passed/Pending/Failed)")
    dependency_check: str = Field("Passed", description="OSV / typosquatting check (Passed/Pending/Failed)")


class RemediationGenerateRequest(BaseModel):
    finding_id: str = Field(..., description="Target finding ID to fix")
    scan_id: Optional[str] = Field(None, description="Optional associated scan UUID")
    title: str = Field(..., description="Security finding title or rule description")
    file_path: str = Field(..., description="Target affected file path")
    original_code: str = Field(..., description="Original vulnerable code snippet")
    vulnerability_details: Optional[str] = Field(None, description="Context from BARQAI or static analysis")
    evidence_id: Optional[str] = Field(None, description="Evidence ID (e.g., OSV-001 or typo_lodashe)")
    allowed_files: Optional[List[str]] = Field(None, description="List of permitted files allowed to be modified")


class RemediationRecord(BaseModel):
    """Complete candidate patch and verification state."""
    id: str = Field(..., description="Remediation identifier (e.g. rem_abc123)")
    finding_id: str
    scan_id: Optional[str] = None
    title: str
    file_path: str
    original_issue: str
    proposed_solution: str
    original_code: str
    suggested_code: str
    unified_diff: str
    explanation: str
    potential_limitations: str
    status: str = Field("awaiting_review", description="awaiting_review, testing, approved, rejected")
    approved: bool = Field(False, description="Developer approval status (never automatically granted)")
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    checks: RemediationChecks = Field(default_factory=RemediationChecks)
    created_at: str


RemediationGenerateResponse = RemediationRecord


class RemediationValidateRequest(BaseModel):
    patch_id: Optional[str] = Field(None, description="Optional remediation record ID")
    unified_diff: str = Field(..., description="Unified git diff to validate")
    file_path: Optional[str] = Field(None, description="Expected target file path")
    allowed_files: Optional[List[str]] = Field(None, description="List of allowed files")


class RemediationValidateResponse(BaseModel):
    is_valid: bool
    format_valid: bool
    files_valid: bool
    modified_files: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class RemediationTestRequest(BaseModel):
    patch_id: Optional[str] = Field(None, description="Remediation identifier")
    unified_diff: Optional[str] = Field(None, description="Optional custom unified diff")
    file_path: Optional[str] = Field(None, description="Target file path")
    files: Optional[Dict[str, str]] = Field(None, description="In-memory repository files map")
    original_findings: Optional[List[Dict[str, Any]]] = Field(None, description="Baseline findings before patch")


class RemediationTestResponse(BaseModel):
    patch_id: str
    passed: bool
    status: str
    checks: RemediationChecks
    details: str
    regressions_count: int = 0
    remaining_findings_count: int = 0


class RemediationApproveRequest(BaseModel):
    developer_id: Optional[str] = Field("developer", description="Identifier of approving developer")
    comment: Optional[str] = Field(None, description="Approval comment or audit note")


class RemediationApproveResponse(BaseModel):
    id: str
    approved: bool
    status: str
    message: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
