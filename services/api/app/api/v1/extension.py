"""Chrome Extension endpoints (CodeFort Guard)."""

import secrets
from typing import List
from fastapi import APIRouter, Query, status
from app.core.errors import NotFoundException
from app.schemas.common import Severity
from app.schemas.extension import (
    ExtensionFindingsCount,
    ExtensionFindingsListResponse,
    ExtensionLineFinding,
    ExtensionPairRequest,
    ExtensionPairResponse,
    ExtensionPRStatusResponse,
    ExtensionSummaryResponse,
    PairingTokenResponse,
)
from app.services.mock_engine import mock_store

router = APIRouter(prefix="/extension", tags=["Extension"])

# In-memory pairing tokens for skeleton/dev
_active_pairing_tokens = set()
_pairing_tokens_status: dict = {
    "demo-pairing-token": {"token": "demo-pairing-token", "status": "paired"}
}


@router.post("/pairing-tokens", response_model=PairingTokenResponse)
async def create_pairing_token():
    """Generates a short-lived single-use pairing token from dashboard."""
    import time
    token = f"pair_{secrets.token_hex(16)}"
    _active_pairing_tokens.add(token)
    _pairing_tokens_status[token] = {
        "token": token,
        "status": "pending",
        "created_at": time.time(),
        "paired_at": None,
    }
    return PairingTokenResponse(pairing_token=token, expires_in_seconds=300)


@router.get("/pairing-tokens/{token}/status")
async def get_pairing_token_status(token: str):
    """Checks the real-time pairing status of a token."""
    import time
    record = _pairing_tokens_status.get(token)
    if not record:
        if token in _active_pairing_tokens:
            return {"token": token, "status": "pending"}
        return {"token": token, "status": "expired"}

    if record.get("status") == "pending" and time.time() - record.get("created_at", 0) > 300:
        record["status"] = "expired"
        _active_pairing_tokens.discard(token)

    return record


@router.post("/pair", response_model=ExtensionPairResponse)
async def pair_extension(req: ExtensionPairRequest):
    """Exchanges a valid pairing token for a scoped extension credential."""
    import time
    if req.pairing_token not in _active_pairing_tokens:
        if req.pairing_token != "demo-pairing-token":
            raise NotFoundException(message="Invalid or expired pairing token.", code="INVALID_PAIRING_TOKEN")
    else:
        _active_pairing_tokens.remove(req.pairing_token)
        if req.pairing_token in _pairing_tokens_status:
            _pairing_tokens_status[req.pairing_token]["status"] = "paired"
            _pairing_tokens_status[req.pairing_token]["paired_at"] = time.time()

    return ExtensionPairResponse(
        access_token=f"ext_{secrets.token_hex(24)}",
        token_type="bearer",
        expires_in=86400 * 30,  # 30 days
    )


@router.get("/pr-status", response_model=ExtensionPRStatusResponse)
async def get_pr_status(
    repo: str = Query(..., description="Repository owner/name, e.g. owner/repo"),
    pr: int = Query(..., description="Pull request number", ge=1),
):
    """Provides compact PR security status for the Chrome Extension badge."""
    scan = mock_store.get_latest_scan_for_pr(repo, pr)
    if not scan:
        scan = await mock_store.trigger_scan(repo, pr)

    findings = mock_store.get_findings(scan.id)
    counts = ExtensionFindingsCount()
    for f in findings:
        if f.severity == Severity.CRITICAL:
            counts.critical += 1
        elif f.severity == Severity.HIGH:
            counts.high += 1
        elif f.severity == Severity.MEDIUM:
            counts.medium += 1
        elif f.severity == Severity.LOW:
            counts.low += 1
        elif f.severity == Severity.INFO:
            counts.info += 1

    return ExtensionPRStatusResponse(
        repository=scan.repository,
        pull_request=scan.pull_request,
        status=scan.status,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        findings_count=counts,
        coverage=scan.coverage,
        last_scanned_at=scan.completed_at or scan.created_at,
    )


@router.get("/findings", response_model=ExtensionFindingsListResponse)
async def get_pr_findings(
    repo: str = Query(..., description="Repository owner/name"),
    pr: int = Query(..., description="Pull request number", ge=1),
):
    """Returns line-level security findings for inline DOM injection."""
    scan = mock_store.get_latest_scan_for_pr(repo, pr)
    if not scan:
        scan = await mock_store.trigger_scan(repo, pr)

    findings = mock_store.get_findings(scan.id)
    line_findings: List[ExtensionLineFinding] = []
    for f in findings:
        if f.file_path and f.line_start:
            line_findings.append(
                ExtensionLineFinding(
                    id=f.id,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    title=f.title,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end or f.line_start,
                    recommendation=f.recommendation,
                )
            )

    return ExtensionFindingsListResponse(
        repository=repo,
        pull_request=pr,
        findings=line_findings,
    )


@router.get("/summary", response_model=ExtensionSummaryResponse)
async def get_pr_summary(
    repo: str = Query(..., description="Repository owner/name"),
    pr: int = Query(..., description="Pull request number", ge=1),
):
    """Returns BARQAI summary and top evidence for the extension side panel."""
    scan = mock_store.get_latest_scan_for_pr(repo, pr)
    if not scan:
        scan = await mock_store.trigger_scan(repo, pr)

    return ExtensionSummaryResponse(
        repository=scan.repository,
        pull_request=scan.pull_request,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        summary=scan.summary,
    )
