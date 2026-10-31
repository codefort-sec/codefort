"""Pull requests and scan management endpoints."""

from typing import Optional
from fastapi import APIRouter, Path, Query, status
from app.core.errors import NotFoundException
from app.schemas.common import PaginatedResponse
from app.schemas.finding import FindingListResponse, FindingResponse
from app.schemas.scan import ScanCreateRequest, ScanResponse
from app.services.mock_engine import mock_store

router = APIRouter(tags=["Scans"])


@router.post(
    "/repositories/{owner}/{repo}/pull-requests/{pr_number}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def queue_pr_scan(
    owner: str = Path(..., description="Repository owner"),
    repo: str = Path(..., description="Repository name"),
    pr_number: int = Path(..., description="PR number", ge=1),
    body: Optional[ScanCreateRequest] = None,
):
    """Queues a security scan for a pull request."""
    repository = f"{owner}/{repo}"
    if body and body.files:
        scan = await mock_store.scan_files(repository=repository, pr_number=pr_number, files=body.files)
        return scan
    head_sha = body.head_sha if body else None
    scan = await mock_store.trigger_scan(repository=repository, pr_number=pr_number, head_sha=head_sha)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_details(scan_id: str = Path(..., description="Scan UUID")):
    """Retrieves status, coverage, and summary for a scan."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(
    scan_id: str = Path(..., description="Scan UUID"),
    limit: int = Query(25, ge=1, le=100),
    cursor: Optional[str] = None,
):
    """Retrieves paginated normalized findings for a scan."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")

    findings = mock_store.get_findings(scan_id)
    return FindingListResponse(
        findings=findings[:limit],
        total=len(findings),
        limit=limit,
        cursor=None,
    )


@router.get("/scans/{scan_id}/telemetry")
async def get_scan_telemetry(scan_id: str = Path(..., description="Scan UUID")):
    """Retrieves sanitized sandbox runtime telemetry if available."""
    scan = mock_store.get_scan(scan_id)
    if not scan:
        raise NotFoundException(message=f"Scan {scan_id} not found.", code="RESOURCE_NOT_FOUND")

    # In MVP, sandbox telemetry is optional
    return {
        "scan_id": scan_id,
        "telemetry_events": [],
        "completeness_status": "not_configured",
    }
