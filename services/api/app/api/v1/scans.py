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


@router.post("/demo/scan", response_model=ScanResponse)
async def run_demo_scan(body: ScanCreateRequest):
    """Executes live multi-engine PR security scan with Barq-AI explanation."""
    from datetime import datetime, timezone
    import uuid
    from app.engines import (
        barqai_engine,
        dependency_intel,
        sandbox_runner,
        static_analyzer,
        workflow_linter,
    )
    from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict
    from app.schemas.finding import FindingResponse
    from app.schemas.scan import CoverageInfo, SandboxTelemetry

    diff_content = body.diff or ""
    packages = body.packages or []

    # 1. Parallel threat detection
    static_findings = await static_analyzer.analyze_diff(diff_content)
    dep_findings = await dependency_intel.analyze_dependencies(packages)
    workflow_findings = await workflow_linter.analyze_workflows({})
    sandbox_data = await sandbox_runner.run_sandbox(package_json=diff_content)

    all_raw_findings = static_findings + dep_findings + workflow_findings + sandbox_data.get("findings", [])

    # 2. Barq-AI Multi-Provider Inference
    explanation = await barqai_engine.analyze(
        pr_diff=diff_content,
        static_findings=static_findings,
        dependency_findings=dep_findings,
        workflow_findings=workflow_findings,
        sandbox_telemetry=sandbox_data,
    )

    # 3. Risk scoring and verdict
    risk_score = barqai_engine.compute_risk_score(explanation, len(all_raw_findings))
    verdict = Verdict.BLOCKED if risk_score >= 70 else Verdict.REVIEW_REQUIRED if risk_score >= 30 else Verdict.PASS

    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)

    # Convert findings to FindingResponse
    normalized_findings = []
    for idx, f in enumerate(all_raw_findings):
        sev_str = f.get("severity", "high").upper()
        sev = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.HIGH if sev_str == "HIGH" else Severity.MEDIUM if sev_str == "MEDIUM" else Severity.LOW
        normalized_findings.append(
            FindingResponse(
                id=f"fnd_{idx:03d}",
                scan_id=scan_id,
                rule_id=f.get("rule_id", "sec.rule"),
                title=f.get("title", "Threat signal detected"),
                description=f.get("description", ""),
                severity=sev,
                file_path=f.get("file_path", "package.json"),
                line_start=f.get("line_start", 1),
                line_end=f.get("line_end", 1),
                recommendation=f.get("recommendation", "Review and remediate."),
                fingerprint=f"fp_{idx}",
                created_at=now,
            )
        )

    telemetry_obj = SandboxTelemetry(
        spawned_processes=sandbox_data.get("spawned_processes", []),
        network_calls=sandbox_data.get("network_calls", []),
        file_modifications=sandbox_data.get("file_modifications", []),
        findings=sandbox_data.get("findings", []),
    )

    return ScanResponse(
        id=scan_id,
        repository="codefort-sec/vulnerable-test-repo",
        pull_request=1,
        status=ScanStatus.COMPLETED,
        verdict=verdict,
        risk_score=risk_score,
        coverage=CoverageInfo(
            static_analysis=EngineStatus.COMPLETED,
            dependency_intel=EngineStatus.COMPLETED,
            workflow_linter=EngineStatus.COMPLETED,
            dynamic_sandbox=EngineStatus.COMPLETED,
        ),
        summary=explanation,
        created_at=now,
        completed_at=now,
        findings=normalized_findings,
        sandbox_telemetry=telemetry_obj,
    )

