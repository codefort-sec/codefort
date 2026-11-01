"""GitHub Pull Request Webhook handler and automated scanning pipeline.

Listens for PR activity (opened, synchronize, reopened), verifies HMAC SHA-256 signatures,
deduplicates deliveries, runs the 7-step security scanning pipeline, and publishes results
back to GitHub using the Checks API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status

from app.core.config import settings
from app.core.errors import BadRequestException, ForbiddenException
from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict
from app.schemas.finding import FindingResponse
from app.schemas.scan import CoverageInfo, ScanResponse, ScanSummary
from app.services.engines.barqai import barqai_engine
from app.services.engines.dependency_intel import DependencyIntelligence
from app.services.engines.github_checks import (
    format_check_annotations,
    format_check_summary,
    publish_check,
)
from app.services.engines.orchestrator import ScanOrchestrator
from app.services.engines.static_analyzer import StaticAnalyzer
from app.services.engines.workflow_linter import WorkflowLinter
from app.services.mock_engine import mock_store
from app.services.policy import calculate_backend_risk_score, evaluate_policy

logger = logging.getLogger("codefort.github_webhooks")

router = APIRouter(tags=["GitHub Webhooks"])

# Set of processed delivery IDs for idempotency deduplication
_processed_deliveries: Set[str] = set()


class WebhookSignatureException(ForbiddenException):
    """Exception for invalid or missing webhook signatures (HTTP 403)."""

    def __init__(self, message: str = "Invalid GitHub signature", code: str = "INVALID_SIGNATURE"):
        super().__init__(message=message, code=code)


class MissingDeliveryException(BadRequestException):
    """Exception for missing delivery ID header (HTTP 400)."""

    def __init__(self, message: str = "Missing delivery ID", code: str = "MISSING_DELIVERY_ID"):
        super().__init__(message=message, code=code)



def verify_github_signature(body: bytes, secret: str, signature: Optional[str]) -> bool:
    """
    Verifies HMAC SHA-256 signature using constant-time comparison.
    Raises WebhookSignatureException (HTTP 403) on mismatch or missing signature.
    """
    # In development mode, allow skipping if secret is empty or set to "skip"
    if not secret or secret == "skip":
        return True

    if not signature:
        raise WebhookSignatureException(message="Missing webhook signature")

    # Ensure format is sha256=<hex_digest>
    expected_prefix = "sha256="
    if not signature.startswith(expected_prefix):
        raise WebhookSignatureException(message="Invalid GitHub signature format")

    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"

    if not hmac.compare_digest(expected, signature):
        raise WebhookSignatureException(message="Invalid GitHub signature")

    return True


async def process_pull_request(
    owner: str,
    repo_name: str,
    pr_number: int,
    head_sha: str,
    installation_id: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = None,
    installation_token: Optional[str] = None,
) -> ScanResponse:
    """
    Executes the 7-step security scanning pipeline for a Pull Request:
      1. GitHub API / PR Changes Retrieval
      2. Semgrep / Static Analysis
      3. Dependency Intelligence (OSV + Typosquatting)
      4. Workflow Linter (GitHub Actions Security)
      5. Isolated Dynamic Sandbox
      6. BARQAI Security Intelligence (Correlation & Explanations)
      7. Risk Engine (Deterministic Backend Score & Policy Verdict)
      8. GitHub Checks API Publication
    """
    repo_full_name = f"{owner}/{repo_name}"
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    created_at = datetime.now(timezone.utc)
    logger.info("Starting PR scan %s for %s #%s (commit: %s)", scan_id, repo_full_name, pr_number, head_sha)

    # 1. Retrieve PR changes / files
    payload_dict = payload or {}
    files: Dict[str, str] = {}

    # Check for direct file overrides (test fixtures or explicit payloads)
    if "_mock_files" in payload_dict and isinstance(payload_dict["_mock_files"], dict):
        files = payload_dict["_mock_files"]
    elif "files" in payload_dict and isinstance(payload_dict["files"], dict):
        files = payload_dict["files"]
    else:
        # Use existing mock_store resolver which also attempts live GitHub API retrieval
        files = await mock_store._resolve_pr_files(repo_full_name, pr_number)

    # 2. Initialize engines
    static_analyzer = StaticAnalyzer()
    dep_intel = DependencyIntelligence()
    wf_linter = WorkflowLinter()
    from app.engines import sandbox_runner

    all_findings: List[FindingResponse] = []
    coverage = CoverageInfo(
        static_analysis=EngineStatus.COMPLETED,
        dependency_intel=EngineStatus.COMPLETED,
        workflow_linter=EngineStatus.COMPLETED,
        dynamic_sandbox=EngineStatus.COMPLETED,
    )

    # Helper for normalizing raw engine findings
    def _add_finding(raw: Any, default_file: str = "package.json") -> None:
        f_id = f"fnd_{uuid.uuid4().hex[:6]}"
        rule_id = getattr(raw, "rule_id", None) or (raw.get("rule_id") if isinstance(raw, dict) else "security.audit")
        title = getattr(raw, "title", None) or (raw.get("title") if isinstance(raw, dict) else "Security finding")
        desc = getattr(raw, "description", None) or (raw.get("description") if isinstance(raw, dict) else title)
        sev_raw = getattr(raw, "severity", None) or (raw.get("severity") if isinstance(raw, dict) else "medium")
        if hasattr(sev_raw, "value"):
            sev = sev_raw
        else:
            try:
                sev = Severity(str(sev_raw).upper())
            except ValueError:
                sev = Severity.MEDIUM

        f_path = getattr(raw, "file_path", None) or (raw.get("file_path") if isinstance(raw, dict) else default_file)
        l_start = getattr(raw, "line_start", None) or (raw.get("line_start") if isinstance(raw, dict) else 1) or 1
        l_end = getattr(raw, "line_end", None) or (raw.get("line_end") if isinstance(raw, dict) else l_start) or l_start
        rec = getattr(raw, "recommendation", None) or (raw.get("recommendation") if isinstance(raw, dict) else "")
        ev_id = getattr(raw, "evidence_id", None) or (raw.get("evidence_id") if isinstance(raw, dict) else f"EV-{uuid.uuid4().hex[:4].upper()}")
        fp = hashlib.sha256(f"{repo_full_name}:{f_path}:{l_start}:{rule_id}".encode()).hexdigest()

        all_findings.append(
            FindingResponse(
                id=f_id,
                scan_id=scan_id,
                rule_id=rule_id,
                title=title,
                description=desc,
                severity=sev,
                confidence=0.9,
                file_path=f_path,
                line_start=l_start,
                line_end=l_end,
                evidence_id=ev_id,
                recommendation=rec,
                fingerprint=fp,
                created_at=datetime.now(timezone.utc),
            )
        )

    # Step 2: Semgrep / Static Analysis
    for file_path, content in files.items():
        try:
            static_results = static_analyzer.scan_file(file_path, content)
            for res in static_results:
                _add_finding(res, file_path)
        except Exception as err:
            logger.warning("Static analyzer error on %s: %s", file_path, err)
            coverage.static_analysis = EngineStatus.FAILED

    # Step 3: Dependency Intelligence
    for file_path, content in files.items():
        if file_path.endswith(("package.json", "requirements.txt", "Pipfile", "pyproject.toml")):
            try:
                dep_results = await dep_intel.scan_file(file_path, content)
                for res in dep_results:
                    _add_finding(res, file_path)
            except Exception as err:
                logger.warning("Dependency intelligence error on %s: %s", file_path, err)
                coverage.dependency_intel = EngineStatus.FAILED

    # Step 4: Workflow Linter
    for file_path, content in files.items():
        if ".github/workflows" in file_path or file_path.endswith((".yml", ".yaml")):
            try:
                wf_results = wf_linter.scan_file(file_path, content)
                for res in wf_results:
                    _add_finding(res, file_path)
            except Exception as err:
                logger.warning("Workflow linter error on %s: %s", file_path, err)
                coverage.workflow_linter = EngineStatus.FAILED

    # Step 5: Isolated Dynamic Sandbox Execution
    package_json_content = files.get("package.json")
    if package_json_content:
        try:
            sandbox_res = await sandbox_runner.run_sandbox(package_json=package_json_content)
            for s_find in sandbox_res.get("findings", []):
                _add_finding(s_find, "package.json")
        except Exception as err:
            logger.warning("Sandbox runner error: %s", err)
            coverage.dynamic_sandbox = EngineStatus.FAILED
    else:
        coverage.dynamic_sandbox = EngineStatus.NOT_CONFIGURED

    # Step 6: Risk Engine (Deterministic Backend Score & Policy Verdict)
    # Backend strictly determines the score and verdict; AI never overrides this
    verdict_enum, calculated_risk = evaluate_policy(all_findings, coverage)
    risk_score, _ = calculate_backend_risk_score(all_findings)
    # Ensure high risk score matches evaluation
    final_risk_score = max(calculated_risk, risk_score)

    if verdict_enum == Verdict.BLOCKED:
        verdict_str = "BLOCK"
    elif verdict_enum in (Verdict.REVIEW_REQUIRED, Verdict.SCAN_ERROR):
        verdict_str = "REVIEW"
    else:
        verdict_str = "PASS"

    # Step 7: BARQAI Correlation & Explanation
    try:
        summary = await barqai_engine.generate_explanation(
            files=files,
            findings=all_findings,
            verdict=verdict_enum,
        )
    except Exception as err:
        logger.warning("BARQAI explanation engine error: %s (using deterministic fallback)", err)
        file_count = len(files)
        summary = ScanSummary(
            what_changed=f"Analyzed {file_count} changed file(s) in PR #{pr_number}.",
            evidence_observed=[f.title for f in all_findings[:4]] or ["No anomalies detected."],
            why_it_matters="Potential supply chain exposure or code vulnerabilities require attention before merging."
            if all_findings
            else "Security baseline satisfied.",
            recommended_actions=[f.recommendation for f in all_findings if f.recommendation][:3]
            or ["Proceed with code review."],
        )

    completed_at = datetime.now(timezone.utc)
    scan = ScanResponse(
        id=scan_id,
        repository=repo_full_name,
        pull_request=pr_number,
        status=ScanStatus.COMPLETED,
        verdict=verdict_enum,
        risk_score=final_risk_score,
        coverage=coverage,
        summary=summary,
        created_at=created_at,
        completed_at=completed_at,
    )

    # Store in mock_store for API and Extension queries
    mock_store.scans[scan.id] = scan
    mock_store.findings_by_scan[scan.id] = all_findings
    mock_store.pr_latest_scan[f"{repo_full_name}#{pr_number}"] = scan.id

    # Step 8: Publish Security Results to GitHub Checks API
    check_summary_md = format_check_summary(
        verdict=verdict_str,
        risk_score=final_risk_score,
        barqai_summary=summary,
        findings=all_findings,
    )
    annotations = format_check_annotations(all_findings)

    try:
        await publish_check(
            owner=owner,
            repo=repo_name,
            head_sha=head_sha,
            installation_token=installation_token,
            verdict=verdict_str,
            summary=check_summary_md,
            annotations=annotations,
        )
        logger.info("Successfully published GitHub Check for %s #%s (Verdict: %s)", repo_full_name, pr_number, verdict_str)
    except Exception as err:
        logger.error("Failed to publish check run to GitHub: %s", err)

    return scan


@router.post("/github/webhook", status_code=status.HTTP_202_ACCEPTED)
@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_delivery: Optional[str] = Header(None, alias="x-github-delivery"),
    x_github_event: Optional[str] = Header(None, alias="x-github-event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="x-hub-signature-256"),
):
    """
    Receives incoming GitHub webhooks for Pull Requests.
    Validates HMAC SHA-256 signature, deduplicates delivery IDs, and kicks off scanning.
    """
    body = await request.body()

    # 1. Determine webhook secret
    secret = os.getenv("GITHUB_WEBHOOK_SECRET") or settings.GITHUB_WEBHOOK_SECRET or ""

    # 2. Verify HMAC SHA-256 signature
    sig_header = x_hub_signature_256 or request.headers.get("x-hub-signature-256")
    verify_github_signature(body, secret, sig_header)

    # 3. Validate presence of delivery ID
    delivery_id = x_github_delivery or request.headers.get("x-github-delivery")
    if not delivery_id:
        raise MissingDeliveryException(message="Missing delivery ID")

    # 4. Check for duplicate delivery ID (idempotency)
    if delivery_id in _processed_deliveries:
        return {
            "status": "ignored",
            "message": "Duplicate delivery ignored.",
            "delivery_id": delivery_id,
        }

    _processed_deliveries.add(delivery_id)

    # 5. Filter event type
    event = x_github_event or request.headers.get("x-github-event")
    if event != "pull_request":
        return {
            "status": "ignored",
            "event": event,
            "message": f"Unsupported event '{event}'. Only 'pull_request' triggers automated scanning.",
        }

    # 6. Parse JSON payload and filter action
    try:
        payload = json.loads(body)
    except Exception:
        payload = await request.json()

    action = payload.get("action")
    if action not in ["opened", "synchronize", "reopened"]:
        return {
            "status": "ignored",
            "action": action,
            "message": f"Action '{action}' does not trigger a scan. Listening to: opened, synchronize, reopened.",
        }

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})

    owner_obj = repo.get("owner", {})
    owner = owner_obj.get("login") if isinstance(owner_obj, dict) else (owner_obj or "")
    if not owner and "/" in repo.get("full_name", ""):
        owner = repo["full_name"].split("/")[0]

    repo_name = repo.get("name") or (repo.get("full_name", "").split("/")[-1] if "/" in repo.get("full_name", "") else "")
    pr_number = pr.get("number")
    head_sha = pr.get("head", {}).get("sha", "0000000000000000000000000000000000000000")
    installation_id = payload.get("installation", {}).get("id")

    if not owner or not repo_name or not pr_number:
        raise HTTPException(status_code=400, detail="Invalid pull request payload: missing owner, repo, or number.")

    # 7. Add processing to FastAPI BackgroundTasks
    background_tasks.add_task(
        process_pull_request,
        owner=owner,
        repo_name=repo_name,
        pr_number=pr_number,
        head_sha=head_sha,
        installation_id=installation_id,
        payload=payload,
    )

    return {
        "status": "queued",
        "delivery_id": delivery_id,
        "event": event,
        "action": action,
        "repository": f"{owner}/{repo_name}",
        "pull_request": pr_number,
        "head_sha": head_sha,
    }


def clear_processed_deliveries() -> None:
    """Clears the set of processed delivery IDs (useful between test runs)."""
    _processed_deliveries.clear()
