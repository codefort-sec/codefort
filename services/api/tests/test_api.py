"""Comprehensive tests for CodeFort API endpoints and contracts."""

import hashlib
import hmac
import pytest
from httpx import ASGITransport, AsyncClient
from app.core.config import settings
from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data
    assert "x-request-id" in response.headers


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "CodeFort API"


@pytest.mark.asyncio
async def test_uniform_error_envelope_not_found(client: AsyncClient):
    response = await client.get("/api/v1/scans/non_existent_scan_id")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert "request_id" in data["error"]
    assert data["error"]["request_id"].startswith("req_")


@pytest.mark.asyncio
async def test_uniform_error_envelope_validation_error(client: AsyncClient):
    # Invalid PR number (e.g. 0 when ge=1)
    response = await client.get("/api/v1/extension/pr-status?repo=owner/repo&pr=0")
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "SCHEMA_VALIDATION_ERROR"
    assert "request_id" in data["error"]


@pytest.mark.asyncio
async def test_extension_pr_status(client: AsyncClient):
    response = await client.get("/api/v1/extension/pr-status?repo=owner/repo&pr=42")
    assert response.status_code == 200
    data = response.json()
    assert data["repository"] == "owner/repo"
    assert data["pull_request"] == 42
    assert data["status"] == "completed"
    assert data["verdict"] in ["REVIEW_REQUIRED", "BLOCKED"]
    assert data["risk_score"] > 0
    assert data["findings_count"]["high"] >= 1
    assert data["coverage"]["static_analysis"] == "completed"


@pytest.mark.asyncio
async def test_extension_findings(client: AsyncClient):
    response = await client.get("/api/v1/extension/findings?repo=owner/repo&pr=42")
    assert response.status_code == 200
    data = response.json()
    assert data["repository"] == "owner/repo"
    assert len(data["findings"]) >= 1
    finding = data["findings"][0]
    assert finding["file_path"] == "package.json"
    assert finding["line_start"] == 12
    assert finding["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_extension_summary(client: AsyncClient):
    response = await client.get("/api/v1/extension/summary?repo=owner/repo&pr=42")
    assert response.status_code == 200
    data = response.json()
    assert data["summary"] is not None
    assert len(data["summary"]["evidence_observed"]) >= 1


@pytest.mark.asyncio
async def test_extension_pairing_flow(client: AsyncClient):
    # 1. Create token
    resp1 = await client.post("/api/v1/extension/pairing-tokens")
    assert resp1.status_code == 200
    token = resp1.json()["pairing_token"]
    assert token.startswith("pair_")

    # 2. Exchange token
    resp2 = await client.post("/api/v1/extension/pair", json={"pairing_token": token})
    assert resp2.status_code == 200
    pair_data = resp2.json()
    assert pair_data["token_type"] == "bearer"
    assert pair_data["access_token"].startswith("ext_")

    # 3. Re-exchanging used token should fail
    resp3 = await client.post("/api/v1/extension/pair", json={"pairing_token": token})
    assert resp3.status_code == 404


@pytest.mark.asyncio
async def test_scan_endpoints(client: AsyncClient):
    # 1. Get scan details
    resp = await client.get("/api/v1/scans/scan_123")
    assert resp.status_code == 200
    scan = resp.json()
    assert scan["id"] == "scan_123"
    assert scan["verdict"] in ["REVIEW_REQUIRED", "BLOCKED"]

    # 2. Get findings
    resp_findings = await client.get("/api/v1/scans/scan_123/findings")
    assert resp_findings.status_code == 200
    findings = resp_findings.json()
    assert findings["total"] >= 2

    # 3. Queue a scan
    resp_queue = await client.post(
        "/api/v1/repositories/owner/repo/pull-requests/99/scans",
        json={"head_sha": "abc1234"},
    )
    assert resp_queue.status_code == 202
    assert resp_queue.json()["pull_request"] == 99


@pytest.mark.asyncio
async def test_trigger_scan_dynamic_execution(client: AsyncClient):
    resp = await client.post(
        "/api/v1/repositories/codefort-sec/vulnerable-test-repo/pull-requests/1/scans",
        json={},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "completed"
    assert data["verdict"] == "BLOCKED"
    assert data["risk_score"] is not None and data["risk_score"] >= 70
    assert data["summary"] is not None



@pytest.mark.asyncio
async def test_github_webhook_hmac_and_dedup(client: AsyncClient):
    payload = b'{"action":"opened","pull_request":{"number":100,"head":{"sha":"fedcba"}},"repository":{"full_name":"owner/repo"}}'
    secret = settings.GITHUB_WEBHOOK_SECRET
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    # 1. Valid signature
    resp = await client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "x-github-delivery": "deliv_001",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "queued"

    # 2. Duplicate delivery
    resp_dup = await client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "x-github-delivery": "deliv_001",
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
    )
    assert resp_dup.status_code == 202
    assert resp_dup.json()["status"] == "ignored"

    # 3. Invalid signature
    resp_bad_sig = await client.post(
        "/api/v1/webhooks/github",
        content=payload,
        headers={
            "x-github-delivery": "deliv_002",
            "x-github-event": "pull_request",
            "x-hub-signature-256": "sha256=invalid_signature_hash_value_123456",
            "content-type": "application/json",
        },
    )
    assert resp_bad_sig.status_code == 403
    assert resp_bad_sig.json()["error"]["code"] == "INVALID_SIGNATURE"


@pytest.mark.asyncio
async def test_list_pull_requests_benchmark_and_fixtures(client: AsyncClient):
    # 1. Vulnerable benchmark repo has 3 PRs
    resp1 = await client.get("/api/v1/repositories/codefort-sec/vulnerable-test-repo/pull-requests")
    assert resp1.status_code == 200
    prs1 = resp1.json()
    assert len(prs1) == 3
    assert prs1[0]["pull_request_number"] == 1
    assert prs1[1]["pull_request_number"] == 2
    assert prs1[2]["pull_request_number"] == 3

    # 2. Clean benchmark repo has 1 PR
    resp2 = await client.get("/api/v1/repositories/codefort-sec/clean-test-repo/pull-requests")
    assert resp2.status_code == 200
    prs2 = resp2.json()
    assert len(prs2) == 1
    assert prs2[0]["pull_request_number"] == 1

    # 3. Test fixture owner/repo
    resp3 = await client.get("/api/v1/repositories/owner/repo/pull-requests")
    assert resp3.status_code == 200
    prs3 = resp3.json()
    assert len(prs3) >= 1
    assert any(p["pull_request_number"] == 42 for p in prs3)

