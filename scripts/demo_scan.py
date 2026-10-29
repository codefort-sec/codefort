#!/usr/bin/env python3
"""CodeFort Demo Runner: Scans synthetic PR scenarios and outputs cyber-brutalist security reports."""

import asyncio
import os
import sys

# Ensure services/api is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/api")))

from app.schemas.common import Verdict
from app.services.engines.orchestrator import orchestrator

GREEN = "\033[92m"
AMBER = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"
LIME = "\033[38;2;215;255;53m"


def color_verdict(verdict: Verdict) -> str:
    if verdict == Verdict.BLOCKED:
        return f"{RED}{BOLD}■ BLOCKED{RESET}"
    elif verdict == Verdict.REVIEW_REQUIRED:
        return f"{AMBER}{BOLD}▲ REVIEW_REQUIRED{RESET}"
    return f"{GREEN}{BOLD}✓ PASS{RESET}"


async def run_scenario(name: str, files: dict, pr_num: int):
    print(f"\n{LIME}┌────────────────────────────────────────────────────────────────────────┐{RESET}")
    print(f"{LIME}│{RESET} {BOLD}SCANNING PR SCENARIO #{pr_num}: {name:<46}{RESET} {LIME}│{RESET}")
    print(f"{LIME}└────────────────────────────────────────────────────────────────────────┘{RESET}")

    scan, findings = await orchestrator.execute_scan(
        repository="codefort-sec/demo-target",
        pull_request=pr_num,
        files=files,
    )

    print(f"VERDICT:    {color_verdict(scan.verdict)}")
    print(f"RISK SCORE: {LIME}{scan.risk_score}{RESET} / 100")
    print(f"FINDINGS:   {len(findings)} detected")

    if scan.summary:
        print(f"\n{BOLD}BARQAI Structured Explanation:{RESET}")
        print(f"  {BOLD}What Changed:{RESET}   {scan.summary.what_changed}")
        print(f"  {BOLD}Why It Matters:{RESET} {scan.summary.why_it_matters}")
        if scan.summary.evidence_observed:
            print(f"  {BOLD}Evidence:{RESET}")
            for ev in scan.summary.evidence_observed:
                print(f"    › {ev}")

    if findings:
        print(f"\n{BOLD}Detailed Findings:{RESET}")
        for idx, f in enumerate(findings, 1):
            sev_color = RED if f.severity in ("CRITICAL", "HIGH") else AMBER
            print(f"  [{idx}] {sev_color}[{f.severity}]{RESET} {f.title}")
            print(f"      Rule:     {f.rule_id}")
            print(f"      Location: {f.file_path}:{f.line_start}")
            if f.recommendation:
                print(f"      Fix:      {f.recommendation}")


async def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../fixtures/scenarios"))

    # Scenario 1: Malicious preinstall hook
    with open(os.path.join(base_dir, "01_malicious_preinstall/package.json")) as f:
        pkg1 = f.read()
    await run_scenario("Malicious Preinstall Shell Pipe", {"package.json": pkg1}, 101)

    # Scenario 2: Typosquatted dependencies
    with open(os.path.join(base_dir, "02_typosquat_dependency/package.json")) as f:
        pkg2 = f.read()
    await run_scenario("Typosquatted Dependency (crypt0-js)", {"package.json": pkg2}, 102)

    # Scenario 3: Unsafe GitHub Actions Workflow
    with open(os.path.join(base_dir, "03_unsafe_workflow_injection/.github/workflows/ci.yml")) as f:
        wf = f.read()
    await run_scenario("GitHub Actions Script Injection", {".github/workflows/ci.yml": wf}, 103)

    # Scenario 4: Clean Feature PR
    with open(os.path.join(base_dir, "04_clean_feature_pr/package.json")) as f:
        pkg4 = f.read()
    with open(os.path.join(base_dir, "04_clean_feature_pr/src/index.ts")) as f:
        src4 = f.read()
    await run_scenario("Clean Feature PR (Benign)", {"package.json": pkg4, "src/index.ts": src4}, 104)

    print(f"\n{LIME}✓ All 4 scenarios completed analysis successfully.{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
