"""Workflow Linter Engine: Safely parses GitHub Actions YAML to detect CI/CD security risks."""

import re
from typing import Any, Dict, List
import yaml
from app.schemas.common import Severity
from app.schemas.finding import FindingBase

# Expressions that are untrusted and attacker-controlled in pull requests
UNTRUSTED_GITHUB_EXPRESSIONS = [
    r"\$\{\{\s*github\.event\.issue\.title\s*\}\}",
    r"\$\{\{\s*github\.event\.issue\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.commits\[.*\]\.message\s*\}\}",
    r"\$\{\{\s*github\.head_ref\s*\}\}",
]


class WorkflowLinter:
    def __init__(self):
        self.version = "1.0.0"

    def scan_file(self, file_path: str, content: str) -> List[FindingBase]:
        findings: List[FindingBase] = []

        # Only inspect GitHub Actions workflow files (.github/workflows/*.yml or *.yaml)
        if not (".github/workflows/" in file_path and file_path.endswith((".yml", ".yaml"))):
            return findings

        try:
            parsed = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(parsed, dict):
            return findings

        lines = content.splitlines()

        # 1. Check for dangerous triggers (pull_request_target)
        triggers = parsed.get("on") or parsed.get(True)  # yaml parses 'on' as boolean True
        if self._has_pull_request_target(triggers):
            # Check if workflow checks out the untrusted head ref
            if "pull_request.head.sha" in content or "github.head_ref" in content:
                line_no = self._find_line(lines, "pull_request_target")
                findings.append(
                    FindingBase(
                        rule_id="gha.trigger.pull_request_target_checkout",
                        title="Dangerous 'pull_request_target' trigger with PR head checkout",
                        description=(
                            "The workflow runs with write permissions/secrets via 'pull_request_target' "
                            "while checking out untrusted code from the pull request head."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        recommendation=(
                            "Switch trigger to standard 'pull_request', or avoid checking out "
                            "the untrusted head branch in a privileged workflow."
                        ),
                        confidence=0.98,
                    )
                )

        # 2. Check for write-all permissions
        perms = parsed.get("permissions")
        if perms == "write-all":
            line_no = self._find_line(lines, "write-all")
            findings.append(
                FindingBase(
                    rule_id="gha.permissions.write_all",
                    title="Excessive permissions: 'write-all' granted to GITHUB_TOKEN",
                    description="The workflow grants full write permissions to the default GITHUB_TOKEN.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    recommendation="Apply principle of least privilege. Explicitly specify only the required read/write scopes.",
                    confidence=0.95,
                )
            )

        # 3. Check for expression injection inside run: steps
        jobs = parsed.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                steps = job_data.get("steps", [])
                if isinstance(steps, list):
                    for step in steps:
                        if not isinstance(step, dict):
                            continue
                        
                        # Check step run scripts for expression injection
                        run_script = step.get("run")
                        if run_script and isinstance(run_script, str):
                            for expr in UNTRUSTED_GITHUB_EXPRESSIONS:
                                if re.search(expr, run_script):
                                    line_no = self._find_regex_line(lines, expr)
                                    findings.append(
                                        FindingBase(
                                            rule_id="gha.injection.inline_expression",
                                            title="Untrusted context expression directly interpolated in 'run' script",
                                            description=(
                                                "Attacker-controlled PR or issue fields are directly evaluated in a shell step. "
                                                "An attacker can submit a PR with quotes in the title to execute arbitrary code in CI."
                                            ),
                                            severity=Severity.CRITICAL,
                                            file_path=file_path,
                                            line_start=line_no,
                                            line_end=line_no,
                                            recommendation="Pass the value through environment variables (env:) instead of inline expressions.",
                                            confidence=0.96,
                                        )
                                    )

                        # Check unpinned 3rd-party actions
                        uses = step.get("uses")
                        if uses and isinstance(uses, str) and not uses.startswith("./"):
                            # If action does not use an immutable 40-char SHA
                            if not re.search(r"@[a-f0-9]{40}$", uses) and not uses.startswith("actions/"):
                                line_no = self._find_line(lines, uses)
                                findings.append(
                                    FindingBase(
                                        rule_id="gha.pinning.unpinned_action",
                                        title=f"Third-party action '{uses}' is not pinned to a full commit SHA",
                                        description="Using mutable tags (e.g., @v1 or @master) leaves the pipeline vulnerable to upstream tag tampering.",
                                        severity=Severity.LOW,
                                        file_path=file_path,
                                        line_start=line_no,
                                        line_end=line_no,
                                        recommendation="Pin the action to an immutable 40-character commit SHA.",
                                        confidence=0.85,
                                    )
                                )

        return findings

    def _has_pull_request_target(self, triggers: Any) -> bool:
        if isinstance(triggers, str):
            return triggers == "pull_request_target"
        if isinstance(triggers, list):
            return "pull_request_target" in triggers
        if isinstance(triggers, dict):
            return "pull_request_target" in triggers
        return False

    def _find_line(self, lines: List[str], target: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if target in line:
                return idx
        return 1

    def _find_regex_line(self, lines: List[str], pattern: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                return idx
        return 1
