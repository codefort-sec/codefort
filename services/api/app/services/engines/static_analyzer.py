"""Static Analyzer Engine: Inspects package scripts, lifecycle hooks, and risky code patterns."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from app.schemas.common import Severity
from app.schemas.finding import FindingBase

# Risky shell and exfiltration patterns in scripts
SUSPICIOUS_SHELL_PATTERNS = [
    (r"curl\s+.*\|\s*(sh|bash)", "Piping remote script from curl directly to shell", Severity.CRITICAL),
    (r"wget\s+.*\|\s*(sh|bash)", "Piping remote script from wget directly to shell", Severity.CRITICAL),
    (r"base64\s+(-d|--decode)", "Decodes base64 payload in lifecycle script", Severity.HIGH),
    (r"/dev/tcp/", "Suspicious direct socket connection / reverse shell indicator", Severity.CRITICAL),
    (r"nc\s+-[e|c]\s+", "Netcat shell execution flag detected", Severity.CRITICAL),
    (r"bash\s+-i\s+>&", "Interactive reverse shell pattern detected", Severity.CRITICAL),
    (r"(env|printenv)\s*\|\s*curl", "Potential environment variable exfiltration via curl", Severity.CRITICAL),
    (r"npm\s+publish", "Suspicious npm publish execution in lifecycle hook", Severity.HIGH),
]


class StaticAnalyzer:
    def __init__(self):
        self.version = "1.0.0"

    def scan_file(self, file_path: str, content: str) -> List[FindingBase]:
        findings: List[FindingBase] = []

        # 1. Detect compiled native binaries (PE Windows executable, Linux ELF, Mach-O)
        if content.startswith("MZ") or "This program cannot be run in DOS mode" in content or content.startswith("\x7fELF"):
            findings.append(
                FindingBase(
                    rule_id="binary.executable.untrusted_artifact",
                    title=f"Untrusted compiled binary executable: {file_path}",
                    description=(
                        f"Detected a compiled native binary executable (Windows PE / ELF) committed as '{file_path}'. "
                        "Software supply chain defense strictly forbids committing unvetted executable binaries directly into source repositories."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_start=1,
                    line_end=1,
                    recommendation="Remove unverified compiled binaries from pull requests. Build artifacts must only be generated via verifiable CI/CD.",
                    confidence=0.99,
                )
            )
            return findings

        # 2. Detect scriptlet / ActiveX / Windows Script Host droppers
        if re.search(r"ActiveXObject|<scriptlet>|WScript\.Shell|BinaryFormatter|FromBase64Transform", content, re.IGNORECASE):
            findings.append(
                FindingBase(
                    rule_id="script.dropper.activex_execution",
                    title=f"Malicious script dropper / ActiveX execution in {file_path}",
                    description=(
                        f"File '{file_path}' contains Windows Script Host or ActiveX automation hooks "
                        "(ActiveXObject, WScript.Shell, scriptlet definitions, or binary deserialization). "
                        "This is a common dropper pattern for secondary payload delivery."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_start=1,
                    line_end=1,
                    recommendation="Remove malicious dropper files from the pull request immediately and quarantine branch.",
                    confidence=0.99,
                )
            )

        # 3. Detect hidden / bypass PowerShell execution
        if re.search(r"powershell(\.exe)?\s+(-exec\s+bypass|-ep\s+bypass|-w\s+hidden|-enc|-encodedcommand)", content, re.IGNORECASE):
            findings.append(
                FindingBase(
                    rule_id="script.dropper.powershell_bypass",
                    title=f"Obfuscated / bypass PowerShell command in {file_path}",
                    description=f"File '{file_path}' invokes PowerShell with execution bypass or hidden window flags.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_start=1,
                    line_end=1,
                    recommendation="Remove unauthorized PowerShell execution logic and review repository changes.",
                    confidence=0.95,
                )
            )

        # 4. Standard package.json lifecycle inspection
        if file_path.endswith("package.json"):
            findings.extend(self._scan_package_json(content, file_path))

        # 5. JavaScript / TypeScript / embedded script inspection (including disguised extensions)
        if file_path.endswith((".js", ".ts", ".mjs", ".cjs", ".hta", ".vbs")) or "<script" in content.lower():
            findings.extend(self._scan_javascript(content, file_path))

        return findings

    def _scan_package_json(self, content: str, file_path: str) -> List[FindingBase]:
        findings: List[FindingBase] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            return findings

        # Check risky lifecycle hooks: preinstall, postinstall, install
        lifecycle_hooks = ["preinstall", "postinstall", "install", "prepare"]
        lines = content.splitlines()

        for hook in lifecycle_hooks:
            cmd = scripts.get(hook)
            if not cmd or not isinstance(cmd, str):
                continue

            # Find line number of this hook in package.json
            line_no = self._find_key_line(lines, hook)

            # 1. Flag any network/shell downloads inside lifecycle hook
            for pattern, reason, severity in SUSPICIOUS_SHELL_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    findings.append(
                        FindingBase(
                            rule_id=f"npm.lifecycle.{hook}.malicious_cmd",
                            title=f"Suspicious execution in '{hook}' script: {reason}",
                            description=(
                                f"The '{hook}' lifecycle hook executes `{cmd}`. "
                                f"This pattern frequently indicates supply chain compromise or remote payload downloading."
                            ),
                            severity=severity,
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            recommendation=(
                                f"Remove the '{hook}' script or avoid executing remote download pipes. "
                                f"Package installation should not execute arbitrary network commands."
                            ),
                            confidence=0.95,
                        )
                    )

            # 2. General warning if preinstall executes node -e
            if hook == "preinstall" and "node -e" in cmd:
                findings.append(
                    FindingBase(
                        rule_id="npm.lifecycle.preinstall.eval",
                        title="Inline JavaScript evaluation in preinstall script",
                        description=f"Script `{cmd}` executes inline JavaScript code during package installation.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        recommendation="Review the inline script thoroughly. Move verified setup logic into standard modules.",
                        confidence=0.85,
                    )
                )

        return findings

    def _scan_javascript(self, content: str, file_path: str) -> List[FindingBase]:
        findings: List[FindingBase] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            # Check for obfuscated eval or child_process invocation
            if re.search(r"child_process\.(exec|execSync|spawn)\s*\(", line):
                findings.append(
                    FindingBase(
                        rule_id="js.process.exec",
                        title="Direct subprocess execution in JavaScript/TypeScript",
                        description="Spawns a shell or external process using child_process.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_start=i,
                        line_end=i,
                        recommendation="Ensure command arguments are strictly sanitized to prevent command injection.",
                        confidence=0.80,
                    )
                )

            if re.search(r"eval\s*\(\s*Buffer\.from\s*\(", line):
                findings.append(
                    FindingBase(
                        rule_id="js.obfuscation.eval_base64",
                        title="Evaluation of base64-decoded buffer (Obfuscated Code)",
                        description="Detected dynamic evaluation of decoded base64 strings.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_start=i,
                        line_end=i,
                        recommendation="Remove obfuscated dynamic code evaluation immediately.",
                        confidence=0.98,
                    )
                )

        return findings

    def _find_key_line(self, lines: List[str], key: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if f'"{key}"' in line or f"'{key}'" in line:
                return idx
        return 1
