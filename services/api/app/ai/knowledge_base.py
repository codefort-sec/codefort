"""Security Attack Knowledge Base & Exemplar Store for BARQAI.

Provides domain-specific attack taxonomy and few-shot exemplars drawn from real-world
software supply chain incidents (e.g. event-stream, ua-parser-js, dependency confusion,
pwn_request CI/CD attacks) to prime and train Qwen's in-context security reasoning.
"""

from __future__ import annotations

import re
from typing import Any


ATTACK_EXEMPLARS: list[dict[str, Any]] = [
    {
        "id": "supply_chain_lifecycle_hook",
        "name": "NPM Lifecycle Hook Exfiltration (ua-parser-js / event-stream pattern)",
        "trigger_keywords": ["preinstall", "postinstall", "curl", "wget", "bash", "sh -c"],
        "exemplar_summary": {
            "what_changed": "Package introduces a preinstall or postinstall script executing external commands.",
            "what_happened": "During install script execution, child process executed curl/wget to an external IP/domain and touched sensitive system files.",
            "why_dangerous": "NPM lifecycle scripts run automatically upon 'npm install'. Attackers abuse this to achieve Remote Code Execution before application code runs, exfiltrating developer tokens and environment secrets.",
            "risk_factors": [
                "Automated execution during package installation phase",
                "Arbitrary command execution via shell interpreter",
                "Outbound egress to unverified host during dependency resolution",
            ],
            "recommended_action": "block",
        },
    },
    {
        "id": "typosquatting_impersonation",
        "name": "Dependency Typosquatting & Brandjacking",
        "trigger_keywords": ["lodashe", "expres", "reaact", "axois", "crossenv"],
        "exemplar_summary": {
            "what_changed": "New dependency added with a name suspiciously close (Levenshtein distance 1-2) to a widely trusted package.",
            "what_happened": "Registry intelligence shows newly created package with zero reverse dependencies and deceptive naming.",
            "why_dangerous": "Typosquatting exploits developer typing errors to deliver trojanized clones of legitimate libraries. The package may mirror benign functionality while harboring steganographic backdoors.",
            "risk_factors": [
                "Package name mimics high-profile open-source library",
                "Untrusted author with recent release timestamp",
                "Lack of upstream provenance or verified source repository",
            ],
            "recommended_action": "block",
        },
    },
    {
        "id": "obfuscated_dynamic_code",
        "name": "Multi-Stage Obfuscated Payload Execution",
        "trigger_keywords": ["base64", "b64decode", "fromCharCode", "eval(", "exec(", "\\x"],
        "exemplar_summary": {
            "what_changed": "Source file introduces hex-encoded literals or base64 decode chained directly into an execution sink.",
            "what_happened": "Static analyzer flagged base64 decode chained into eval(); sandbox confirmed runtime execution of dynamic payload.",
            "why_dangerous": "Obfuscation is deliberately employed by threat actors to evade static code analyzers and code review by concealing malicious URLs, dropped binaries, or reverse shell primitives.",
            "risk_factors": [
                "Deliberate anti-analysis evasion tactics",
                "Runtime execution of dynamic unverified code string",
                "Potential payload staging or remote stager retrieval",
            ],
            "recommended_action": "block",
        },
    },
    {
        "id": "cicd_pwn_request",
        "name": "GitHub Actions PwnRequest & Secret Exfiltration",
        "trigger_keywords": ["pull_request_target", "github.event.pull_request.head", "secrets.", "${{ github.event"],
        "exemplar_summary": {
            "what_changed": "Workflow configuration binds pull_request_target with an untrusted checkout of fork head, or injects github.event expressions into bash run steps.",
            "what_happened": "Workflow linter flagged expression injection and high-privilege execution context on untrusted PR triggers.",
            "why_dangerous": "pull_request_target runs in the context of the base repository with full access to repository secrets and write tokens. Checking out untrusted PR head code allows hostile forks to extract repository secrets (AWS, NPM, PyPI tokens).",
            "risk_factors": [
                "Privilege boundary collapse in CI/CD pipeline",
                "Exfiltration vector for production repository secrets",
                "Arbitrary command execution via unsanitized GitHub event parameters",
            ],
            "recommended_action": "block",
        },
    },
    {
        "id": "benign_false_positive_trap",
        "name": "Legitimate Dynamic Code (Parser / AST / Compiler)",
        "trigger_keywords": ["parse", "ast", "visitor", "eval_expression", "math", "sanitize"],
        "exemplar_summary": {
            "what_changed": "PR introduces mathematical expression parsing or sandboxed evaluation without shell sinks or outbound egress.",
            "what_happened": "Sandbox execution verified zero network calls, zero anomalous syscalls, and all file operations remained inside the project root.",
            "why_dangerous": "While terms like 'eval' or dynamic parsing may match shallow static keywords, sandbox evidence confirms the implementation is mathematically bounded, contains no network sockets, and presents no supply chain risk.",
            "risk_factors": [],
            "recommended_action": "pass",
        },
    },
]


def retrieve_relevant_exemplars(
    diff_text: str,
    findings: list[dict[str, Any]],
    telemetry: dict[str, Any],
    max_exemplars: int = 2,
) -> list[dict[str, Any]]:
    """Retrieves top matching attack exemplars based on keyword and threat signal scoring."""
    combined_text = (
        (diff_text or "")
        + " "
        + " ".join(f.get("title", "") + " " + f.get("description", "") for f in findings)
        + " "
        + str(telemetry)
    ).lower()

    scored: list[tuple[int, dict[str, Any]]] = []

    for ex in ATTACK_EXEMPLARS:
        score = sum(1 for kw in ex["trigger_keywords"] if kw.lower() in combined_text)
        if score > 0:
            scored.append((score, ex))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored[:max_exemplars]]


def format_exemplars_for_prompt(exemplars: list[dict[str, Any]]) -> str:
    """Formats retrieved exemplars into structured in-context guidance for Qwen."""
    if not exemplars:
        return ""

    blocks = ["## Domain Security Exemplars (Few-Shot Context)"]
    for ex in exemplars:
        summ = ex["exemplar_summary"]
        blocks.append(
            f"### Pattern: {ex['name']}\n"
            f"- Observed Signal: {summ['what_changed']}\n"
            f"- Impact Analysis: {summ['why_dangerous']}\n"
            f"- Recommended Verdict: {summ['recommended_action'].upper()}\n"
        )
    return "\n".join(blocks)
