"""GitHub Checks API integration for publishing security scan results to pull requests.

Publishes check runs with conclusions (success, neutral, failure), line-level annotations,
and detailed markdown summaries directly to GitHub Pull Requests.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings

logger = logging.getLogger("codefort.github_checks")

# In-memory registry of published check runs for testing, verification, and audit trail
_published_checks: List[Dict[str, Any]] = []

VERDICT_CONCLUSIONS: Dict[str, str] = {
    "PASS": "success",
    "REVIEW": "neutral",
    "BLOCK": "failure",
    # Additional aliases for robustness
    "SUCCESS": "success",
    "NEUTRAL": "neutral",
    "FAILURE": "failure",
    "REVIEW_REQUIRED": "neutral",
    "BLOCKED": "failure",
}


def normalize_verdict(verdict: str) -> str:
    """Normalizes input verdict string to canonical PASS, REVIEW, or BLOCK."""
    v_upper = verdict.strip().upper()
    if v_upper in ("PASS", "SUCCESS", "CLEAN"):
        return "PASS"
    elif v_upper in ("BLOCK", "BLOCKED", "FAILURE", "CRITICAL"):
        return "BLOCK"
    elif v_upper in ("REVIEW", "REVIEW_REQUIRED", "NEUTRAL", "WARNING"):
        return "REVIEW"
    elif v_upper in VERDICT_CONCLUSIONS:
        return v_upper
    raise ValueError(f"Invalid security verdict: {verdict}")


async def publish_check(
    owner: str,
    repo: str,
    head_sha: str,
    installation_token: Optional[str] = None,
    verdict: str = "REVIEW",
    summary: str = "",
    annotations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Publishes a check run to the GitHub Checks API for the specified commit SHA.

    Maps:
      - PASS   -> success
      - REVIEW -> neutral
      - BLOCK  -> failure

    Args:
        owner: GitHub repository owner / organization.
        repo: Repository name.
        head_sha: Exact PR head commit SHA.
        installation_token: Optional GitHub App installation access token.
        verdict: 'PASS', 'REVIEW', or 'BLOCK'.
        summary: Markdown explanation summary for the check run.
        annotations: Optional list of line-level annotations.

    Returns:
        Dict containing check run details (GitHub API response or simulated payload).
    """
    # 1. Validate and map verdict to conclusion
    try:
        canonical_verdict = normalize_verdict(verdict)
    except ValueError:
        raise ValueError(f"Invalid security verdict: {verdict}")

    conclusion = VERDICT_CONCLUSIONS.get(canonical_verdict)
    if not conclusion:
        raise ValueError(f"Invalid security verdict: {verdict}")

    # 2. Construct output payload
    output: Dict[str, Any] = {
        "title": f"CODEFORT: {canonical_verdict}",
        "summary": summary or f"CODEFORT Security analysis completed with verdict: {canonical_verdict}",
    }
    if annotations:
        # GitHub Checks API caps annotations at 50 per request
        output["annotations"] = annotations[:50]

    payload: Dict[str, Any] = {
        "name": "CODEFORT Security",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": output,
    }

    # 3. Determine active token
    token = installation_token or getattr(settings, "GITHUB_TOKEN", None) or os.environ.get("GITHUB_TOKEN")

    check_record: Dict[str, Any] = {
        "id": int(uuid.uuid4().int % 10_000_000),
        "owner": owner,
        "repo": repo,
        "head_sha": head_sha,
        "verdict": canonical_verdict,
        "conclusion": conclusion,
        "payload": payload,
        "published_at": datetime.now(timezone.utc).isoformat(),
        "simulated": True,
    }

    # 4. Attempt live GitHub API call if token provided
    if token and not os.environ.get("CODEFORT_OFFLINE_MODE"):
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CODEFORT-Security-Scanner",
        }
        url = f"https://api.github.com/repos/{owner}/{repo}/check-runs"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                if res.status_code in (200, 201):
                    api_data = res.json()
                    check_record["id"] = api_data.get("id", check_record["id"])
                    check_record["html_url"] = api_data.get("html_url")
                    check_record["simulated"] = False
                    logger.info("Successfully published GitHub check run %s to %s/%s", check_record["id"], owner, repo)
                else:
                    logger.warning(
                        "GitHub Checks API returned %s: %s (falling back to simulated record)",
                        res.status_code,
                        res.text[:200],
                    )
        except Exception as err:
            logger.warning("Error communicating with GitHub Checks API: %s (falling back to simulated record)", err)

    _published_checks.append(check_record)
    return check_record


def format_check_summary(
    verdict: str,
    risk_score: int,
    barqai_summary: Any,
    findings: List[Any],
    remediation_text: Optional[str] = None,
) -> str:
    """
    Formats a rich GitHub-compatible Markdown check summary.

    Includes:
      - Overall verdict and risk score
      - BARQAI analysis and explanation
      - Categorized security findings
      - Suggested remediation steps
    """
    v_upper = verdict.strip().upper()
    badge = "🟢 PASS" if v_upper == "PASS" else ("🟡 REVIEW REQUIRED" if v_upper == "REVIEW" else "🔴 BLOCKED")

    lines = [
        f"## CODEFORT Security Check — {badge}",
        f"**Risk Score:** `{risk_score}/100` | **Verdict:** `{v_upper}`",
        "",
        "### 🧠 BARQAI Security Intelligence",
    ]

    if hasattr(barqai_summary, "what_changed"):
        lines.append(f"**What Changed:** {barqai_summary.what_changed}")
    elif isinstance(barqai_summary, dict) and "what_changed" in barqai_summary:
        lines.append(f"**What Changed:** {barqai_summary['what_changed']}")

    if hasattr(barqai_summary, "why_it_matters"):
        lines.append(f"**Impact Assessment:** {barqai_summary.why_it_matters}")
    elif isinstance(barqai_summary, dict) and "why_it_matters" in barqai_summary:
        lines.append(f"**Impact Assessment:** {barqai_summary['why_it_matters']}")

    if hasattr(barqai_summary, "evidence_observed") and barqai_summary.evidence_observed:
        lines.append("")
        lines.append("**Evidence Observed:**")
        for ev in barqai_summary.evidence_observed[:5]:
            lines.append(f"- {ev}")
    elif isinstance(barqai_summary, dict) and barqai_summary.get("evidence_observed"):
        lines.append("")
        lines.append("**Evidence Observed:**")
        for ev in barqai_summary["evidence_observed"][:5]:
            lines.append(f"- {ev}")

    lines.append("")
    lines.append("### 🔍 Detected Security Findings")

    if not findings:
        lines.append("✅ No critical vulnerabilities or suspicious supply chain indicators detected.")
    else:
        for f in findings[:10]:
            title = getattr(f, "title", None) or (f.get("title") if isinstance(f, dict) else "Security finding")
            sev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "MEDIUM")
            sev_str = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
            file_path = getattr(f, "file_path", None) or (f.get("file_path") if isinstance(f, dict) else "")
            line_no = getattr(f, "line_start", None) or (f.get("line_start") if isinstance(f, dict) else "")
            loc = f" (`{file_path}:{line_no}`)" if file_path else ""
            lines.append(f"- **[{sev_str}]** {title}{loc}")

    lines.append("")
    lines.append("### 🛠️ Remediation & Recommendations")
    if remediation_text:
        lines.append(remediation_text)
    elif hasattr(barqai_summary, "recommended_actions") and barqai_summary.recommended_actions:
        for action in barqai_summary.recommended_actions[:4]:
            lines.append(f"- {action}")
    else:
        lines.append("- Review modified code and verified security findings prior to merging.")

    lines.append("")
    lines.append("---")
    lines.append("*Automated analysis by CODEFORT Security Engine & BARQAI Intelligence.*")

    return "\n".join(lines)


def format_check_annotations(findings: List[Any]) -> List[Dict[str, Any]]:
    """Converts normalized findings into GitHub Checks API line-level annotations."""
    annotations: List[Dict[str, Any]] = []

    for f in findings:
        file_path = getattr(f, "file_path", None) or (f.get("file_path") if isinstance(f, dict) else None)
        if not file_path:
            continue

        line_start = getattr(f, "line_start", None) or (f.get("line_start") if isinstance(f, dict) else 1) or 1
        line_end = getattr(f, "line_end", None) or (f.get("line_end") if isinstance(f, dict) else line_start) or line_start

        sev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "MEDIUM")
        sev_str = (sev.value.upper() if hasattr(sev, "value") else str(sev)).upper()

        if sev_str in ("CRITICAL", "HIGH"):
            level = "failure"
        elif sev_str == "MEDIUM":
            level = "warning"
        else:
            level = "notice"

        title = getattr(f, "title", None) or (f.get("title") if isinstance(f, dict) else "Security finding")
        desc = getattr(f, "description", None) or (f.get("description") if isinstance(f, dict) else title)
        recomm = getattr(f, "recommendation", None) or (f.get("recommendation") if isinstance(f, dict) else "")

        msg = desc
        if recomm:
            msg += f"\nRecommendation: {recomm}"

        annotations.append({
            "path": file_path,
            "start_line": max(1, line_start),
            "end_line": max(1, line_end),
            "annotation_level": level,
            "title": f"CODEFORT: {title[:60]}",
            "message": msg[:500],
        })

    return annotations


def get_published_checks(head_sha: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all published check runs or checks matching a specific commit SHA."""
    if head_sha:
        return [c for c in _published_checks if c.get("head_sha") == head_sha]
    return list(_published_checks)


def clear_published_checks() -> None:
    """Clears the in-memory checks registry (useful between test cases)."""
    _published_checks.clear()
