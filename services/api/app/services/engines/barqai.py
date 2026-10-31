"""BARQAI Explanation Engine: Synthesizes evidence-linked risk narratives using Google Gemini with deterministic fallback."""

import json
import logging
from typing import Dict, List, Optional
import httpx

from app.core.config import settings
from app.schemas.common import Verdict
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanSummary

logger = logging.getLogger("codefort.barqai")


class BarqAIEngine:
    """Zero-trust AI explanation engine that links concrete evidence to security narratives."""

    def __init__(self):
        import os
        self.provider = settings.LLM_PROVIDER
        self.api_key = settings.LLM_API_KEY or settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY") or os.environ.get("LLM_API_KEY")
        self.gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent"

    async def generate_explanation(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> ScanSummary:
        """Generates a structured ScanSummary using Gemini if available, or deterministic rules."""
        if self.api_key and self.provider == "gemini":
            try:
                ai_summary = await self._call_gemini(files, findings, verdict)
                if ai_summary:
                    return ai_summary
            except Exception as e:
                logger.warning(f"BARQAI Gemini call failed, falling back to deterministic explanation: {e}")

        # Deterministic fallback guaranteed to produce clean, factual explanations
        return self._generate_deterministic(files, findings, verdict)

    async def _call_gemini(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> Optional[ScanSummary]:
        """Calls Google Gemini API with strict JSON schema constraints."""
        findings_context = []
        for f in findings:
            findings_context.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file_path,
                "line": f.line_start,
                "recommendation": f.recommendation,
            })

        prompt = (
            "You are BARQAI, the AI zero-trust code security auditor for CodeFort.\n"
            "Analyze the pull request changes and detected security findings below.\n\n"
            f"Verdict: {verdict.value}\n"
            f"Modified Files: {list(files.keys())}\n"
            f"Detected Findings: {json.dumps(findings_context, indent=2)}\n\n"
            "Requirements:\n"
            "1. Output ONLY valid JSON matching this schema:\n"
            "{\n"
            '  "what_changed": "High-level summary of modified code or dependencies",\n'
            '  "evidence_observed": ["Specific indicator 1", "Specific indicator 2"],\n'
            '  "why_it_matters": "Clear explanation of risk impact (e.g. runner takeover, credential leakage)",\n'
            '  "recommended_actions": ["Specific mitigation 1", "Specific mitigation 2"]\n'
            "}\n"
            "2. Do NOT invent findings or hallucinate evidence that is not in Detected Findings.\n"
            "3. Keep language concise, technical, and actionable."
        )

        request_body = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800,
                "responseMimeType": "application/json",
            },
        }

        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                f"{self.gemini_url}?key={self.api_key}",
                json=request_body,
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        raw_json = parts[0].get("text", "{}").strip()
                        if raw_json.startswith("```json"):
                            raw_json = raw_json[7:]
                        if raw_json.startswith("```"):
                            raw_json = raw_json[3:]
                        if raw_json.endswith("```"):
                            raw_json = raw_json[:-3]
                        raw_json = raw_json.strip()
                        parsed = json.loads(raw_json)
                        return ScanSummary(
                            what_changed=parsed.get("what_changed", "Code modifications analyzed."),
                            evidence_observed=parsed.get("evidence_observed", []),
                            why_it_matters=parsed.get("why_it_matters", "Security impact evaluated."),
                            recommended_actions=parsed.get("recommended_actions", []),
                        )

        return None

    def _generate_deterministic(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> ScanSummary:
        """Deterministic, zero-hallucination security narrative generation."""
        file_names = list(files.keys())
        what_changed = f"Modified {len(file_names)} file(s): {', '.join(file_names[:3])}"
        if len(file_names) > 3:
            what_changed += f" and {len(file_names) - 3} more."

        if not findings:
            return ScanSummary(
                what_changed=what_changed,
                evidence_observed=["No security anomalies or high-risk patterns detected across scanned files."],
                why_it_matters="All evaluated files satisfied the configured organizational security baseline.",
                recommended_actions=["Proceed with standard peer code review."],
            )

        evidence = [f.title for f in findings[:4]]
        recomms = [f.recommendation for f in findings if f.recommendation][:3]

        if verdict == Verdict.BLOCKED:
            why_it_matters = (
                "Critical malicious execution patterns or severe CI/CD vulnerabilities detected. "
                "Merging this PR poses an immediate security compromise risk."
            )
        elif verdict == Verdict.REVIEW_REQUIRED:
            why_it_matters = (
                "Suspicious lifecycle hooks, potential dependency typosquats, or workflow permission issues "
                "require explicit human security review before merging."
            )
        else:
            why_it_matters = "Security baseline met with minor non-blocking informational advisories."

        return ScanSummary(
            what_changed=what_changed,
            evidence_observed=evidence,
            why_it_matters=why_it_matters,
            recommended_actions=recomms or ["Review modified lines before approval."],
        )


barqai_engine = BarqAIEngine()
