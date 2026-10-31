"""BARQAI Explanation Engine: Synthesizes evidence-linked risk narratives using Qwen3.8-Max via OpenRouter with deterministic fallback."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
import httpx
try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None

from app.core.config import settings
from app.schemas.common import Verdict
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanSummary
from app.ai.knowledge_base import format_exemplars_for_prompt, retrieve_relevant_exemplars

logger = logging.getLogger("codefort.barqai")


class BarqAIEngine:
    """Zero-trust AI explanation engine that links concrete evidence to security narratives using Qwen3.8-Max."""

    def __init__(self):
        self.provider = settings.LLM_PROVIDER
        self.openrouter_api_key = settings.OPENROUTER_API_KEY or settings.LLM_API_KEY
        self.openrouter_base_url = settings.OPENROUTER_BASE_URL
        self.model = settings.OPENROUTER_MODEL
        self.reasoning = settings.OPENROUTER_REASONING
        self.gemini_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

    def _get_openrouter_client(self) -> Optional[AsyncOpenAI]:
        if AsyncOpenAI is None:
            return None
        return AsyncOpenAI(
            api_key=self.openrouter_api_key,
            base_url=self.openrouter_base_url,
            default_headers={
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "CodeFort BARQAI",
            },
        )

    async def generate_explanation(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> ScanSummary:
        """Generates a structured ScanSummary using Qwen3.8-Max, Gemini fallback, or deterministic rules."""
        # 1. Primary: Qwen3.8-Max via OpenRouter
        if self.openrouter_api_key and ("openrouter" in self.provider.lower() or "qwen" in self.provider.lower()):
            try:
                ai_summary = await self._call_qwen(files, findings, verdict)
                if ai_summary:
                    return ai_summary
            except Exception as e:
                logger.warning(f"BARQAI Qwen call failed, attempting fallback: {e}")

        # 2. Secondary: Gemini Fallback
        if settings.LLM_API_KEY and self.provider == "gemini":
            try:
                ai_summary = await self._call_gemini(files, findings, verdict)
                if ai_summary:
                    return ai_summary
            except Exception as e:
                logger.warning(f"BARQAI Gemini call failed: {e}")

        # 3. Deterministic zero-hallucination fallback
        return self._generate_deterministic(files, findings, verdict)

    async def _call_qwen(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> Optional[ScanSummary]:
        """Calls Qwen3.8-Max via OpenRouter with few-shot in-context attack exemplars."""
        findings_context = []
        findings_for_exemplars = []
        for f in findings:
            item = {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file_path,
                "line": f.line_start,
                "recommendation": f.recommendation,
            }
            findings_context.append(item)
            findings_for_exemplars.append({"title": f.title, "description": f.description or ""})

        # Dynamic few-shot attack exemplar retrieval
        combined_diff = "\n".join(f"--- {fn}\n{c[:500]}" for fn, c in files.items())
        exemplars = retrieve_relevant_exemplars(
            diff_text=combined_diff,
            findings=findings_for_exemplars,
            telemetry={},
            max_exemplars=2,
        )
        exemplar_prompt_section = format_exemplars_for_prompt(exemplars)

        prompt = (
            "You are BARQAI, the AI zero-trust code security auditor for CodeFort powered by Qwen.\n"
            "Analyze the pull request changes and detected security findings below.\n\n"
            f"Verdict: {verdict.value}\n"
            f"Modified Files: {list(files.keys())}\n"
            f"Detected Findings: {json.dumps(findings_context, indent=2)}\n\n"
            f"{exemplar_prompt_section}\n\n"
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

        client = self._get_openrouter_client()
        if client is None:
            return None
        raw_content = None

        try:
            resp = await client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a code security analyzer. Respond in valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=800,
                response_format={"type": "json_object"},
            )
            raw_content = resp.choices[0].message.content
        except Exception as err:
            logger.warning(f"OpenRouter direct call failed: {err}")
            return None

        if raw_content:
            try:
                clean_text = raw_content.strip()
                if clean_text.startswith("```"):
                    lines = clean_text.splitlines()
                    clean_text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])
                parsed = json.loads(clean_text)
                return ScanSummary(
                    what_changed=parsed.get("what_changed", "Code modifications analyzed."),
                    evidence_observed=parsed.get("evidence_observed", []),
                    why_it_matters=parsed.get("why_it_matters", "Security impact evaluated."),
                    recommended_actions=parsed.get("recommended_actions", []),
                )
            except Exception as e:
                logger.warning(f"Failed to parse Qwen JSON response: {e}")

        return None

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
            '  "why_it_matters": "Clear explanation of risk impact",\n'
            '  "recommended_actions": ["Specific mitigation 1", "Specific mitigation 2"]\n'
            "}\n"
        )

        request_body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800,
                "responseMimeType": "application/json",
            },
        }

        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(
                f"{self.gemini_url}?key={settings.LLM_API_KEY}",
                json=request_body,
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        raw_json = parts[0].get("text", "{}")
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
