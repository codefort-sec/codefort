"""Standardized BARQAI security analysis schemas with strict evidence verification."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    CLEAN = "CLEAN"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BARQAIFindingAnalysis(BaseModel):
    """Individual security finding analyzed by BARQAI."""
    title: str = Field(..., description="Short finding title")
    severity: str = Field(..., description="Finding severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    evidence_ids: List[str] = Field(default_factory=list, description="Verified evidence IDs supporting this finding")
    explanation: str = Field(..., description="Clear explanation of the vulnerability in simple language")
    impact: str = Field(..., description="Potential security impact")
    recommendation: str = Field(..., description="Safe remediation steps")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> str:
        s = str(v).upper() if v else "MEDIUM"
        if s not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            return "MEDIUM"
        return s

    @field_validator("title", "explanation", "impact", "recommendation", mode="before")
    @classmethod
    def validate_non_empty(cls, v: Any) -> str:
        s = str(v).strip() if v else ""
        if not s:
            return "Not specified"
        return s


class StandardBARQAIAnalysis(BaseModel):
    """Standardized BARQAI analysis output format validated before database persistence and UI rendering."""
    model_config = {"extra": "allow"}

    summary: str = Field(..., description="High-level security analysis summary")
    risk_level: str = Field(..., description="Risk classification: LOW, MEDIUM, HIGH, CRITICAL, CLEAN")
    findings: List[BARQAIFindingAnalysis] = Field(
        default_factory=list, description="Verified security findings with evidence citations"
    )
    unknowns: List[str] = Field(
        default_factory=list, description="Identified missing evidence or unverified components"
    )
    remediation_status: str = Field(
        "NOT_TESTED", description="Remediation status: NOT_TESTED, VERIFIED, FAILED"
    )
    evidence_verification: str = Field(
        "Validated", description="Status of evidence grounding verification"
    )
    patch_verification: str = Field(
        "Not tested", description="Status of independent patch verification"
    )
    clean_patch: Optional[str] = Field(
        None, description="Unified git diff remediation patch"
    )

    @field_validator("risk_level", mode="before")
    @classmethod
    def validate_risk_level(cls, v: Any) -> str:
        r = str(v).upper() if v else "MEDIUM"
        if r not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "CLEAN"}:
            return "MEDIUM"
        return r

    @field_validator("summary", mode="before")
    @classmethod
    def validate_summary(cls, v: Any) -> str:
        s = str(v).strip() if v else ""
        return s or "Security analysis completed."


class BarqAIChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message text")


class BarqAIChatRequest(BaseModel):
    message: str = Field(..., description="User message, question, or error prompt")
    error_context: Optional[str] = Field(None, description="Optional stack trace, error message, or scan finding context")
    code_snippet: Optional[str] = Field(None, description="Optional code snippet with the error or vulnerability")
    file_path: Optional[str] = Field(None, description="Optional relative file path, e.g. package.json or src/auth.js")
    scan_id: Optional[str] = Field(None, description="Optional scan ID for context retrieval")
    finding_id: Optional[str] = Field(None, description="Optional finding ID being discussed")
    history: List[BarqAIChatMessage] = Field(default_factory=list, description="Prior conversation history")
    action: Optional[str] = Field("chat", description="'chat', 'explain', 'rewrite', or 'fix'")


class BarqAIChatResponse(BaseModel):
    reply: str = Field(..., description="Conversational explanation and guidance from BARQAI")
    explanation: str = Field(..., description="Detailed explanation of what the error/vulnerability is and why it happened")
    rewritten_code: Optional[str] = Field(None, description="Rewritten, safe, and functional code")
    original_code: Optional[str] = Field(None, description="Original code before rewriting")
    diff: Optional[str] = Field(None, description="Unified git diff showing the changes")
    model: str = Field("Qwen 2.5 Coder 32B Instruct (MoE)", description="Model used for generation")
    suggested_actions: List[str] = Field(default_factory=list, description="Suggested quick prompts for the user")

