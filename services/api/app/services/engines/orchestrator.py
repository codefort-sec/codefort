from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from app.schemas.common import EngineStatus, ScanStatus, Severity, Verdict
from app.schemas.finding import FindingBase, FindingResponse
from app.schemas.scan import CoverageInfo, ScanResponse, ScanSummary
from app.services.engines.barqai import barqai_engine
from app.services.engines.dependency_intel import DependencyIntelligence
from app.services.engines.static_analyzer import StaticAnalyzer
from app.services.engines.workflow_linter import WorkflowLinter
from app.services.policy import evaluate_policy

Tuple_Scan_Findings = Tuple[ScanResponse, List[FindingResponse]]


class ScanOrchestrator:
    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.dependency_intel = DependencyIntelligence()
        self.workflow_linter = WorkflowLinter()

    async def execute_scan(
        self,
        repository: str,
        pull_request: int,
        files: Dict[str, str],
        scan_id: Optional[str] = None,
    ) -> Tuple_Scan_Findings:
        scan_id = scan_id or f"scan_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now(timezone.utc)

        coverage = CoverageInfo(
            static_analysis=EngineStatus.COMPLETED,
            dependency_intel=EngineStatus.COMPLETED,
            workflow_linter=EngineStatus.COMPLETED,
            dynamic_sandbox=EngineStatus.NOT_CONFIGURED,
        )

        all_findings: List[FindingResponse] = []

        # 1. Run each engine across the input files
        for file_path, content in files.items():
            # Static Analyzer
            try:
                static_findings = self.static_analyzer.scan_file(file_path, content)
                for f in static_findings:
                    all_findings.append(self._normalize_finding(scan_id, f))
            except Exception:
                coverage.static_analysis = EngineStatus.FAILED

            # Dependency Intelligence
            try:
                dep_findings = await self.dependency_intel.scan_file(file_path, content)
                for f in dep_findings:
                    all_findings.append(self._normalize_finding(scan_id, f))
            except Exception:
                coverage.dependency_intel = EngineStatus.FAILED

            # Workflow Linter
            try:
                wf_findings = self.workflow_linter.scan_file(file_path, content)
                for f in wf_findings:
                    all_findings.append(self._normalize_finding(scan_id, f))
            except Exception:
                coverage.workflow_linter = EngineStatus.FAILED

        # 2. Evaluate policy for final verdict and risk score
        verdict, risk_score = evaluate_policy(all_findings, coverage)

        # 3. Generate BARQAI structured explanation
        summary = await barqai_engine.generate_explanation(files, all_findings, verdict)

        completed_at = datetime.now(timezone.utc)

        scan = ScanResponse(
            id=scan_id,
            repository=repository,
            pull_request=pull_request,
            status=ScanStatus.COMPLETED,
            verdict=verdict,
            risk_score=risk_score,
            coverage=coverage,
            summary=summary,
            created_at=created_at,
            completed_at=completed_at,
        )

        return scan, all_findings

    def _normalize_finding(self, scan_id: str, raw: FindingBase) -> FindingResponse:
        f_id = f"fnd_{uuid.uuid4().hex[:6]}"
        fp_str = f"{raw.file_path}:{raw.line_start}:{raw.rule_id}"
        fingerprint = hashlib.sha256(fp_str.encode()).hexdigest()

        return FindingResponse(
            id=f_id,
            scan_id=scan_id,
            rule_id=raw.rule_id,
            title=raw.title,
            description=raw.description,
            severity=raw.severity,
            confidence=raw.confidence,
            file_path=raw.file_path,
            line_start=raw.line_start,
            line_end=raw.line_end,
            recommendation=raw.recommendation,
            fingerprint=fingerprint,
            created_at=datetime.now(timezone.utc),
        )

    def _generate_barqai_summary(
        self,
        files: Dict[str, str],
        findings: List[FindingResponse],
        verdict: Verdict,
    ) -> ScanSummary:
        file_names = list(files.keys())
        what_changed = f"Modified {len(file_names)} file(s): {', '.join(file_names[:3])}"
        if len(file_names) > 3:
            what_changed += f" and {len(file_names) - 3} more."

        if not findings:
            return ScanSummary(
                what_changed=what_changed,
                evidence_observed=["No security anomalies or high-risk patterns detected across scanned files."],
                why_it_matters="All evaluated files satisfied the configured security baseline.",
                recommended_actions=["Proceed with standard code review."],
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
            why_it_matters = "Minor findings detected. Review recommendations to ensure code quality."

        return ScanSummary(
            what_changed=what_changed,
            evidence_observed=evidence,
            why_it_matters=why_it_matters,
            recommended_actions=recomms or ["Review flagged diff lines before approval."],
        )


orchestrator = ScanOrchestrator()
