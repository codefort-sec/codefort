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

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_findings(self, scan_id: str) -> List[FindingResponse]:
        return self.findings_by_scan.get(scan_id, [])

    def get_latest_scan_for_pr(self, repository: str, pr_number: int) -> Optional[ScanResponse]:
        scan_id = self.pr_latest_scan.get(f"{repository}#{pr_number}")
        if scan_id:
            return self.scans.get(scan_id)
        return None

    def trigger_scan(self, repository: str, pr_number: int, head_sha: Optional[str] = None) -> ScanResponse:
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now(timezone.utc)
        
        # In a real scanner this queues async work; for deterministic dev skeleton we simulate completion
        scan = ScanResponse(
            id=scan_id,
            repository=repository,
            pull_request=pr_number,
            status=ScanStatus.QUEUED,
            verdict=Verdict.SCAN_PENDING,
            risk_score=None,
            coverage=CoverageInfo(),
            summary=None,
            created_at=created_at,
        )
        self.scans[scan_id] = scan
        self.findings_by_scan[scan_id] = []
        self.pr_latest_scan[f"{repository}#{pr_number}"] = scan_id
        return scan


# Global singleton instance for local dev
mock_store = MockStore()
