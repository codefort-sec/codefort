"""Tests for OSV Vulnerability Client, Vulnerabilities Dataset, and BARQAI 20-Case Evaluation."""

import json
from pathlib import Path
import pytest

from app.schemas.common import Severity, Verdict
from app.schemas.finding import FindingResponse
from app.services.engines.barqai import barqai_engine
from app.services.engines.osv_client import (
    format_osv_evidence,
    get_cached_vulnerabilities,
    get_vulnerabilities,
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@pytest.mark.asyncio
async def test_osv_client_query():
    """Verifies that OSV client retrieves real vulnerability records for known packages."""
    vulns = await get_vulnerabilities("jinja2", "PyPI", "2.4.1")
    assert len(vulns) >= 1
    first = vulns[0]
    assert "id" in first
    assert "GHSA-" in first["id"] or "CVE-" in first["id"]

    # Test evidence formatting
    evidence = format_osv_evidence(vulns[:2], "jinja2", "2.4.1", "PyPI", evidence_start_idx=1)
    assert len(evidence) == 2
    assert evidence[0]["evidence_id"] == "OSV-001"
    assert evidence[0]["source"] == "OSV"
    assert evidence[0]["package"] == "jinja2"
    assert evidence[0]["version"] == "2.4.1"
    assert "vulnerability_id" in evidence[0]


def test_processed_vulnerabilities_dataset_integrity():
    """Validates the structure and schema of datasets/processed/vulnerabilities.json."""
    dataset_file = DATASETS_DIR / "processed" / "vulnerabilities.json"
    assert dataset_file.exists(), "vulnerabilities.json must exist in datasets/processed/"

    with open(dataset_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    assert len(records) >= 15, "Dataset must have at least 15 verified vulnerability records"

    for r in records:
        assert "evidence_id" in r and r["evidence_id"].startswith("OSV-")
        assert r["source"] == "OSV"
        assert "package" in r and r["package"]
        assert "version" in r and r["version"]
        assert "vulnerability_id" in r and r["vulnerability_id"]
        assert "severity" in r
        assert "description" in r and len(r["description"]) > 5
        assert "fixed_version" in r


def test_barqai_evaluation_dataset_distribution():
    """Validates that datasets/evaluation/barqai_test.jsonl contains the exact 20 test cases."""
    eval_file = DATASETS_DIR / "evaluation" / "barqai_test.jsonl"
    assert eval_file.exists(), "barqai_test.jsonl must exist in datasets/evaluation/"

    cases = []
    with open(eval_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))

    assert len(cases) == 20, f"Expected 20 evaluation test cases, got {len(cases)}"

    # Check category distribution per Step 7:
    # Known vulnerability: 8, Benign: 6, Dependency issue: 3, Incomplete evidence: 3
    counts = {}
    for c in cases:
        cat = c.get("category")
        counts[cat] = counts.get(cat, 0) + 1

    assert counts.get("KNOWN_VULNERABILITY", 0) == 8, f"Expected 8 known vulnerability cases, got {counts.get('KNOWN_VULNERABILITY')}"
    assert counts.get("BENIGN", 0) == 6, f"Expected 6 benign cases, got {counts.get('BENIGN')}"
    assert counts.get("DEPENDENCY_ISSUE", 0) == 3, f"Expected 3 dependency issue cases, got {counts.get('DEPENDENCY_ISSUE')}"
    assert counts.get("INSUFFICIENT_EVIDENCE", 0) == 3, f"Expected 3 incomplete evidence cases, got {counts.get('INSUFFICIENT_EVIDENCE')}"


@pytest.mark.asyncio
async def test_barqai_grounded_in_osv_evidence():
    """Verifies that BARQAI cites OSV evidence IDs and advises fixed versions without hallucination."""
    osv_evidence = [
        {
            "evidence_id": "OSV-001",
            "source": "OSV",
            "package": "jinja2",
            "version": "2.4.1",
            "vulnerability_id": "GHSA-462w-v97r-4m45",
            "description": "Jinja2 sandbox escape via string formatting",
            "fixed_version": "2.10.1",
            "severity": "HIGH",
        }
    ]

    finding = FindingResponse(
        id="fnd-01",
        scan_id="scan-01",
        rule_id="dep.cve.GHSA-462w-v97r-4m45",
        title="Vulnerability in jinja2@2.4.1: GHSA-462w-v97r-4m45",
        description="Jinja2 sandbox escape",
        severity=Severity.HIGH,
        file_path="requirements.txt",
        line_start=1,
        line_end=1,
        recommendation="Upgrade to 2.10.1",
        fingerprint="fp1",
    )

    summary = await barqai_engine.generate_explanation(
        files={"requirements.txt": "jinja2==2.4.1\n"},
        findings=[finding],
        verdict=Verdict.BLOCKED,
        osv_evidence=osv_evidence,
    )

    # Must cite evidence ID in evidence_observed
    has_evidence_id = any("OSV-001" in item for item in summary.evidence_observed)
    assert has_evidence_id, "BARQAI must ground observed evidence in supplied evidence ID (OSV-001)"

    # Must mention fixed version or upgrade path
    has_recom_upgrade = any("2.10.1" in item or "Upgrade" in item for item in summary.recommended_actions)
    assert has_recom_upgrade, "BARQAI must recommend upgrading to the fixed version"

    # Must explain why it matters referencing the advisory
    assert "jinja2" in summary.why_it_matters.lower() or "GHSA-462w-v97r-4m45" in summary.why_it_matters
