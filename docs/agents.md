# CodeFort Agents and Engineering Responsibilities

## 1. Purpose
This document defines the logical workers/agents in CodeFort. These are service components, not autonomous agents with unrestricted access. Each component has a narrow responsibility and communicates through typed contracts.

## 2. Components
### 2.1 Web Application
- Owns user-facing dashboard, repository settings, scan details, incident history, and patch review.
- Uses authenticated API calls only.
- Does not hold GitHub App private keys or execute scans.
- Validates UI inputs and renders server-returned content safely.

### 2.2 Chrome Extension
- Detects GitHub PR pages and requests compact scan status.
- Injects a badge and line warnings based on backend data.
- Does not perform authoritative scanning or make policy decisions.
- Uses a scoped, revocable extension credential.

### 2.3 API / Orchestrator
- Authenticates users and authorizes access.
- Validates GitHub webhook signatures and payload schemas.
- Creates idempotent scan jobs and coordinates engines.
- Persists results and exposes dashboard/extension APIs.
- Does not execute untrusted repository code itself.

### 2.4 Static Analyzer
- Runs configured Semgrep rules and AST-based checks.
- Returns normalized findings: rule ID, severity, file/line, evidence, confidence, recommendation.
- Does not decide final verdict alone.

### 2.5 Dependency Intelligence
- Parses supported lockfiles and manifests.
- Checks known vulnerabilities through OSV and package metadata.
- Flags suspicious name similarity, unusually new releases, and other configured signals.
- Treats heuristics as signals, not proof of maliciousness.

### 2.6 Workflow Linter
- Parses GitHub Actions YAML without executing it.
- Checks permissions, unpinned actions, unsafe expression usage, secret exposure risks, and risky triggers.
- Produces evidence-backed findings.

### 2.7 Sandbox Worker
- Runs only in isolated disposable infrastructure.
- Captures permitted process, network, and file telemetry.
- Applies time, CPU, memory, disk, and network limits.
- Returns telemetry and an explicit completeness status; cannot access production credentials.

### 2.8 BARQAI Explanation Engine
- Consumes normalized findings and selected redacted evidence.
- Produces structured `what_changed`, `evidence_observed`, `why_it_matters`, and `recommended_actions`.
- Must not invent evidence, execute code, or directly apply patches.
- Marks uncertainty and references finding/evidence IDs.

### 2.9 Patch Worker
- Creates candidate patches or review comments.
- Runs validation in isolated workers.
- Returns diff, tests, and validation status.
- Applies changes only after a separate authorized API action.

## 3. Pipeline Contract
1. Webhook receiver validates signature and stores delivery ID.
2. Orchestrator deduplicates delivery and creates a queued scan.
3. Engines run in parallel where safe.
4. Each engine returns normalized results or a typed failure.
5. Results are persisted with coverage information.
6. BARQAI summarizes stored evidence.
7. Policy evaluator computes verdict from explicit rules and findings.
8. Dashboard, extension, and GitHub Checks receive consistent results.
9. Audit event is written for policy decisions and remediation.

## 4. Shared Result Schema
```json
{
  "engine": "static_analyzer",
  "status": "completed",
  "findings": [
    {
      "rule_id": "example.rule",
      "severity": "HIGH",
      "title": "Suspicious shell execution",
      "file_path": "package.json",
      "line_start": 12,
      "line_end": 12,
      "evidence_id": "ev_123",
      "recommendation": "Review the install script before merging."
    }
  ],
  "errors": []
}
```

## 5. Failure Handling
- Engine timeout: mark that engine failed/timed out and continue other safe checks.
- Database failure: retry safely; do not report a completed scan before persistence succeeds.
- LLM unavailable: preserve deterministic findings and show “explanation unavailable.”
- Sandbox unavailable: show dynamic analysis as not run; never imply runtime checks passed.
- GitHub API rate limit: back off and retry according to provider headers.
- Partial results: verdict policy must account for required checks and visible coverage.

## 6. Operational Rules
- All jobs have unique IDs, bounded retries, timeouts, and structured logs.
- Never pass raw secrets to agents or LLM prompts.
- Workers communicate using versioned schemas.
- Side effects such as posting comments or pushing commits occur only in explicitly authorized components.
