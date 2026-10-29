# CodeFort Implementation Plan

## Delivery Strategy
Build a safe end-to-end MVP first. Use mock scan results initially, then replace each mock with a real engine. Dynamic sandboxing and automated patch application are advanced phases, not prerequisites for the first demo.

## Phase 0 — Repository and Engineering Setup
**Tasks**
- Create monorepo folders: `apps/web`, `apps/extension`, `services/api`, `packages/types`.
- Add root README, `.gitignore`, `.env.example`, formatting/linting configuration.
- Define shared verdict, severity, finding, scan, PR, and telemetry types.
- Add CI for lint, type-check, unit tests, and build.

**Exit criteria**
- A fresh clone can install dependencies and run each development service using documented commands.
- No real credentials are committed.

## Phase 1 — Backend and Mock Scan
**Tasks**
- Scaffold FastAPI and `/health`.
- Configure PostgreSQL, SQLAlchemy models, and Alembic migrations.
- Implement auth abstraction and repository/PR/scan endpoints.
- Create a deterministic mock scan engine with sample findings.
- Add scan state machine, normalized results, and policy evaluator.
- Add authorization tests and seed data for local development.

**Exit criteria**
- API can create a scan, return a result, and expose findings.
- A failed engine is shown as failed/partial, not as a pass.
- API tests run in CI.

## Phase 2 — Chrome Extension Overlay
**Tasks**
- Scaffold Manifest V3 + Vite + React + TypeScript.
- Implement GitHub PR URL parser.
- Implement service worker API client and pairing flow.
- Inject one compact verdict badge on PR pages.
- Handle Turbo navigation and avoid duplicate UI.
- Add popup connection state and side-panel summary.

**Exit criteria**
- On a test PR with mock data, badge and side panel display the expected result.
- Unpaired, no-result, stale, and API-error states are understandable.
- Permissions are minimal and documented.

## Phase 3 — Web Dashboard
**Tasks**
- Build GitHub sign-in and callback.
- Build repository list/connect/disconnect.
- Build dashboard overview and PR list.
- Build PR detail page with verdict, score, coverage, findings, and evidence.
- Add incidents/audit list and repository policy settings.
- Add accessible loading, empty, error, and permission-denied states.

**Exit criteria**
- User can connect a test repository and inspect a mock scan from the browser.
- UI and extension use the same API contract and status vocabulary.

## Phase 4 — Real Static and Dependency Analysis
**Tasks**
- Integrate Semgrep for a declared initial language scope.
- Parse supported package manifests and lockfiles.
- Integrate OSV lookups with caching and rate-limit handling.
- Add safe GitHub Actions YAML checks.
- Normalize findings and store engine versions/coverage.

**Exit criteria**
- Fixture repositories produce expected findings.
- Each engine has unit/integration tests and timeouts.
- Findings include evidence, location, recommendation, and source engine.

## Phase 5 — GitHub Webhooks and Checks
**Tasks**
- Configure GitHub App and webhook secret.
- Verify signatures and deduplicate delivery IDs.
- Queue scan jobs for PR opened/reopened/synchronize events.
- Publish GitHub Checks status and summary.
- Handle installation removal and permission changes.

**Exit criteria**
- Duplicate events do not create duplicate scans.
- New commit SHA creates a new scan.
- GitHub status matches dashboard result.

## Phase 6 — BARQAI Explanations
**Tasks**
- Define strict input/output schemas.
- Provide only redacted, relevant evidence.
- Generate change summary, observed evidence, impact, and recommended actions.
- Validate all model output and link it to existing evidence IDs.
- Add fallback explanation when the LLM is unavailable.

**Exit criteria**
- Malformed or fabricated references are rejected or marked unsupported.
- Deterministic findings remain available during provider outage.

## Phase 7 — Secure Dynamic Sandbox
**Tasks**
- Threat-model worker isolation before implementation.
- Build disposable worker pool with non-root user and strict resource limits.
- Restrict egress and block access to internal metadata services.
- Capture process/network/file telemetry.
- Destroy workspaces after completion and redact output.

**Exit criteria**
- Sandbox isolation tests pass.
- Timeouts and denied egress are visible.
- If controls are not met, feature stays disabled.

## Phase 8 — Patch Preview and Remediation
**Tasks**
- Generate candidate patch or review comment.
- Run tests/build checks in isolated worker.
- Show original/candidate diff and validation state.
- Require explicit confirmation and recheck permissions before applying.
- Write immutable audit event for every action.

**Exit criteria**
- Unauthorized users cannot apply patches.
- Model output is never applied without validation and user confirmation.
- Failed validation prevents automatic application.

## Phase 9 — Hardening and Release
**Tasks**
- Run security review, dependency scan, accessibility review, and load tests.
- Set up monitoring, backup/restore, retention, and incident response.
- Deploy staging and run end-to-end tests.
- Publish extension privacy disclosure and permission rationale.
- Prepare user guide and known-limitations page.

**Release gate**
- No critical unresolved security issues.
- Authorization, webhook, sandbox, and patch-approval tests pass.
- Scan coverage and limitations are visible to users.
