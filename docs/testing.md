# CodeFort Testing Strategy

## 1. Goals
Verify correctness, authorization, safe failure behavior, explainability, extension compatibility, and reliability across the web app, extension, API, engines, and workers.

## 2. Test Levels
### Unit tests
- Risk-score boundaries and policy evaluation.
- Finding normalization and fingerprinting.
- GitHub URL parsing and PR number extraction.
- Webhook signature verification.
- Schema validation for BARQAI output.
- Redaction of secrets and sensitive telemetry.
- Dependency version and manifest parsing.

### API integration tests
- Authentication required on protected routes.
- User A cannot read User B's private repository scan.
- Connected/disconnected repository behavior.
- Scan lifecycle and partial engine failures.
- Pagination, rate limits, validation errors, and not-found responses.
- Duplicate webhook delivery creates no duplicate work.
- Expired/revoked extension tokens are rejected.
- Patch endpoints enforce permissions and audit changes.

### Engine tests
- Static analyzer: safe fixtures, vulnerable fixtures, malformed source.
- Dependency intelligence: known vulnerable package, unknown package, unavailable OSV, rate limiting, typo-similarity false positive.
- Workflow linter: excessive permissions, unpinned action, unsafe expression, valid secure workflow.
- Sandbox: benign fixture, timeout, resource limit, denied network egress, cleanup after failure.
- BARQAI: valid JSON, malformed JSON, unsupported claims, nonexistent evidence IDs, provider outage.

### Frontend tests
- Dashboard loading, empty, error, and success states.
- Verdict/severity labels and keyboard accessibility.
- Findings filter and sort behavior.
- Patch diff preview and confirmation dialog.
- Extension badge, side panel, disconnected state, stale state, and API error.

### End-to-end tests
1. Sign in with a test account.
2. Connect a test repository.
3. Open/update a test PR.
4. Confirm webhook produces a scan.
5. Confirm dashboard and extension show the same result.
6. Confirm GitHub Check status is posted when configured.
7. Preview a patch and verify confirmation is required before applying.

## 3. Security Tests
- Invalid/missing webhook signature is rejected.
- Cross-tenant IDs cannot be used to access resources.
- XSS payloads in repository names, PR titles, finding descriptions, and model output render as text.
- SSRF-like URLs in repository-controlled content are not fetched without policy validation.
- Rate limits and payload size limits work.
- Tokens never appear in logs or browser-visible responses.
- Sandbox cannot mount host socket or read production secrets.
- LLM prompt injection in source comments cannot authorize actions.
- Patch application is blocked without explicit authorization.

## 4. Test Data
Maintain synthetic fixture repositories containing:
- A clean PR.
- A suspicious install script.
- A vulnerable dependency version.
- An unsafe workflow.
- A mixed finding PR.
- Malformed lockfile/workflow.
- Source text containing fake secrets and prompt-injection instructions.
Never use real private repository content in public test fixtures.

## 5. Quality Gates
- Every bug fix adds a regression test where practical.
- Unit/integration tests run in CI on every pull request.
- Linting, type checking, migration checks, and production builds must pass.
- Security-sensitive changes require review.
- Critical security tests must pass before release.
- Test results include the commit SHA and build identifier.

## 6. MVP Definition of Tested
The MVP is test-ready when a mock scan can travel from API to database to dashboard and extension, with authorization checks, explicit failure states, duplicate-webhook handling, and a repeatable CI test suite.
