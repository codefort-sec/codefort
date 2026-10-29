# CodeFort API Contract

## 1. Conventions
- Base path: `/api/v1`
- Format: JSON over HTTPS in production.
- Authentication: secure web session for dashboard requests; scoped bearer token for extension requests; GitHub App credentials remain server-side.
- All timestamps: ISO 8601 UTC.
- All responses should include a request/correlation ID where practical.
- Pagination: `limit` (default 25, maximum 100) and `cursor` for list endpoints.
- Never return secrets, provider tokens, raw secret values, or internal stack traces.

## 2. Common Error Shape
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found.",
    "request_id": "req_abc123"
  }
}
```
Use appropriate HTTP status codes: 400 malformed request, 401 unauthenticated, 403 unauthorized, 404 absent/inaccessible resource, 409 conflict, 422 schema validation error, 429 rate limited, 500 unexpected error, 503 dependency unavailable.

## 3. Authentication
- `GET /auth/github/start` — start GitHub OAuth and issue validated state.
- `GET /auth/github/callback` — validate state, exchange code server-side, create session.
- `POST /auth/logout` — invalidate session.
- `GET /auth/me` — current user and organization memberships.
- `POST /extension/pairing-tokens` — create a short-lived, single-use pairing token for the authenticated user.
- `POST /extension/pair` — exchange pairing token for a scoped extension credential.
Pairing tokens must expire quickly, be single-use, and be stored hashed server-side.

## 4. Repositories
- `GET /repositories` — list repositories available to the current user.
- `POST /repositories/{repository_id}/connect` — enable CodeFort for a repository.
- `DELETE /repositories/{repository_id}/connect` — disconnect repository.
- `GET /repositories/{owner}/{repo}` — repository details and scan settings.
- `PATCH /repositories/{owner}/{repo}/policy` — update repository security policy, if authorized.

## 5. Pull Requests and Scans
- `GET /repositories/{owner}/{repo}/pull-requests` — list PRs and latest scan status.
- `GET /repositories/{owner}/{repo}/pull-requests/{pr_number}` — PR metadata and latest result.
- `POST /repositories/{owner}/{repo}/pull-requests/{pr_number}/scans` — queue a scan; return `202 Accepted`.
- `GET /scans/{scan_id}` — status and summary.
- `GET /scans/{scan_id}/findings` — paginated findings.
- `GET /scans/{scan_id}/telemetry` — sanitized sandbox telemetry, if available.
- `GET /scans/{scan_id}/evidence/{evidence_id}` — one evidence item, with authorization.
- `GET /incidents` — list incidents visible to the user/team.
- `GET /incidents/{incident_id}` — incident details and audit events.

## 6. Extension
- `GET /extension/pr-status?repo={owner}/{repo}&pr={number}` — compact status for a GitHub PR page.
- `GET /extension/findings?repo={owner}/{repo}&pr={number}` — line-level warnings and short explanations.
- `GET /extension/summary?repo={owner}/{repo}&pr={number}` — BARQAI summary and top evidence.
The server must derive access from the authenticated extension identity and connected repository permissions, not from query parameters alone. Cache responses briefly and invalidate on new scan completion.

## 7. GitHub Webhooks
- `POST /webhooks/github` — accept supported pull request and installation events.
- Verify `X-Hub-Signature-256` before parsing or processing the payload.
- Store delivery ID for idempotency and enqueue work; return promptly.
- Support `pull_request.opened`, `pull_request.synchronize`, `pull_request.reopened`, `pull_request.closed`, and installation permission changes as needed.

## 8. Remediation
- `POST /scans/{scan_id}/patches` — request a candidate patch; return a patch ID and validation status.
- `GET /patches/{patch_id}` — preview candidate diff and checks.
- `POST /patches/{patch_id}/apply` — apply only after permission/policy checks and explicit confirmation.
- `POST /patches/{patch_id}/comments` — publish a review comment instead of changing files.
Patch requests must be idempotent where possible and must create audit events.

## 9. Example Scan Response
```json
{
  "id": "scan_123",
  "repository": "owner/repo",
  "pull_request": 42,
  "status": "completed",
  "verdict": "REVIEW_REQUIRED",
  "risk_score": 67,
  "coverage": {
    "static_analysis": "completed",
    "dependency_intel": "completed",
    "workflow_linter": "completed",
    "dynamic_sandbox": "not_configured"
  },
  "summary": {
    "what_changed": "A new package and install script were added.",
    "evidence_observed": ["Install script starts a shell process."],
    "why_it_matters": "The behavior needs review before merging."
  },
  "created_at": "2026-10-29T09:00:00Z"
}
```

## 10. Data Model Notes
Core resources: User, Organization/Team, Repository, PullRequest, Scan, Finding, Evidence, TelemetryEvent, Patch, Incident, AuditEvent, WebhookDelivery, ExtensionCredential.
Every resource must have a stable ID, timestamps, ownership/tenant scope, and appropriate indexes.

## 11. API Acceptance Criteria
- [ ] Every endpoint has authentication and authorization tests.
- [ ] Request and response schemas are validated.
- [ ] Pagination and rate limiting are consistent.
- [ ] Webhooks verify signatures and handle duplicate deliveries.
- [ ] Scan endpoints report partial coverage and errors explicitly.
- [ ] Patch endpoints require authorization and produce audit events.
- [ ] OpenAPI docs contain examples without real secrets or private data.
