# CodeFort Technical Requirements Document (TRD): Integrations

## 1. Purpose
This document defines how CodeFort connects to GitHub, the Chrome extension, analysis providers, the database, and optional AI/sandbox services.

## 2. GitHub Integration
### Authentication and permissions
- Use GitHub OAuth for user identity and a GitHub App installation for repository access and checks/webhooks.
- Choose the minimum repository permissions required for MVP; document why each permission is needed.
- Keep the GitHub App private key and OAuth client secret only on the server.
- Do not assume OAuth identity automatically grants installation access to every repository.

### Webhooks
- Endpoint: `POST /api/v1/webhooks/github`.
- Verify `X-Hub-Signature-256` against the raw request body using the configured webhook secret.
- Store `X-GitHub-Delivery` to deduplicate retries.
- Validate event type, repository identity, action, PR number, and commit SHA.
- Respond quickly after durable enqueue; process expensive work asynchronously.
- Handle installation removal and permission changes by disabling access and revoking related credentials.

### Checks and comments
- Publish status through GitHub Checks API where permissions permit.
- Report scan coverage and distinguish pending, failure, review, and block outcomes.
- Do not change branch protection or merge settings without explicit user/admin configuration.
- Patch commits and comments must be authorized, auditable, and idempotent where possible.

## 3. Chrome Extension Integration
- Manifest V3 with a service worker, content scripts, popup, and side panel.
- Match only supported GitHub host pages.
- Content script extracts owner/repository/PR number from the URL, not arbitrary page text.
- Service worker calls the API; content scripts receive only the minimal result needed for display.
- Use runtime message schemas and validate sender/origin.
- Pairing token is short-lived and single-use; exchanged credential is scoped and revocable.
- Never inject executable scripts from the website or load remote executable code.
- Keep DOM injection idempotent and clean up stale UI on SPA navigation.

## 4. Static Analysis Integration
- Use Semgrep rules and AST-based checks for supported languages.
- Pin tool versions in build configuration.
- Normalize results into CodeFort's shared Finding schema.
- Record rule version, file path, line range, and engine status.
- Treat source files and configuration as untrusted input.

## 5. Dependency Intelligence
- Parse supported lockfiles/manifests.
- Query OSV for known vulnerabilities and preserve package/version/ecosystem references.
- Heuristic checks (release age, name similarity, maintainer changes) must be configurable and labeled as heuristic.
- Cache public vulnerability data with a defined TTL and handle provider rate limits.
- Do not classify a package as malicious based only on its age or a similarity score.

## 6. GitHub Actions Workflow Linter
- Parse YAML safely; do not execute workflows.
- Check action pinning, excessive permissions, risky pull-request triggers, unsafe expression interpolation, and secret handling.
- Include the exact workflow path and relevant line where possible.

## 7. Dynamic Sandbox Integration
- Sandbox execution is an optional advanced capability and must not block MVP delivery.
- Use disposable isolated workers, non-root execution, resource limits, and restricted network egress.
- No host Docker socket, production credentials, or unrestricted access to internal services.
- Capture only approved telemetry (process, network, file events) and sanitize it before storage.
- A sandbox result includes run status, timeout, coverage, and limitations.
- If the required isolation controls cannot be provided, disable dynamic execution rather than running untrusted code unsafely.

## 8. BARQAI / LLM Integration
- Input: normalized findings, selected redacted evidence, scan metadata, and supported context.
- Output: schema-validated JSON fields for change summary, observed evidence references, impact, and recommendations.
- Model-generated statements must reference existing finding/evidence IDs where possible.
- Do not send secrets or private repository content to a provider unless explicitly enabled and approved.
- Use deterministic findings and a fallback summary when the provider is unavailable.
- Model output cannot trigger shell commands, repository changes, or policy decisions directly.

## 9. Database and Queue
- PostgreSQL stores structured state.
- Use migrations and transaction boundaries for scan creation/result persistence.
- Queue jobs must be idempotent and carry repository ID, PR number, head SHA, and scan ID.
- Retry transient failures with backoff; cap retries and route persistent failures to a dead-letter mechanism.
- Never place credentials or raw secret values in job payloads.

## 10. Environment Variables
Example names only; actual values belong in a secret store:
- `DATABASE_URL`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_APP_ID`
- `GITHUB_APP_PRIVATE_KEY`
- `GITHUB_WEBHOOK_SECRET`
- `SESSION_SECRET`
- `EXTENSION_TOKEN_SIGNING_KEY`
- `LLM_API_KEY`
- `REDIS_URL`
- `ALLOWED_WEB_ORIGINS`
Do not commit actual values. Provide `.env.example` with placeholders only.

## 11. Integration Acceptance Tests
- Valid and invalid webhook signatures.
- Duplicate webhook delivery.
- Expired/revoked extension credential.
- User without repository permission.
- OSV/provider timeout and rate limiting.
- LLM malformed output and outage.
- Sandbox timeout and denied network attempt.
- GitHub API rate limit and permission denial.
