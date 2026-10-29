# CodeFort Security Policy

## 1. Purpose and Scope
CodeFort protects software repositories and pull requests through static analysis, dependency intelligence, workflow validation, optional isolated runtime analysis, and explainable findings from BARQAI. This policy applies to the web dashboard, FastAPI backend, GitHub App/webhooks, CodeFort Guard Chrome extension, scan workers, database, and deployment infrastructure.

## 2. Security Principles
- Least privilege: request only the GitHub permissions needed for selected features.
- Defense in depth: validate at the browser, API, worker, database, and infrastructure boundaries.
- Fail safely: if a scan fails, show `SCAN_ERROR` or `REVIEW_REQUIRED`; never label an unscanned PR as safe.
- Human control: destructive remediation and automatic blocking must follow configured policy and retain an audit trail.
- Isolation: never execute pull-request code or package install scripts on the API server or a trusted host.
- Explainability: distinguish observed evidence from inferred risk and AI-generated explanation.

## 3. Identity and Access
- Use GitHub OAuth for user authentication and a GitHub App installation for repository operations.
- Validate OAuth `state`; use PKCE where supported by the selected OAuth flow.
- Keep access tokens server-side whenever possible. Do not expose GitHub App private keys or long-lived provider tokens to the browser or extension.
- Issue short-lived, scoped extension pairing tokens; store them in `chrome.storage.local`, support revocation, and never put tokens in URLs or logs.
- Enforce authorization on every API request: the authenticated user must have access to the requested organization, repository, pull request, scan, and incident.
- Separate user, organization/team, repository, and administrator permissions.

## 4. Secrets and Configuration
- Store secrets in environment variables or a managed secret store; commit only `.env.example` with dummy values.
- Required secrets may include GitHub OAuth client secret, GitHub App private key, webhook secret, session signing key, database credentials, and LLM provider key.
- Rotate exposed credentials immediately. Never log authorization headers, cookies, tokens, private keys, or raw secrets found in repository content.
- Redact secrets from findings and telemetry before persistence or display.

## 5. Webhooks and API
- Verify GitHub webhook signatures using HMAC SHA-256 and constant-time comparison before processing payloads.
- Reject invalid signatures, malformed payloads, oversized bodies, unsupported event types, and replayed events where an event identifier is available.
- Make webhook handling idempotent; persist delivery IDs and process events asynchronously.
- Apply request size limits, rate limits, timeouts, schema validation, and restrictive CORS allowlists.
- Use TLS in production. Configure secure, HttpOnly, SameSite cookies for web sessions.
- Prevent SSRF: validate outbound destinations and do not allow repository content to select arbitrary internal URLs.
- Do not trust owner/repository names, PR numbers, file paths, diff content, or model output without validation.

## 6. Untrusted Code and Sandbox
- Treat all code, dependency packages, GitHub Actions workflows, archives, and scan artifacts as hostile.
- Run dynamic analysis in disposable, non-root containers or stronger isolated workers with CPU, memory, disk, process, and time limits.
- Disable privileged mode; drop Linux capabilities; use read-only base filesystems where feasible; mount only temporary workspaces; never mount host sockets or host credentials.
- Restrict network egress by default. If network observation is required, use an explicit allowlist or controlled proxy.
- Destroy the worker and temporary files after each job. Keep sandbox workers separate from the API and database networks.
- Do not run package scripts on a developer laptop or production API host as part of scanning.

## 7. AI / BARQAI Safety
- Treat source code, comments, package metadata, issue text, and logs as untrusted prompt content.
- Use structured output schemas and validate every model response. Model output must not directly execute commands, change repository settings, or apply patches.
- Separate evidence collection from AI explanation. Preserve links to original evidence and label uncertain conclusions.
- Require tests and, by default, human approval before applying generated patches.
- Do not send private repository content to an external LLM unless the organization has explicitly enabled that provider and understands its data terms. Minimize and redact prompts.

## 8. Extension Security
- Use Manifest V3 and request only required permissions and host access.
- Restrict content scripts to GitHub pages. Avoid `eval`, remote executable code, and unsafe HTML insertion.
- Sanitize any text inserted into GitHub's DOM; render repository-controlled strings as text, not HTML.
- Validate messages between page, content script, service worker, and website using explicit schemas and origin checks.
- Pairing must be initiated by an authenticated user action and use a short-lived, single-use token.
- Do not treat page DOM content as authoritative scan results; fetch results from the authenticated backend.

## 9. Data Classification and Retention
- Public: documentation and public product metadata.
- Internal: scan status, repository metadata, configuration.
- Confidential: private source snippets, findings, telemetry, incident records.
- Secrets: credentials and detected secret values; do not persist raw values unless strictly necessary.
- Define retention periods for source snapshots, sandbox traces, logs, and incidents. Provide deletion/export workflows and honor organization policy.

## 10. Logging, Monitoring, and Incident Response
- Log authentication events, permission changes, scan starts/results, policy decisions, remediation actions, and administrative access.
- Use correlation IDs and redact sensitive values.
- Alert on repeated authentication failures, webhook signature failures, unusual scan volume, sandbox escape indicators, and repeated API errors.
- Incident steps: contain affected credentials/workers, preserve relevant audit evidence, assess scope, notify affected owners as required, rotate secrets, patch, and document lessons learned.

## 11. Security Acceptance Checklist
- [ ] No secrets committed or emitted in logs.
- [ ] GitHub webhook signatures verified.
- [ ] Authorization tests cover cross-user and cross-organization access.
- [ ] Rate limits and payload limits are enabled.
- [ ] Sandbox cannot access host credentials or internal services.
- [ ] Extension permissions are minimal and messages are validated.
- [ ] AI output is schema-validated and never executed directly.
- [ ] Patch application requires policy approval and audit logging.
- [ ] Backup, retention, deletion, and incident procedures are documented.

## 12. Known Limitations
A risk score is a prioritization aid, not proof that a change is malicious or safe. Static analysis and sandbox runs can produce false positives and false negatives. CodeFort must communicate scan coverage, skipped checks, and failures clearly.
