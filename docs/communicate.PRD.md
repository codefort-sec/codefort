# CodeFort Product Requirements Document (PRD)

## 1. Product Summary
**CodeFort** is a repository and pull-request security platform. It combines a web dashboard, CodeFort Guard Chrome extension, FastAPI backend, analysis engines, and BARQAI explanation layer to help developers understand risky changes before they merge.

## 2. Problem
Pull requests can introduce vulnerable dependencies, suspicious install scripts, unsafe code patterns, and insecure GitHub Actions workflows. Existing findings may be fragmented or difficult for less-experienced developers to interpret. Developers need a single, explainable view of risk, evidence, and possible remediation.

## 3. Target Users
- Individual developers and students learning secure development.
- Maintainers of open-source projects.
- Small engineering teams.
- Security reviewers responsible for pull-request policy.

## 4. Goals
- Detect common code, dependency, and workflow risks before merge.
- Explain each finding in plain language with traceable evidence.
- Show scan status directly on GitHub pull-request pages through the extension.
- Provide a dashboard for repositories, scans, incidents, and remediation.
- Keep an auditable history of findings and policy decisions.

## 5. Non-Goals for MVP
- Guarantee that code is safe or malicious.
- Replace a full security operations center or professional penetration test.
- Execute arbitrary pull-request code on the API server.
- Automatically apply AI-generated patches without validation and authorization.
- Support every language, package manager, or Git hosting provider on day one.

## 6. Primary User Journey
1. User signs in with GitHub.
2. User installs the CodeFort GitHub App and selects repositories.
3. A PR is opened or updated.
4. The backend validates the webhook and queues a scan.
5. Analysis engines run and save evidence/findings.
6. BARQAI creates a structured, evidence-linked explanation.
7. The dashboard displays verdict, risk score, coverage, findings, and audit history.
8. CodeFort Guard shows a compact status badge and inline warnings on GitHub.
9. The user reviews a suggested patch and explicitly approves any application.

## 7. Functional Requirements
### Authentication and repository connection
- FR-01: Support GitHub OAuth sign-in and sign-out.
- FR-02: Connect/disconnect repositories through a GitHub App installation.
- FR-03: Enforce repository and organization permissions on every request.

### Scanning
- FR-04: Accept PR opened, reopened, and synchronize events.
- FR-05: Run static analysis, dependency intelligence, and GitHub Actions workflow validation.
- FR-06: Report scan state and coverage, including skipped or failed engines.
- FR-07: Store findings with severity, location, evidence, recommendation, and fingerprint.
- FR-08: Produce a 0–100 risk score with documented, versioned inputs.
- FR-09: Never report `PASS` when required checks failed or were skipped without disclosure.

### Dashboard
- FR-10: Show connected repositories and latest PR scan states.
- FR-11: Provide a PR detail/forensic view with findings, evidence, and sanitized telemetry.
- FR-12: Show incident history and audit events.
- FR-13: Support finding filtering by severity, engine, path, and status.

### Chrome extension
- FR-14: Detect GitHub PR pages after normal navigation and SPA navigation.
- FR-15: Show verdict and risk score in a compact badge.
- FR-16: Show warnings on changed lines when line mapping is available.
- FR-17: Open a side panel with summary, evidence, and remediation links.
- FR-18: Handle disconnected, loading, stale, and unavailable states.

### Remediation
- FR-19: Generate a proposed patch or review comment.
- FR-20: Validate the patch and display test status.
- FR-21: Require permission checks, explicit confirmation, and audit logging before applying changes.

## 8. Non-Functional Requirements
- NFR-01 Security: least privilege, webhook verification, secure sessions, sandbox isolation.
- NFR-02 Reliability: idempotent webhook handling and retryable background jobs.
- NFR-03 Performance: extension status endpoint should be lightweight; dashboard lists should be paginated.
- NFR-04 Explainability: findings must link to evidence and distinguish observation from inference.
- NFR-05 Accessibility: keyboard support, readable contrast, labels beyond color.
- NFR-06 Maintainability: typed contracts, migrations, automated tests, and clear module boundaries.
- NFR-07 Privacy: minimize source-code retention and redact secrets from logs and model prompts.

## 9. MVP Acceptance Criteria
- A user can sign in and connect a test repository.
- A PR event creates one scan job even if the webhook is delivered more than once.
- Static/dependency/workflow checks produce a stored result or an explicit engine error.
- The dashboard and extension display the same latest verdict and risk score.
- Unauthorized users cannot retrieve another user's private repository findings.
- Scan failures are not shown as a passing result.
- Patch application is gated by authorization and explicit confirmation.

## 10. Success Metrics
- Percentage of supported PRs scanned successfully.
- Median time from webhook receipt to first result.
- Findings with useful evidence and actionable remediation.
- False-positive rate on a labeled test set.
- Extension status-fetch latency and error rate.
- Number of unauthorized-access/security test failures (target: zero).

## 11. Risks and Assumptions
- Dynamic analysis requires carefully isolated infrastructure and may be deferred beyond MVP.
- GitHub permissions and API limits constrain available metadata and actions.
- LLM explanations may hallucinate; evidence must remain authoritative.
- Risk-score thresholds require testing and calibration.
- The initial language/package-manager scope must be declared clearly.
