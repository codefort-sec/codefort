# CodeFort Application Flows

## 1. Sign-In Flow
1. User selects **Sign in with GitHub**.
2. Web app requests an OAuth start URL.
3. Backend creates a cryptographically random `state` value and redirects to GitHub.
4. GitHub redirects to the callback with a code and state.
5. Backend validates state and exchanges the code server-side.
6. Backend creates a secure session and redirects to the dashboard.
7. Dashboard fetches `/auth/me`.
Failure states: invalid state, denied consent, expired code, provider unavailable, or account without required repository access.

## 2. Repository Connection Flow
1. User installs the CodeFort GitHub App on an account or organization.
2. User selects repositories in GitHub's installation flow.
3. Backend receives and verifies installation events.
4. Dashboard lists repositories the user can access.
5. User enables CodeFort for selected repositories.
6. Backend stores repository connection and policy configuration.
7. User can disconnect a repository; future scans stop and revocation is audited.

## 3. Pull Request Scan Flow
1. GitHub sends a supported PR webhook.
2. API verifies signature and validates event.
3. API stores delivery ID and ignores duplicates.
4. API creates/updates the PR record and queues a scan for the exact head SHA.
5. Workers run static analysis, dependency checks, workflow linting, and optional sandbox analysis.
6. Engines return normalized findings and coverage.
7. Results are stored; BARQAI creates an evidence-linked explanation.
8. Policy evaluator computes verdict and risk score.
9. GitHub Checks, dashboard, and extension receive consistent status.
10. New commits create a new scan; old scans remain available for audit.

## 4. Extension PR Page Flow
1. Content script detects a URL matching `/OWNER/REPO/pull/NUMBER`.
2. Extension parses the URL and waits for page readiness.
3. It requests status from the backend using a scoped extension credential.
4. It displays a loading state, then verdict/score/last-scan time/coverage.
5. If on “Files changed,” it maps findings to visible diff lines and injects sanitized warnings.
6. Clicking the badge opens the side panel or dashboard details.
7. On Turbo navigation, the extension re-detects the PR and updates UI without duplicates.
Failure states: extension not paired, permission denied, no scan yet, stale scan, API offline, or no line mapping.

## 5. Findings Review Flow
1. User opens a finding.
2. UI displays severity, source engine, file/line, evidence, confidence if available, and recommendation.
3. User marks it acknowledged, false positive, or resolved if that workflow is enabled.
4. User comments or overrides are audited.
5. Rescanning the updated commit determines whether the finding remains.

## 6. Patch Flow
1. User chooses **Preview patch**.
2. Patch worker creates a candidate based on the finding and relevant context.
3. Candidate is validated in an isolated environment.
4. UI displays the diff and validation results.
5. Authorized user reviews and explicitly confirms application.
6. Backend rechecks repository permissions and policy.
7. Patch is applied as a commit/branch or posted as a review comment.
8. Audit event records actor, patch, target SHA, and outcome.
Never automatically apply unreviewed model output.

## 7. Incident Flow
1. Policy or scan logic creates an incident for a configured high-risk event.
2. Incident links to repository, PR, scan, findings, and evidence.
3. Team reviews the timeline and takes action.
4. Incident is closed with a resolution and actor.
5. Audit history remains subject to retention policy.
