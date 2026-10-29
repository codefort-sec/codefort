# CodeFort Style Guide

## 1. Product Voice
CodeFort should feel like a trustworthy security copilot for developers: precise, calm, explainable, and actionable. Avoid fear-based language and avoid claiming certainty without evidence.

## 2. UI Principles
- Put the verdict, risk score, and top reason first.
- Explain findings in three layers: **What changed**, **Evidence observed**, and **Why it matters**.
- Keep detailed telemetry available without overwhelming the default view.
- Make severity, status, and confidence visible through both text and visual cues; never rely on color alone.
- Make every warning actionable: show file/line, impact, recommended fix, and evidence link when available.
- Preserve GitHub's native layout and keyboard behavior in the extension.

## 3. Verdict and Severity Labels
Use these stable labels across the dashboard, API, and extension:
- `PASS`: no blocking findings were detected by the configured checks.
- `REVIEW_REQUIRED`: findings or incomplete coverage require human review.
- `BLOCKED`: configured policy says this PR must not proceed.
- `SCAN_PENDING`: queued or currently running.
- `SCAN_ERROR`: scan could not complete reliably.
- `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`: finding severity.

Do not equate `PASS` with “guaranteed safe.” Display which checks ran and which did not.

## 4. Risk Score
- Integer range: 0–100.
- Higher scores mean higher estimated risk.
- Show the top contributing factors beside the score.
- Document score inputs and version the scoring policy.
- Do not present the score as a probability unless it has been calibrated and validated as one.

Suggested initial interpretation (configurable):
- 0–19: Low
- 20–39: Moderate
- 40–69: High
- 70–100: Critical
These bands are starting defaults and must be validated against test data.

## 5. Visual Tokens
Suggested defaults; implement as design tokens so they can be changed centrally:
- Background: neutral light/dark surfaces with sufficient contrast.
- Text: primary, secondary, and muted text roles.
- Status: green for PASS, amber for REVIEW_REQUIRED, red for BLOCKED/CRITICAL, gray for pending/unknown.
- Spacing: 4px base scale (4, 8, 12, 16, 24, 32).
- Radius: 6–10px for cards and controls.
- Typography: readable sans-serif; clear hierarchy for page title, section title, body, and metadata.
- Avoid tiny telemetry text; support zoom and responsive layouts.

## 6. Accessibility
- Meet WCAG 2.2 AA as a target.
- Ensure keyboard navigation and visible focus.
- Add labels to icon-only controls.
- Use semantic headings, buttons, tables, and dialogs.
- Provide text labels/icons in addition to color.
- Announce status updates to assistive technology where appropriate.
- Respect reduced-motion preferences.

## 7. Components
- `RiskBadge`: verdict + score + accessible label.
- `FindingCard`: severity, title, location, evidence, explanation, remediation.
- `EvidencePanel`: timestamps, source, observed event, sanitized details.
- `TelemetryTable`: sortable, filterable, paginated process/network/file events.
- `PatchPreview`: original vs proposed diff, validation status, approval action.
- `EmptyState`: explain what is missing and the next action.
- `ErrorState`: explain the failure, whether results are stale, and retry options.

## 8. Content Rules
- Prefer direct wording: “The install script starts a shell process” rather than “This could potentially perhaps…”
- Clearly separate facts (“Observed outbound connection”) from interpretation (“May indicate data exfiltration”).
- Include file path and line number when known.
- Never expose raw secret values.
- Dates use a consistent timezone-aware format; display the user's local time where useful.
- Buttons use verbs: “Run scan”, “Review finding”, “Preview patch”, “Apply patch”.

## 9. Extension-Specific Rules
- Keep injected UI compact and visually compatible with GitHub.
- Avoid covering native controls or modifying repository content.
- Provide a loading state and a clear unavailable/error state.
- Reinitialize safely after GitHub Turbo navigation without duplicating badges or warnings.
- Allow the user to open the full dashboard for complex actions.

## 10. Definition of Done
A UI feature is complete when it is responsive, keyboard accessible, covered by relevant tests, consistent with shared status labels, and includes loading, empty, error, and permission-denied states.
