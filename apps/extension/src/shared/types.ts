/**
 * Chrome Extension Shared Types & Contracts
 */

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type Verdict = "PASS" | "REVIEW_REQUIRED" | "BLOCKED" | "SCAN_PENDING" | "SCAN_ERROR";

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type EngineStatus = "completed" | "failed" | "skipped" | "not_configured";

export interface CoverageInfo {
  static_analysis: EngineStatus;
  dependency_intel: EngineStatus;
  workflow_linter: EngineStatus;
  dynamic_sandbox: EngineStatus;
}

export interface ScanSummary {
  what_changed: string;
  evidence_observed: string[];
  why_it_matters: string;
  recommended_actions?: string[];
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ExtensionPRStatusResponse {
  repository: string;
  pull_request: number;
  status: ScanStatus;
  verdict: Verdict;
  risk_score?: number | null;
  findings_count: FindingsCount;
  coverage: CoverageInfo;
  last_scanned_at?: string | null;
}

export interface ExtensionLineFinding {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  file_path: string;
  line_start: number;
  line_end: number;
  recommendation?: string | null;
}

export interface ExtensionFindingsResponse {
  repository: string;
  pull_request: number;
  findings: ExtensionLineFinding[];
}

export interface ExtensionSummaryResponse {
  repository: string;
  pull_request: number;
  verdict: Verdict;
  risk_score?: number | null;
  summary?: ScanSummary | null;
}

export interface ExtensionConfig {
  apiUrl: string;
  token?: string | null;
  paired: boolean;
}

// Background <-> Content Script / Popup Messaging
export type ExtensionMessage =
  | { type: "GET_PR_STATUS"; repo: string; pr: number }
  | { type: "GET_PR_FINDINGS"; repo: string; pr: number }
  | { type: "GET_PR_SUMMARY"; repo: string; pr: number }
  | { type: "CHECK_PAIRING_STATUS" }
  | { type: "PAIR_WITH_TOKEN"; pairingToken: string };

export type ExtensionResponse<T = any> =
  | { success: true; data: T }
  | { success: false; error: { code: string; message: string } };
