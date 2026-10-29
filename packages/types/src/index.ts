/**
 * CodeFort Shared TypeScript Contracts
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

export interface ScanResponse {
  id: string;
  repository: string;
  pull_request: number;
  status: ScanStatus;
  verdict: Verdict;
  risk_score?: number | null;
  coverage: CoverageInfo;
  summary?: ScanSummary | null;
  created_at: string;
  completed_at?: string | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  description?: string | null;
  severity: Severity;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  evidence_id?: string | null;
  recommendation?: string | null;
  confidence?: number | null;
  fingerprint: string;
  created_at: string;
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

export interface ErrorDetail {
  code: string;
  message: string;
  request_id?: string | null;
}

export interface APIErrorResponse {
  error: ErrorDetail;
}
