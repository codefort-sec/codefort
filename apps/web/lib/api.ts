/**
 * CodeFort Web Dashboard API Client
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "https://codefort-lilac.vercel.app";

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...options.headers,
    },
    cache: "no-store",
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => null);
    const message = errorData?.error?.message || `HTTP ${res.status}`;
    throw new Error(message);
  }

  return res.json();
}

export interface ScanDetail {
  id: string;
  repository: string;
  pull_request: number;
  status: string;
  verdict: string;
  risk_score: number | null;
  risk_level?: string;
  coverage: {
    static_analysis: string;
    dependency_intel: string;
    workflow_linter: string;
    dynamic_sandbox: string;
  };
  summary?: {
    what_changed: string;
    evidence_observed: string[];
    why_it_matters: string;
    recommended_actions?: string[];
    clean_patch?: string;
    analysis?: {
      summary: string;
      risk_level: string;
      findings: Array<{
        title: string;
        severity: string;
        evidence_ids: string[];
        explanation: string;
        impact: string;
        recommendation: string;
      }>;
      unknowns: string[];
      remediation_status: string;
      evidence_verification: string;
      patch_verification: string;
    };
    risk_level?: string;
    unknowns?: string[];
    remediation_status?: string;
    evidence_verification?: string;
    patch_verification?: string;
  };
  created_at: string;
  completed_at?: string;
}

export interface FindingItem {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  description?: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  file_path?: string;
  line_start?: number;
  line_end?: number;
  evidence_id?: string;
  recommendation?: string;
  fingerprint: string;
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  return apiFetch<ScanDetail>(`/api/v1/scans/${scanId}`);
}

export async function getScanFindings(scanId: string): Promise<{ findings: FindingItem[]; total: number }> {
  return apiFetch<{ findings: FindingItem[]; total: number }>(`/api/v1/scans/${scanId}/findings`);
}

export async function createPairingToken(): Promise<{ pairing_token: string; expires_in_seconds: number }> {
  return apiFetch<{ pairing_token: string; expires_in_seconds: number }>(`/api/v1/extension/pairing-tokens`, {
    method: "POST",
  });
}

export async function triggerPRScan(repoFullName: string, prNumber: number): Promise<ScanDetail> {
  const parts = repoFullName.split("/");
  const owner = parts[0] || repoFullName;
  const repo = parts[1] || "";
  return apiFetch<ScanDetail>(
    `/api/v1/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pull-requests/${prNumber}/scans`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }
  );
}

export interface RemediationProposal {
  finding_id: string;
  rule_id: string;
  title: string;
  file_path: string;
  line_start: number;
  original_code: string;
  suggested_code: string;
  unified_diff: string;
  explanation: string;
  verification_status: "verified" | "failed" | "unverified";
}

export interface RemediationResponse {
  scan_id: string;
  repository: string;
  pull_request: number;
  clean_patch?: string | null;
  proposals: RemediationProposal[];
  overall_verification_status: "verified" | "failed" | "review_required";
  can_auto_apply: boolean;
}

export interface RemediationApplyResponse {
  status: string;
  scan_id: string;
  message: string;
  diff_applied?: string;
}

export async function getRemediationPatch(scanId: string): Promise<RemediationResponse> {
  return apiFetch<RemediationResponse>(`/api/v1/remediation/${scanId}/patch`);
}

export async function verifyRemediationPatch(
  scanId: string,
  patch?: string
): Promise<{
  scan_id: string;
  is_verified: boolean;
  verification_status: string;
  message: string;
  remaining_findings_count: number;
  regressions_detected: number;
}> {
  return apiFetch(`/api/v1/remediation/${scanId}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch ? { patch } : {}),
  });
}

export async function applyRemediationPatch(
  scanId: string,
  commitMessage?: string
): Promise<RemediationApplyResponse> {
  return apiFetch<RemediationApplyResponse>(`/api/v1/remediation/${scanId}/apply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(commitMessage ? { commit_message: commitMessage } : {}),
  });
}

export interface RemediationChecks {
  patch_format: "Passed" | "Failed";
  file_validation: "Passed" | "Failed";
  syntax_check: "Passed" | "Failed";
  unit_tests: "Passed" | "Pending" | "Failed";
  security_retest: "Passed" | "Pending" | "Failed";
  dependency_check: "Passed" | "Failed";
}

export interface RemediationRecord {
  id: string;
  finding_id: string;
  scan_id?: string | null;
  title: string;
  file_path: string;
  original_issue: string;
  proposed_solution: string;
  original_code: string;
  suggested_code: string;
  unified_diff: string;
  explanation: string;
  potential_limitations: string;
  status: "awaiting_review" | "testing" | "tested" | "approved" | "rejected";
  approved: boolean;
  approved_by?: string | null;
  approved_at?: string | null;
  checks: RemediationChecks;
  created_at: string;
}

export interface RemediationApproveResponse {
  id: string;
  approved: boolean;
  status: string;
  message: string;
  approved_by?: string | null;
  approved_at?: string | null;
}

export async function getRemediationRecord(id: string): Promise<RemediationRecord> {
  return apiFetch<RemediationRecord>(`/api/v1/remediation/${id}`);
}

export async function testSandboxRemediation(
  patchId: string,
  unifiedDiff?: string,
  filePath?: string
): Promise<{
  patch_id: string;
  passed: boolean;
  status: string;
  checks: RemediationChecks;
  details: string;
  regressions_count: number;
  remaining_findings_count: number;
}> {
  return apiFetch(`/api/v1/remediation/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      patch_id: patchId,
      unified_diff: unifiedDiff,
      file_path: filePath,
    }),
  });
}

export async function approveRemediation(
  id: string,
  developerId: string = "developer",
  comment?: string
): Promise<RemediationApproveResponse> {
  return apiFetch<RemediationApproveResponse>(`/api/v1/remediation/${id}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ developer_id: developerId, comment }),
  });
}

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface BarqAIChatRequest {
  message: string;
  error_context?: string;
  code_snippet?: string;
  file_path?: string;
  scan_id?: string;
  finding_id?: string;
  history?: ChatMessage[];
  action?: "chat" | "explain" | "rewrite" | "fix";
}

export interface BarqAIChatResponse {
  reply: string;
  explanation: string;
  rewritten_code?: string;
  original_code?: string;
  diff?: string;
  model: string;
  suggested_actions: string[];
}

export async function sendBarqAIChat(req: BarqAIChatRequest): Promise<BarqAIChatResponse> {
  return apiFetch<BarqAIChatResponse>("/api/v1/barqai/chat", {
    method: "POST",
    body: JSON.stringify(req),
  });
}


