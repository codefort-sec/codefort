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

