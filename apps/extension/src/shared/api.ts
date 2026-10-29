/**
 * CodeFort API client for the Chrome Extension
 */

import { getStoredConfig, setStoredConfig } from "./storage";
import {
  ExtensionFindingsResponse,
  ExtensionPRStatusResponse,
  ExtensionSummaryResponse,
} from "./types";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const config = await getStoredConfig();
  const url = `${config.apiUrl.replace(/\/$/, "")}${path}`;

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (config.token) {
    headers["Authorization"] = `Bearer ${config.token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    const errorMsg = data?.error?.message || `HTTP error ${response.status}`;
    const errorCode = data?.error?.code || "REQUEST_FAILED";
    const err = new Error(errorMsg) as Error & { code?: string; status?: number };
    err.code = errorCode;
    err.status = response.status;
    throw err;
  }

  return data as T;
}

export async function fetchPRStatus(repo: string, pr: number): Promise<ExtensionPRStatusResponse> {
  return request<ExtensionPRStatusResponse>(
    `/api/v1/extension/pr-status?repo=${encodeURIComponent(repo)}&pr=${pr}`
  );
}

export async function fetchPRFindings(repo: string, pr: number): Promise<ExtensionFindingsResponse> {
  return request<ExtensionFindingsResponse>(
    `/api/v1/extension/findings?repo=${encodeURIComponent(repo)}&pr=${pr}`
  );
}

export async function fetchPRSummary(repo: string, pr: number): Promise<ExtensionSummaryResponse> {
  return request<ExtensionSummaryResponse>(
    `/api/v1/extension/summary?repo=${encodeURIComponent(repo)}&pr=${pr}`
  );
}

export async function pairWithToken(pairingToken: string): Promise<boolean> {
  const res = await request<{ access_token: string }>("/api/v1/extension/pair", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairing_token: pairingToken }),
  });

  if (res.access_token) {
    await setStoredConfig({ token: res.access_token, paired: true });
    return true;
  }
  return false;
}
