"use client";

import React, { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { apiFetch, triggerPRScan } from "@/lib/api";
import {
  addLocalRepo,
  getLocalRepos,
  getWorkspaceId,
  removeLocalRepo,
  RepoItem,
  restoreDemoRepo,
  saveLocalRepos,
} from "@/lib/workspace";

interface PRItem {
  pull_request_number: number;
  title: string;
  author_login: string;
  state: string;
  html_url: string;
  latest_scan?: {
    id: string;
    verdict: string;
    risk_score: number;
    status: string;
    created_at: string;
  };
}

function DashboardContent() {
  const searchParams = useSearchParams();
  const repoQuery = searchParams.get("repo");

  const [repos, setRepos] = useState<RepoItem[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [selectedRepo, setSelectedRepo] = useState<string>(
    repoQuery || "codefort-sec/vulnerable-test-repo"
  );
  const [prs, setPrs] = useState<PRItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanningPRs, setScanningPRs] = useState<Record<number, boolean>>({});

  // Quick PR scan input
  const [customPRInput, setCustomPRInput] = useState("");
  const [customScanning, setCustomScanning] = useState(false);

  // Connect Repository Modal State
  const [showConnectModal, setShowConnectModal] = useState(false);
  const [newRepoName, setNewRepoName] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [policyBlockCritical, setPolicyBlockCritical] = useState(true);
  const [policyReviewHigh, setPolicyReviewHigh] = useState(true);
  const [policyRequireStatic, setPolicyRequireStatic] = useState(true);
  const [policyRequireDep, setPolicyRequireDep] = useState(true);

  // Initialize and load repos from local workspace storage (instant, zero flickering)
  useEffect(() => {
    const wsId = getWorkspaceId();
    setWorkspaceId(wsId);
    const local = getLocalRepos();
    setRepos(local);

    if (local.length > 0) {
      if (repoQuery && local.some((r) => r.full_name.toLowerCase() === repoQuery.toLowerCase())) {
        const found = local.find((r) => r.full_name.toLowerCase() === repoQuery.toLowerCase());
        if (found) setSelectedRepo(found.full_name);
      } else if (repoQuery) {
        // Query param repo not in list yet, connect it locally
        const newRepoItem: RepoItem = {
          id: "repo_" + Math.random().toString(36).substring(2, 8),
          full_name: repoQuery,
          is_connected: true,
        };
        const updated = addLocalRepo(newRepoItem);
        setRepos(updated);
        setSelectedRepo(repoQuery);
      } else {
        const hasSelected = local.some((r) => r.full_name === selectedRepo);
        if (!hasSelected) {
          const hasVuln = local.some((r) => r.full_name === "codefort-sec/vulnerable-test-repo");
          setSelectedRepo(hasVuln ? "codefort-sec/vulnerable-test-repo" : local[0].full_name);
        }
      }
    }
    setLoading(false);

    // Sync with backend in background
    async function syncWithBackend() {
      try {
        const backendRepos = await apiFetch<RepoItem[]>("/api/v1/repositories");
        if (backendRepos && backendRepos.length > 0) {
          setRepos((prev) => {
            const merged = [...prev];
            backendRepos.forEach((br) => {
              if (!merged.some((m) => m.full_name.toLowerCase() === br.full_name.toLowerCase())) {
                merged.push(br);
              }
            });
            saveLocalRepos(merged);
            return merged;
          });
        }
      } catch {
        // Offline/serverless resilient: local storage is the source of truth
      }
    }
    syncWithBackend();
  }, [repoQuery]);

  useEffect(() => {
    if (!selectedRepo) {
      setPrs([]);
      return;
    }
    let isMounted = true;
    async function loadPrs() {
      try {
        const prList = await apiFetch<PRItem[]>(`/api/v1/repositories/${selectedRepo}/pull-requests`);
        if (isMounted) setPrs(prList);
      } catch (err) {
        console.error(`Failed to load PRs for ${selectedRepo}:`, err);
        if (isMounted) setPrs([]);
      }
    }
    loadPrs();
    const interval = setInterval(loadPrs, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [selectedRepo]);

  async function handleDisconnectRepo(repoId: string, repoFullName: string, e: React.MouseEvent) {
    e.stopPropagation();
    const updated = removeLocalRepo(repoId, repoFullName);
    setRepos(updated);
    if (selectedRepo === repoFullName) {
      setSelectedRepo(updated.length > 0 ? updated[0].full_name : "");
    }
    try {
      await apiFetch(`/api/v1/repositories/${encodeURIComponent(repoId)}/connect`, {
        method: "DELETE",
      });
    } catch {
      // Non-blocking
    }
  }

  async function handleLoadDemoRepo() {
    const updated = restoreDemoRepo();
    setRepos(updated);
    setSelectedRepo("codefort-sec/vulnerable-test-repo");
    try {
      await apiFetch<RepoItem>("/api/v1/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: "codefort-sec/vulnerable-test-repo" }),
      });
    } catch {
      // Non-blocking
    }
  }

  async function handleTriggerScan(prNumber: number) {
    if (!selectedRepo) return;
    setScanningPRs((prev) => ({ ...prev, [prNumber]: true }));
    try {
      await triggerPRScan(selectedRepo, prNumber);
      const prList = await apiFetch<PRItem[]>(`/api/v1/repositories/${selectedRepo}/pull-requests`);
      setPrs(prList);
    } catch (err: any) {
      console.error(`Failed to trigger scan for ${selectedRepo}#${prNumber}:`, err);
    } finally {
      setScanningPRs((prev) => ({ ...prev, [prNumber]: false }));
    }
  }

  async function handleCustomScan(e: React.FormEvent) {
    e.preventDefault();
    const prNum = parseInt(customPRInput.trim(), 10);
    if (isNaN(prNum) || prNum < 1 || !selectedRepo) return;
    setCustomScanning(true);
    try {
      await handleTriggerScan(prNum);
      setCustomPRInput("");
    } finally {
      setCustomScanning(false);
    }
  }

  async function handleConnectRepo(e: React.FormEvent) {
    e.preventDefault();
    if (!newRepoName.trim()) {
      setConnectError("Please enter a valid repository (e.g. owner/repo)");
      return;
    }
    setConnecting(true);
    setConnectError(null);
    try {
      const cleanName = newRepoName
        .trim()
        .replace(/^https:\/\/github\.com\//, "")
        .replace(/^\/+|\/+$/g, "");

      if (!cleanName.includes("/")) {
        setConnectError("Format must be 'owner/repo' or full GitHub URL");
        setConnecting(false);
        return;
      }

      const policy = {
        block_on_critical: policyBlockCritical,
        review_on_high: policyReviewHigh,
        require_static: policyRequireStatic,
        require_dependency: policyRequireDep,
      };

      const newRepoItem: RepoItem = {
        id: "repo_" + Math.random().toString(36).substring(2, 8),
        full_name: cleanName,
        is_connected: true,
        policy,
      };

      // 1. Immediately persist locally
      const updated = addLocalRepo(newRepoItem);
      setRepos(updated);
      setSelectedRepo(cleanName);
      setNewRepoName("");
      setShowConnectModal(false);

      // 2. Notify backend in background to register
      apiFetch<RepoItem>("/api/v1/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: cleanName, policy }),
      }).catch((err) => {
        console.warn("Backend repo registration background note:", err);
      });
    } catch (err: any) {
      console.error("Failed to connect repository:", err);
      setConnectError(err?.message || "Failed to connect repository. Please verify name.");
    } finally {
      setConnecting(false);
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 font-mono flex flex-col gap-8 w-full">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-border pb-4 gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-lime uppercase tracking-widest">/01 DASHBOARD</span>
            {workspaceId && (
              <span
                className="text-[10px] bg-surface-raised border border-border text-text-dim px-2 py-0.5 rounded"
                title="Your private browser workspace. Connected repositories are stored securely on this device."
              >
                WORKSPACE: {workspaceId}
              </span>
            )}
          </div>
          <h1 className="text-2xl font-black text-text uppercase">REPOSITORIES &amp; PULL REQUESTS</h1>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => {
              setConnectError(null);
              setShowConnectModal(true);
            }}
            className="bg-lime hover:bg-lime-muted text-bg text-xs px-4 py-2 uppercase font-extrabold transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <span>+</span>
            <span>Connect Repository</span>
          </button>
        </div>
      </div>

      {/* Repositories Strip */}
      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between text-xs text-text-dim uppercase tracking-wider">
          <span className="font-bold">Connected Repositories ({repos.length})</span>
          {!repos.some((r) => r.full_name === "codefort-sec/vulnerable-test-repo") && (
            <button
              type="button"
              onClick={handleLoadDemoRepo}
              className="text-[10px] text-lime hover:underline uppercase font-bold cursor-pointer"
            >
              + Restore Demo Playground
            </button>
          )}
        </div>

        {repos.length === 0 ? (
          <div className="border border-dashed border-border bg-surface p-8 text-center flex flex-col items-center justify-center gap-3">
            <div className="text-lime text-xs font-bold tracking-widest uppercase">WORKSPACE READY // 0 REPOSITORIES</div>
            <h3 className="text-base font-black text-text uppercase">No Repositories Connected</h3>
            <p className="text-xs text-text-muted max-w-md">
              Connect your own GitHub repository to activate real-time malicious PR defense, or load the pre-configured demo playground for evaluation.
            </p>
            <div className="flex items-center gap-3 mt-3">
              <button
                type="button"
                onClick={() => {
                  setConnectError(null);
                  setShowConnectModal(true);
                }}
                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-4 py-2 uppercase"
              >
                + Connect Your Repository
              </button>
              <button
                type="button"
                onClick={handleLoadDemoRepo}
                className="border border-border hover:border-lime text-text hover:text-lime font-bold text-xs px-4 py-2 uppercase"
              >
                Load Demo Benchmark ↗
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {/* Horizontal Tabs Bar */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-border">
              {repos.map((repo) => {
                const isSelected = repo.full_name === selectedRepo;
                const isDemo =
                  repo.full_name === "codefort-sec/vulnerable-test-repo" ||
                  repo.full_name === "codefort-sec/clean-test-repo";
                return (
                  <div
                    key={repo.id}
                    onClick={() => setSelectedRepo(repo.full_name)}
                    className={`group flex items-center gap-2 px-3 py-2 text-xs font-bold border transition-all cursor-pointer shrink-0 ${
                      isSelected
                        ? "border-lime bg-surface-raised text-lime shadow-[0_0_12px_rgba(204,255,0,0.12)]"
                        : "border-border bg-surface text-text hover:border-text-dim hover:text-white"
                    }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${isSelected ? "bg-lime animate-pulse" : "bg-text-dim"}`} />
                    <span className="truncate max-w-[220px] md:max-w-[280px]">{repo.full_name}</span>
                    {isDemo && (
                      <span className={`text-[9px] px-1 py-0.2 font-extrabold uppercase ${isSelected ? "bg-lime/20 text-lime" : "bg-surface-raised text-text-dim"}`}>
                        DEMO
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={(e) => handleDisconnectRepo(repo.id, repo.full_name, e)}
                      title="Disconnect repository"
                      className="ml-1 text-text-dim hover:text-danger text-xs opacity-60 group-hover:opacity-100 hover:bg-danger/20 px-1 rounded transition-all"
                    >
                      ✕
                    </button>
                  </div>
                );
              })}

              <button
                type="button"
                onClick={() => {
                  setConnectError(null);
                  setShowConnectModal(true);
                }}
                className="border border-dashed border-border hover:border-lime text-text-dim hover:text-lime text-xs px-3 py-2 font-bold uppercase transition-colors shrink-0 flex items-center gap-1"
              >
                <span>+</span>
                <span>Connect</span>
              </button>
            </div>

            {/* Active Repo Context Sub-bar */}
            {selectedRepo && (
              <div className="flex flex-wrap items-center justify-between text-[11px] text-text-dim bg-surface/50 border border-border px-3 py-1.5 gap-2">
                <div className="flex items-center gap-3">
                  <span>
                    ACTIVE: <strong className="text-text">{selectedRepo}</strong>
                  </span>
                  <span className="text-text-dim">|</span>
                  <span>
                    POLICY: <strong className="text-lime">BLOCK CRITICAL (DEFAULT)</strong>
                  </span>
                  <span className="text-text-dim hidden sm:inline">|</span>
                  <span className="hidden sm:inline text-emerald-400 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    Webhooks Active
                  </span>
                </div>
                <a
                  href={`https://github.com/${selectedRepo}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-text-muted hover:text-lime transition-colors font-medium flex items-center gap-1"
                >
                  GitHub ↗
                </a>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Pull Requests & Scan Activity */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-text">Pull Request Security Audits</span>
            <span className="text-lime">({prs.length})</span>
          </div>
          <div className="flex items-center gap-3">
            <form onSubmit={handleCustomScan} className="flex items-center gap-1.5">
              <span className="text-[10px] text-text-dim uppercase hidden sm:inline">Audit PR:</span>
              <input
                type="number"
                min="1"
                placeholder="#"
                value={customPRInput}
                onChange={(e) => setCustomPRInput(e.target.value)}
                className="w-16 bg-surface-raised border border-border focus:border-lime text-text px-2 py-1 text-[11px] font-mono outline-none"
              />
              <button
                type="submit"
                disabled={customScanning || !customPRInput || !selectedRepo}
                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-[10px] px-2.5 py-1 uppercase tracking-wider disabled:opacity-50 transition-colors cursor-pointer"
              >
                {customScanning ? "..." : "⚡ Scan"}
              </button>
            </form>
          </div>
        </div>

        <div className="border border-border bg-surface overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-surface-raised border-b border-border text-text-dim uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4">Pull Request</th>
                <th className="py-3 px-4">Author</th>
                <th className="py-3 px-4">Security Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {prs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-text-dim">
                    {loading
                      ? "FETCHING PULL REQUESTS..."
                      : selectedRepo
                      ? "NO PULL REQUESTS DETECTED FOR THIS REPOSITORY YET."
                      : "SELECT OR CONNECT A REPOSITORY ABOVE TO VIEW SCAN FORENSICS."}
                  </td>
                </tr>
              ) : (
                prs.map((pr) => {
                  const scan = pr.latest_scan;
                  const isBlocked = scan?.verdict === "BLOCKED";
                  const isReview = scan?.verdict === "REVIEW_REQUIRED";
                  const isPass = scan?.verdict === "PASS";

                  return (
                    <tr key={pr.pull_request_number} className="hover:bg-surface-raised/40 transition-colors">
                      <td className="py-3.5 px-4 max-w-sm">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-lime">#{pr.pull_request_number}</span>
                          <span className="font-medium text-text truncate" title={pr.title}>
                            {pr.title}
                          </span>
                        </div>
                        {pr.html_url && (
                          <a
                            href={pr.html_url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-[10px] text-text-dim hover:text-lime transition-colors inline-block mt-0.5"
                          >
                            GitHub PR ↗
                          </a>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-text-muted">@{pr.author_login}</td>
                      <td className="py-3.5 px-4">
                        {scanningPRs[pr.pull_request_number] ? (
                          <span className="px-2 py-0.5 text-[10px] font-bold bg-lime/10 border border-lime text-lime animate-pulse">
                            ANALYZING...
                          </span>
                        ) : scan ? (
                          <span
                            className={`px-2 py-0.5 text-[10px] font-bold border ${
                              isBlocked
                                ? "bg-danger/10 border-danger text-danger"
                                : isReview
                                ? "bg-amber-500/10 border-amber-500 text-amber-500"
                                : "bg-emerald-500/10 border-emerald-500 text-emerald-500"
                            }`}
                          >
                            {scan.verdict.replace(/_/g, " ")}
                          </span>
                        ) : (
                          <span className="text-text-dim text-[11px]">NO SCAN</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-bold">
                        {scanningPRs[pr.pull_request_number] ? (
                          <span className="text-lime animate-pulse text-[11px]">CALCULATING...</span>
                        ) : scan?.risk_score !== undefined ? (
                          <span className={scan.risk_score >= 80 ? "text-danger" : scan.risk_score >= 50 ? "text-amber-500" : "text-lime"}>
                            {scan.risk_score} / 100
                          </span>
                        ) : (
                          <span className="text-text-dim">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {scan ? (
                            <>
                              <Link
                                href={`/scans/${scan.id}`}
                                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-[10px] px-3 py-1.5 uppercase tracking-wider transition-colors"
                              >
                                FORENSICS ↗
                              </Link>
                              <button
                                type="button"
                                onClick={() => handleTriggerScan(pr.pull_request_number)}
                                disabled={scanningPRs[pr.pull_request_number]}
                                title="Re-scan pull request"
                                className="border border-border hover:border-lime text-text text-[11px] px-2 py-1 transition-colors disabled:opacity-50"
                              >
                                {scanningPRs[pr.pull_request_number] ? "..." : "↻"}
                              </button>
                            </>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleTriggerScan(pr.pull_request_number)}
                              disabled={scanningPRs[pr.pull_request_number]}
                              className="border border-lime text-lime hover:bg-lime hover:text-bg font-bold text-[10px] px-3 py-1.5 uppercase tracking-wider transition-colors disabled:opacity-50"
                            >
                              {scanningPRs[pr.pull_request_number] ? "SCANNING..." : "⚡ RUN SCAN"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Connect Repository Modal */}
      {showConnectModal && (
        <div className="fixed inset-0 bg-bg/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="border-2 border-lime bg-surface max-w-lg w-full p-6 shadow-[0_0_30px_rgba(204,255,0,0.2)] font-mono flex flex-col gap-5">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <div className="text-[10px] text-lime uppercase tracking-widest">// SYSTEM ACTION: REPO_CONNECT</div>
                <h2 className="text-lg font-black text-text uppercase">CONNECT GITHUB REPOSITORY</h2>
              </div>
              <button
                type="button"
                onClick={() => setShowConnectModal(false)}
                className="text-text-muted hover:text-text font-bold text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleConnectRepo} className="flex flex-col gap-4">
              <div>
                <label className="block text-xs uppercase tracking-wider text-text-dim mb-1">
                  GitHub Repository (owner/repo)
                </label>
                <input
                  type="text"
                  value={newRepoName}
                  onChange={(e) => setNewRepoName(e.target.value)}
                  placeholder="e.g. your-org/awesome-repo or full GitHub URL"
                  className="w-full bg-surface-raised border border-border focus:border-lime text-text px-3 py-2 text-xs outline-none"
                  autoFocus
                />
                <div className="text-[10px] text-text-muted mt-1">
                  CodeFort will register webhook listeners for PR opened and synchronize events.
                </div>
              </div>

              {/* Policy Checklist */}
              <div className="border border-border p-3 flex flex-col gap-2 bg-surface-raised/40">
                <div className="text-[11px] font-bold text-text uppercase">Enforced Security Baseline:</div>
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyBlockCritical}
                    onChange={(e) => setPolicyBlockCritical(e.target.checked)}
                    className="accent-lime"
                  />
                  <span>Block merge on Critical severity findings</span>
                </label>
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyReviewHigh}
                    onChange={(e) => setPolicyReviewHigh(e.target.checked)}
                    className="accent-lime"
                  />
                  <span>Require security review on High findings</span>
                </label>
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyRequireStatic}
                    onChange={(e) => setPolicyRequireStatic(e.target.checked)}
                    className="accent-lime"
                  />
                  <span>Static AST Analysis (Inspect lifecycle hooks & scripts)</span>
                </label>
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={policyRequireDep}
                    onChange={(e) => setPolicyRequireDep(e.target.checked)}
                    className="accent-lime"
                  />
                  <span>Dependency Intelligence (Levenshtein typosquats & OSV CVEs)</span>
                </label>
              </div>

              {connectError && (
                <div className="text-xs text-danger bg-danger/10 border border-danger p-2">
                  ⚠ {connectError}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowConnectModal(false)}
                  className="border border-border text-text hover:border-text-dim text-xs px-4 py-2 uppercase font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={connecting}
                  className="bg-lime hover:bg-lime-muted text-bg text-xs px-5 py-2 uppercase font-extrabold transition-colors disabled:opacity-50"
                >
                  {connecting ? "CONNECTING..." : "[+] CONNECT REPOSITORY"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="max-w-7xl mx-auto px-4 py-16 font-mono text-center">
          <div className="text-lime text-sm animate-pulse">&gt; LOADING DASHBOARD_</div>
        </div>
      }
    >
      <DashboardContent />
    </Suspense>
  );
}

