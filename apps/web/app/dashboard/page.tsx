"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, triggerPRScan } from "@/lib/api";

interface RepoItem {
  id: string;
  full_name: string;
  is_connected: boolean;
  policy?: Record<string, any>;
}

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

export default function DashboardPage() {
  const [repos, setRepos] = useState<RepoItem[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string>("codefort-sec/vulnerable-test-repo");
  const [prs, setPrs] = useState<PRItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanningPRs, setScanningPRs] = useState<Record<number, boolean>>({});

  // Connect Repository Modal State
  const [showConnectModal, setShowConnectModal] = useState(false);
  const [newRepoName, setNewRepoName] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [policyBlockCritical, setPolicyBlockCritical] = useState(true);
  const [policyReviewHigh, setPolicyReviewHigh] = useState(true);
  const [policyRequireStatic, setPolicyRequireStatic] = useState(true);
  const [policyRequireDep, setPolicyRequireDep] = useState(true);

  useEffect(() => {
    async function loadRepos() {
      try {
        const repoList = await apiFetch<RepoItem[]>("/api/v1/repositories");
        setRepos(repoList);
        if (repoList.length > 0) {
          const hasVuln = repoList.some((r) => r.full_name === "codefort-sec/vulnerable-test-repo");
          const defaultRepo = hasVuln ? "codefort-sec/vulnerable-test-repo" : repoList[0].full_name;
          setSelectedRepo(defaultRepo);
        }
      } catch (err) {
        console.error("Failed to load repositories:", err);
      } finally {
        setLoading(false);
      }
    }
    loadRepos();
  }, []);

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
    try {
      await apiFetch(`/api/v1/repositories/${encodeURIComponent(repoId)}/connect`, {
        method: "DELETE",
      });
      setRepos((prev) => {
        const remaining = prev.filter((r) => r.id !== repoId && r.full_name !== repoFullName);
        if (selectedRepo === repoFullName) {
          setSelectedRepo(remaining.length > 0 ? remaining[0].full_name : "");
        }
        return remaining;
      });
    } catch (err) {
      console.error("Failed to disconnect repository:", err);
    }
  }

  async function handleLoadDemoRepo() {
    setLoading(true);
    try {
      const res = await apiFetch<RepoItem>("/api/v1/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: "codefort-sec/vulnerable-test-repo" }),
      });
      setRepos((prev) => {
        const exists = prev.some((r) => r.full_name === res.full_name);
        return exists ? prev : [res, ...prev];
      });
      setSelectedRepo(res.full_name);
    } catch (err) {
      console.error("Failed to load demo repo:", err);
    } finally {
      setLoading(false);
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

      const res = await apiFetch<RepoItem>("/api/v1/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: cleanName, policy }),
      });

      setRepos((prev) => {
        const exists = prev.some((r) => r.full_name === res.full_name);
        return exists ? prev : [res, ...prev];
      });
      setSelectedRepo(res.full_name);
      setNewRepoName("");
      setShowConnectModal(false);
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
          <div className="text-xs text-lime uppercase tracking-widest">/01 DASHBOARD</div>
          <h1 className="text-2xl font-black text-text uppercase">REPOSITORIES & PULL REQUESTS</h1>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/settings"
            className="border border-border hover:border-lime text-text text-xs px-3 py-2 uppercase font-bold"
          >
            Extension Pairing
          </Link>
          <button
            type="button"
            onClick={() => {
              setConnectError(null);
              setShowConnectModal(true);
            }}
            className="bg-lime hover:bg-lime-muted text-bg text-xs px-4 py-2 uppercase font-extrabold transition-colors cursor-pointer"
          >
            + Connect Repository
          </button>
        </div>
      </div>

      {/* Repositories Section */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider flex items-center justify-between">
          <span>Connected Repositories ({repos.length}) — Click to filter scans</span>
          {repos.length === 0 && (
            <button
              onClick={handleLoadDemoRepo}
              className="text-[11px] text-lime hover:underline uppercase font-bold"
            >
              + Restore Demo Benchmark
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {repos.map((repo) => {
              const isSelected = repo.full_name === selectedRepo;
              const isDemo =
                repo.full_name === "codefort-sec/vulnerable-test-repo" ||
                repo.full_name === "codefort-sec/clean-test-repo";
              return (
                <div
                  key={repo.id}
                  onClick={() => setSelectedRepo(repo.full_name)}
                  className={`border p-4 flex flex-col justify-between cursor-pointer transition-all ${
                    isSelected
                      ? "border-lime bg-surface-raised shadow-[0_0_15px_rgba(204,255,0,0.15)]"
                      : "border-border bg-surface hover:border-text-dim"
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-1.5">
                        {isDemo ? (
                          <span className="text-[9px] px-1.5 py-0.5 font-extrabold bg-lime/10 border border-lime text-lime uppercase tracking-wider">
                            DEMO PLAYGROUND
                          </span>
                        ) : (
                          <span className="text-[9px] px-1.5 py-0.5 font-bold bg-surface-raised border border-border text-text-dim uppercase tracking-wider">
                            CONNECTED REPO
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] px-2 py-0.5 font-bold ${
                            isSelected
                              ? "bg-lime text-bg font-extrabold"
                              : "bg-surface-raised text-text-muted"
                          }`}
                        >
                          {isSelected ? "ACTIVE" : "SELECT"}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => handleDisconnectRepo(repo.id, repo.full_name, e)}
                          title="Disconnect repository"
                          className="text-text-dim hover:text-danger text-xs px-1 hover:bg-danger/10 transition-colors"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                    <div className="text-sm font-bold text-text uppercase mb-1 truncate">{repo.full_name}</div>
                    <div className="text-[11px] text-text-muted mb-4">
                      {isDemo
                        ? "Curated evaluation repository loaded with live supply chain attack scenarios."
                        : "Automated scan triggers active on PR opened & synchronize."}
                    </div>
                  </div>

                  <div className="border-t border-border pt-3 flex justify-between items-center text-xs">
                    <span className="text-text-dim">POLICY: DEFAULT</span>
                    <span className="text-lime font-bold">BLOCK ON CRITICAL</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Pull Requests & Scan Activity */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider flex items-center justify-between">
          <span>
            Recent Pull Request Scans —{" "}
            <span className="text-lime">{selectedRepo || "None selected"}</span>
          </span>
          <span className="text-[10px] text-text-dim">Auto-refresh active</span>
        </div>

        <div className="border border-border bg-surface overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-raised border-b border-border text-text-dim uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4">PR #</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Author</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {prs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-text-dim font-mono">
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
                    <tr key={pr.pull_request_number} className="hover:bg-surface-raised/50 transition-colors">
                      <td className="py-3 px-4 font-bold text-lime">#{pr.pull_request_number}</td>
                      <td className="py-3 px-4 font-medium text-text max-w-xs truncate">{pr.title}</td>
                      <td className="py-3 px-4 text-text-muted">@{pr.author_login}</td>
                      <td className="py-3 px-4">
                        {scanningPRs[pr.pull_request_number] ? (
                          <span className="px-2 py-0.5 text-[10px] font-bold border rounded-none bg-lime/10 border-lime text-lime animate-pulse">
                            ANALYZING...
                          </span>
                        ) : scan ? (
                          <span
                            className={`px-2 py-0.5 text-[10px] font-bold border rounded-none ${
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
                          <span className="text-text-dim">NO SCAN</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-bold">
                        {scanningPRs[pr.pull_request_number] ? (
                          <span className="text-lime animate-pulse text-[11px]">CALCULATING...</span>
                        ) : scan?.risk_score !== undefined ? (
                          <span className="text-lime">{scan.risk_score} / 100</span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {scan ? (
                            <>
                              <Link
                                href={`/scans/${scan.id}`}
                                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-[10px] px-3 py-1 uppercase tracking-wider"
                              >
                                FORENSICS ↗
                              </Link>
                              <button
                                type="button"
                                onClick={() => handleTriggerScan(pr.pull_request_number)}
                                disabled={scanningPRs[pr.pull_request_number]}
                                title="Re-run security scan"
                                className="border border-border hover:border-lime text-text text-[10px] px-2 py-1 transition-colors disabled:opacity-50"
                              >
                                {scanningPRs[pr.pull_request_number] ? "..." : "↻"}
                              </button>
                            </>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleTriggerScan(pr.pull_request_number)}
                              disabled={scanningPRs[pr.pull_request_number]}
                              className="border border-lime text-lime hover:bg-lime hover:text-bg font-bold text-[10px] px-3 py-1 uppercase tracking-wider transition-colors disabled:opacity-50"
                            >
                              {scanningPRs[pr.pull_request_number] ? "SCANNING..." : "⚡ TRIGGER SCAN"}
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
