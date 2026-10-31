"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch } from "@/lib/api";

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
  const [selectedRepo, setSelectedRepo] = useState<string>("codefort-sec/codefort");
  const [prs, setPrs] = useState<PRItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadRepos() {
      try {
        const repoList = await apiFetch<RepoItem[]>("/api/v1/repositories");
        setRepos(repoList);
        if (repoList.length > 0) {
          const hasCodefort = repoList.some((r) => r.full_name === "codefort-sec/codefort");
          const defaultRepo = hasCodefort ? "codefort-sec/codefort" : repoList[0].full_name;
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
    if (!selectedRepo) return;
    async function loadPrs() {
      try {
        const prList = await apiFetch<PRItem[]>(`/api/v1/repositories/${selectedRepo}/pull-requests`);
        setPrs(prList);
      } catch (err) {
        console.error(`Failed to load PRs for ${selectedRepo}:`, err);
      }
    }
    loadPrs();
  }, [selectedRepo]);

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
            className="bg-lime hover:bg-lime-muted text-bg text-xs px-4 py-2 uppercase font-extrabold"
          >
            + Connect Repository
          </button>
        </div>
      </div>

      {/* Repositories Section */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider">
          Connected Repositories ({repos.length}) — Click to filter scans
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {repos.map((repo) => {
            const isSelected = repo.full_name === selectedRepo;
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
                    <span className="text-xs text-text-dim">ID: {repo.id}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 font-bold ${
                        isSelected
                          ? "bg-lime text-bg font-extrabold"
                          : "bg-lime/10 border border-lime text-lime"
                      }`}
                    >
                      {isSelected ? "ACTIVE" : "CONNECTED"}
                    </span>
                  </div>
                  <div className="text-sm font-bold text-text uppercase mb-1">{repo.full_name}</div>
                  <div className="text-[11px] text-text-muted mb-4">
                    Automated scan triggers active on PR opened & synchronize.
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
      </section>

      {/* Pull Requests & Scan Activity */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider flex items-center justify-between">
          <span>Recent Pull Request Scans — <span className="text-lime">{selectedRepo}</span></span>
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
              {prs.map((pr) => {
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
                      {scan ? (
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
                      {scan?.risk_score !== undefined ? (
                        <span className="text-lime">{scan.risk_score} / 100</span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {scan ? (
                        <Link
                          href={`/scans/${scan.id}`}
                          className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-[10px] px-3 py-1 uppercase"
                        >
                          FORENSICS ↗
                        </Link>
                      ) : (
                        <button
                          type="button"
                          className="border border-border text-text text-[10px] px-2 py-1"
                        >
                          TRIGGER SCAN
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
