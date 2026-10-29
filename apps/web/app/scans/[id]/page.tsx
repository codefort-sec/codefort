"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { FindingItem, getScan, getScanFindings, ScanDetail } from "@/lib/api";

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);

  useEffect(() => {
    async function loadScanData() {
      try {
        const scanData = await getScan(params.id);
        setScan(scanData);

        const findingsData = await getScanFindings(params.id);
        setFindings(findingsData.findings);
      } catch (err: any) {
        setError(err.message || "Failed to load scan");
      } finally {
        setLoading(false);
      }
    }
    loadScanData();
  }, [params.id]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-16 font-mono text-center">
        <div className="text-lime text-sm animate-pulse">&gt; LOADING SCAN FORENSICS_</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-16 font-mono text-center">
        <div className="border border-danger bg-surface p-8 max-w-md mx-auto">
          <div className="text-danger font-bold text-sm mb-2">SCAN_NOT_FOUND</div>
          <p className="text-xs text-text-muted mb-4">{error || "Requested scan ID does not exist."}</p>
          <Link href="/dashboard" className="bg-lime text-bg font-bold text-xs px-4 py-2 uppercase">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  const isBlocked = scan.verdict === "BLOCKED";
  const isReview = scan.verdict === "REVIEW_REQUIRED";

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 font-mono flex flex-col gap-8 w-full">
      {/* Breadcrumb & Navigation */}
      <div className="flex items-center gap-2 text-xs text-text-dim">
        <Link href="/dashboard" className="hover:text-lime">
          / DASHBOARD
        </Link>
        <span>/</span>
        <span className="text-text-muted">{scan.repository}</span>
        <span>/</span>
        <span className="text-lime">PULL #{scan.pull_request}</span>
      </div>

      {/* Verdict & Risk Banner */}
      <div className="border border-border bg-surface p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <span
              className={`px-2.5 py-1 text-xs font-black uppercase tracking-wider border ${
                isBlocked
                  ? "bg-danger/10 border-danger text-danger"
                  : isReview
                  ? "bg-amber-500/10 border-amber-500 text-amber-500"
                  : "bg-emerald-500/10 border-emerald-500 text-emerald-500"
              }`}
            >
              VERDICT: {scan.verdict.replace(/_/g, " ")}
            </span>
            <span className="text-xs text-text-dim">SCAN ID: {scan.id}</span>
          </div>

          <h1 className="text-2xl font-black text-text uppercase">
            {scan.repository} • PR #{scan.pull_request}
          </h1>
          <div className="text-xs text-text-muted mt-1">
            Created at {new Date(scan.created_at).toLocaleString()}
          </div>
        </div>

        {/* Score Readout */}
        <div className="flex items-center gap-6 border-l border-border pl-6">
          <div className="text-right">
            <div className="text-[10px] text-text-dim uppercase tracking-wider">ESTIMATED RISK</div>
            <div className="text-4xl font-black text-lime">{scan.risk_score ?? 0} <span className="text-xs text-text-dim">/ 100</span></div>
          </div>
        </div>
      </div>

      {/* Coverage Status Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <div className="border border-border bg-surface-raised p-3 flex justify-between items-center">
          <span className="text-text-dim text-[11px]">STATIC ANALYSIS</span>
          <span className="text-lime font-bold uppercase text-[10px]">{scan.coverage.static_analysis}</span>
        </div>
        <div className="border border-border bg-surface-raised p-3 flex justify-between items-center">
          <span className="text-text-dim text-[11px]">DEPENDENCY INTEL</span>
          <span className="text-lime font-bold uppercase text-[10px]">{scan.coverage.dependency_intel}</span>
        </div>
        <div className="border border-border bg-surface-raised p-3 flex justify-between items-center">
          <span className="text-text-dim text-[11px]">WORKFLOW LINTER</span>
          <span className="text-lime font-bold uppercase text-[10px]">{scan.coverage.workflow_linter}</span>
        </div>
        <div className="border border-border bg-surface-raised p-3 flex justify-between items-center">
          <span className="text-text-dim text-[11px]">DYNAMIC SANDBOX</span>
          <span className="text-text-muted font-bold uppercase text-[10px]">{scan.coverage.dynamic_sandbox}</span>
        </div>
      </div>

      {/* BARQAI Explanation Engine Summary */}
      {scan.summary && (
        <section className="border border-lime/40 bg-surface p-6 flex flex-col gap-5 relative">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <span className="bg-lime text-bg font-extrabold text-[10px] px-2 py-0.5">AI_COPILOT</span>
              <span className="text-xs font-bold text-lime uppercase tracking-wider">
                BARQAI Structured Explanation
              </span>
            </div>
            <span className="text-[10px] text-text-dim">MODEL: GEMINI_BARQAI_V1</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">
                01. What Changed
              </div>
              <p className="text-xs text-text leading-relaxed">{scan.summary.what_changed}</p>
            </div>

            <div>
              <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">
                02. Why It Matters
              </div>
              <p className="text-xs text-text leading-relaxed">{scan.summary.why_it_matters}</p>
            </div>
          </div>

          {scan.summary.evidence_observed.length > 0 && (
            <div className="border-t border-border/50 pt-4">
              <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">
                03. Observed Evidence
              </div>
              <ul className="list-disc list-inside space-y-1 text-xs text-text-muted">
                {scan.summary.evidence_observed.map((ev, i) => (
                  <li key={i} className="text-lime-muted">
                    <span className="text-text">{ev}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* Findings List */}
      <section className="flex flex-col gap-4">
        <div className="flex justify-between items-center">
          <div className="text-xs text-text-dim uppercase tracking-wider">
            Detected Findings ({findings.length})
          </div>
        </div>

        <div className="flex flex-col gap-3">
          {findings.map((f) => (
            <div
              key={f.id}
              className="border border-border hover:border-border-strong bg-surface p-5 flex flex-col gap-3 transition-colors"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span
                    className={`px-2 py-0.5 text-[10px] font-black uppercase border ${
                      f.severity === "CRITICAL"
                        ? "bg-danger/20 border-danger text-danger"
                        : "bg-amber-500/20 border-amber-500 text-amber-500"
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="text-xs font-bold text-text uppercase">{f.title}</span>
                </div>
                <span className="text-[11px] text-text-dim font-mono">RULE: {f.rule_id}</span>
              </div>

              {f.description && (
                <p className="text-xs text-text-muted leading-relaxed">{f.description}</p>
              )}

              <div className="flex flex-wrap items-center justify-between border-t border-border/50 pt-3 text-xs gap-3">
                <div className="flex items-center gap-2 text-text-dim text-[11px]">
                  <span>LOCATION:</span>
                  <span className="text-lime">{f.file_path}:{f.line_start}</span>
                </div>

                {f.recommendation && (
                  <div className="text-[11px] text-text-muted">
                    <span className="text-text-dim">FIX: </span>
                    <span>{f.recommendation}</span>
                  </div>
                )}

                <button
                  type="button"
                  onClick={() => setSelectedFinding(f)}
                  className="bg-surface-raised border border-border hover:border-lime text-lime font-bold text-[10px] px-3 py-1 uppercase"
                >
                  PREVIEW REMEDIATION ↗
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Remediation Patch Preview Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="border border-lime bg-surface max-w-2xl w-full p-6 flex flex-col gap-4 font-mono shadow-2xl">
            <div className="flex justify-between items-center border-b border-border pb-3">
              <span className="text-xs font-bold text-lime uppercase">
                REMEDIATION PREVIEW // {selectedFinding.rule_id}
              </span>
              <button
                type="button"
                onClick={() => setSelectedFinding(null)}
                className="text-text-dim hover:text-text text-sm"
              >
                ✕
              </button>
            </div>

            <div className="text-xs text-text">
              <div className="font-bold text-text-muted mb-1">Recommended Change:</div>
              <div className="p-3 bg-bg border border-border text-[11px] font-mono leading-relaxed text-lime-muted">
                {selectedFinding.recommendation || "Review and remove suspicious lifecycle hooks."}
              </div>
            </div>

            <div className="text-[11px] text-text-dim">
              Note: Automated patches require authorized maintainer confirmation before application per security policy.
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setSelectedFinding(null)}
                className="border border-border text-text text-xs px-4 py-2 uppercase font-bold"
              >
                Close
              </button>
              <button
                type="button"
                className="bg-lime text-bg text-xs px-4 py-2 uppercase font-extrabold hover:bg-lime-muted"
                onClick={() => {
                  alert("Patch candidate created for review comment.");
                  setSelectedFinding(null);
                }}
              >
                Post Review Comment ↗
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
