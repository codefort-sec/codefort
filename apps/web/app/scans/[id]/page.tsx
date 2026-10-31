"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  FindingItem,
  getScan,
  getScanFindings,
  ScanDetail,
  getRemediationPatch,
  applyRemediationPatch,
  RemediationProposal,
  RemediationResponse,
} from "@/lib/api";

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);
  const [activeTab, setActiveTab] = useState<"side-by-side" | "diff">("side-by-side");
  const [applying, setApplying] = useState(false);
  const [applyResult, setApplyResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    async function loadScanData() {
      try {
        const scanData = await getScan(params.id);
        setScan(scanData);

        const findingsData = await getScanFindings(params.id);
        setFindings(findingsData.findings);

        // Fetch intelligent remediation proposals and verification status
        try {
          const remData = await getRemediationPatch(params.id);
          setRemediation(remData);
        } catch {
          // Remediation may be unavailable for non-vulnerable scans
        }
      } catch (err: any) {
        setError(err.message || "Failed to load scan");
      } finally {
        setLoading(false);
      }
    }
    loadScanData();
  }, [params.id]);

  const handleApplyRemediation = async () => {
    if (!scan) return;
    setApplying(true);
    setApplyResult(null);
    try {
      const res = await applyRemediationPatch(
        scan.id,
        `fix(security): apply CodeFort automated remediation for PR #${scan.pull_request}`
      );
      setApplyResult({
        success: true,
        message: res.message || "Remediation patch applied successfully to branch.",
      });
    } catch (err: any) {
      setApplyResult({
        success: false,
        message: err.message || "Failed to apply remediation patch.",
      });
    } finally {
      setApplying(false);
    }
  };

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
  const isVerified = remediation?.overall_verification_status === "verified";

  // Find matching proposal for the selected finding if modal is open
  const matchingProposal = selectedFinding
    ? remediation?.proposals.find(
        (p) => p.finding_id === selectedFinding.id || p.rule_id === selectedFinding.rule_id
      )
    : null;

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
            <div className="text-4xl font-black text-lime">
              {scan.risk_score ?? 0} <span className="text-xs text-text-dim">/ 100</span>
            </div>
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

      {/* Barq-AI Explanation Engine Summary */}
      {scan.summary && (
        <section className="border border-lime/40 bg-surface p-6 flex flex-col gap-5 relative">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center gap-2">
              <span className="bg-lime text-bg font-extrabold text-[10px] px-2 py-0.5">AI_COPILOT</span>
              <span className="text-xs font-bold text-lime uppercase tracking-wider">
                Barq-AI Grounded Explanation & Threat Correlation
              </span>
            </div>
            <span className="text-[10px] text-text-dim">MODEL: QWEN3.8_MAX_MOE (Evidence-Grounded)</span>
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
                02. Why It Matters (Impact & Threat Vector)
              </div>
              <p className="text-xs text-text leading-relaxed">{scan.summary.why_it_matters}</p>
            </div>
          </div>

          {scan.summary.evidence_observed.length > 0 && (
            <div className="border-t border-border/50 pt-4">
              <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">
                03. Concrete Telemetry Evidence Citations
              </div>
              <ul className="list-disc list-inside space-y-1.5 text-xs text-text-muted">
                {scan.summary.evidence_observed.map((ev, i) => (
                  <li key={i} className="text-lime">
                    <span className="text-text font-mono text-[11px]">{ev}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* Phase 3 & 4: Intelligent Remediation & 1-Click Verified Fixes */}
      {(remediation?.proposals?.length || scan.summary?.clean_patch) && (
        <section className="border border-lime bg-surface p-6 flex flex-col gap-5 shadow-lg shadow-lime/5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-lime text-bg text-[10px] font-black px-2 py-0.5 uppercase tracking-wider">
                  INTELLIGENT REMEDIATION
                </span>
                <span
                  className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 border ${
                    isVerified
                      ? "border-emerald-500 bg-emerald-500/10 text-emerald-400"
                      : "border-amber-500 bg-amber-500/10 text-amber-400"
                  }`}
                >
                  {isVerified ? "✓ VERIFIED: 0 REGRESSIONS DETECTED" : "⚠ REVIEW REQUIRED"}
                </span>
              </div>
              <h2 className="text-sm font-bold text-text uppercase tracking-wide">
                1-Click Clean Unified Patch & Side-by-Side Code Preview
              </h2>
            </div>

            <div className="flex items-center gap-3">
              <div className="border border-border bg-bg flex p-0.5 text-[10px]">
                <button
                  type="button"
                  onClick={() => setActiveTab("side-by-side")}
                  className={`px-3 py-1 font-bold uppercase ${
                    activeTab === "side-by-side" ? "bg-lime text-bg" : "text-text-dim hover:text-text"
                  }`}
                >
                  Side-by-Side
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("diff")}
                  className={`px-3 py-1 font-bold uppercase ${
                    activeTab === "diff" ? "bg-lime text-bg" : "text-text-dim hover:text-text"
                  }`}
                >
                  Unified Diff
                </button>
              </div>

              <button
                type="button"
                disabled={applying}
                onClick={handleApplyRemediation}
                className="bg-lime text-bg text-xs font-black px-4 py-2 uppercase tracking-wider hover:bg-lime-muted transition-colors disabled:opacity-50"
              >
                {applying ? "APPLYING PATCH..." : "APPLY VERIFIED FIX ↗"}
              </button>
            </div>
          </div>

          {/* Feedback Alert */}
          {applyResult && (
            <div
              className={`p-3 text-xs border ${
                applyResult.success
                  ? "bg-emerald-950/40 border-emerald-500 text-emerald-300"
                  : "bg-red-950/40 border-red-500 text-red-300"
              }`}
            >
              <div className="font-bold mb-0.5">
                {applyResult.success ? "✓ REMEDIATION STAGED" : "✗ APPLICATION ERROR"}
              </div>
              <div>{applyResult.message}</div>
            </div>
          )}

          {/* Side-by-Side Mode */}
          {activeTab === "side-by-side" && remediation?.proposals && remediation.proposals.length > 0 && (
            <div className="flex flex-col gap-6">
              {remediation.proposals.map((prop, idx) => (
                <div key={idx} className="border border-border bg-bg/50 p-4 flex flex-col gap-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-lime font-bold text-xs uppercase">{prop.title}</span>
                      <span className="text-[10px] text-text-dim font-mono">({prop.rule_id})</span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px]">
                      <span className="text-text-dim">
                        LOCATION: <span className="text-lime">{prop.file_path}:{prop.line_start}</span>
                      </span>
                      <span
                        className={`px-2 py-0.5 text-[9px] font-bold uppercase border ${
                          prop.verification_status === "verified"
                            ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                            : "border-amber-500/50 bg-amber-500/10 text-amber-400"
                        }`}
                      >
                        {prop.verification_status}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-text-muted">{prop.explanation}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {/* Original Code */}
                    <div className="border border-red-900/50 bg-red-950/20 p-3 flex flex-col gap-2">
                      <div className="text-[10px] font-bold text-red-400 uppercase tracking-wider flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-red-500 inline-block"></span>
                        Original Vulnerable Code
                      </div>
                      <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-red-200 overflow-x-auto whitespace-pre leading-relaxed border border-red-900/40">
                        {prop.original_code}
                      </pre>
                    </div>

                    {/* Suggested Fix */}
                    <div className="border border-emerald-900/50 bg-emerald-950/20 p-3 flex flex-col gap-2">
                      <div className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-emerald-400 inline-block"></span>
                        BARQAI Verified Correction
                      </div>
                      <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-emerald-200 overflow-x-auto whitespace-pre leading-relaxed border border-emerald-900/40">
                        {prop.suggested_code}
                      </pre>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Unified Diff Mode */}
          {(activeTab === "diff" || (!remediation?.proposals?.length && scan.summary?.clean_patch)) && (
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-text-dim uppercase tracking-wider">
                  Git Unified Patch (Target: PR Branch)
                </span>
                <button
                  type="button"
                  onClick={() => {
                    const patch = remediation?.clean_patch || scan.summary?.clean_patch;
                    if (patch) {
                      navigator.clipboard.writeText(patch);
                      alert("Unified diff copied to clipboard!");
                    }
                  }}
                  className="bg-surface-raised border border-border hover:border-lime text-lime text-[10px] font-bold px-3 py-1 uppercase"
                >
                  COPY DIFF ↗
                </button>
              </div>
              <pre className="p-4 bg-bg border border-border text-[11px] font-mono text-lime-muted overflow-x-auto whitespace-pre leading-relaxed">
                {remediation?.clean_patch || scan.summary?.clean_patch}
              </pre>
            </div>
          )}
        </section>
      )}

      {/* Findings List */}
      <section className="flex flex-col gap-4">
        <div className="flex justify-between items-center">
          <div className="text-xs text-text-dim uppercase tracking-wider">
            Detected Security Findings ({findings.length})
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
                    <span className="text-text-dim">RECOMMENDED: </span>
                    <span>{f.recommendation}</span>
                  </div>
                )}

                <button
                  type="button"
                  onClick={() => setSelectedFinding(f)}
                  className="bg-surface-raised border border-border hover:border-lime text-lime font-bold text-[10px] px-3 py-1 uppercase"
                >
                  INSPECT REMEDIATION ↗
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Remediation Patch Preview Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="border border-lime bg-surface max-w-3xl w-full p-6 flex flex-col gap-4 font-mono shadow-2xl">
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

            {matchingProposal ? (
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-text">{matchingProposal.title}</span>
                  <span className="px-2 py-0.5 text-[9px] font-bold uppercase border border-emerald-500 bg-emerald-500/10 text-emerald-400">
                    {matchingProposal.verification_status}
                  </span>
                </div>
                <p className="text-xs text-text-muted">{matchingProposal.explanation}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="border border-red-900/50 bg-red-950/20 p-3">
                    <div className="text-[10px] font-bold text-red-400 uppercase mb-1">Before</div>
                    <pre className="p-2 bg-black/60 text-[10px] font-mono text-red-200 overflow-x-auto whitespace-pre">
                      {matchingProposal.original_code}
                    </pre>
                  </div>
                  <div className="border border-emerald-900/50 bg-emerald-950/20 p-3">
                    <div className="text-[10px] font-bold text-emerald-400 uppercase mb-1">After (Fix)</div>
                    <pre className="p-2 bg-black/60 text-[10px] font-mono text-emerald-200 overflow-x-auto whitespace-pre">
                      {matchingProposal.suggested_code}
                    </pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-text">
                <div className="font-bold text-text-muted mb-1">Recommended Change:</div>
                <div className="p-3 bg-bg border border-border text-[11px] font-mono leading-relaxed text-lime-muted">
                  {selectedFinding.recommendation || "Review and remove suspicious lifecycle hooks."}
                </div>
              </div>
            )}

            <div className="text-[11px] text-text-dim">
              Note: Automated patches are verified independently through in-memory static, dependency, and workflow re-scanners.
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
                onClick={async () => {
                  await handleApplyRemediation();
                  setSelectedFinding(null);
                }}
              >
                Apply Fix to Branch ↗
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
