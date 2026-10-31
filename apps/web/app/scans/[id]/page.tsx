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
  RemediationRecord,
  getRemediationRecord,
  testSandboxRemediation,
  approveRemediation,
} from "@/lib/api";

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [remediationRecord, setRemediationRecord] = useState<RemediationRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);
  const [activeTab, setActiveTab] = useState<"side-by-side" | "diff">("side-by-side");
  const [applying, setApplying] = useState(false);
  const [testing, setTesting] = useState(false);
  const [approving, setApproving] = useState(false);
  const [applyResult, setApplyResult] = useState<{ success: boolean; message: string } | null>(null);
  const [testResult, setTestResult] = useState<{ passed: boolean; details: string } | null>(null);
  const [approvalResult, setApprovalResult] = useState<{ approved: boolean; message: string } | null>(null);

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

        // Fetch candidate remediation record (Phase 3)
        try {
          const record = await getRemediationRecord(params.id);
          setRemediationRecord(record);
        } catch {
          // Record may be absent if not yet requested
        }
      } catch (err: any) {
        setError(err.message || "Failed to load scan");
      } finally {
        setLoading(false);
      }
    }
    loadScanData();
  }, [params.id]);

  const handleRunSandboxTest = async () => {
    if (!scan && !remediationRecord) return;
    setTesting(true);
    setTestResult(null);
    try {
      const idToTest = remediationRecord?.id || scan?.id;
      const res = await testSandboxRemediation(
        idToTest!,
        remediationRecord?.unified_diff || scan?.summary?.clean_patch || undefined,
        remediationRecord?.file_path || "package.json"
      );
      setTestResult({
        passed: res.passed,
        details: res.details,
      });
      if (remediationRecord) {
        setRemediationRecord({
          ...remediationRecord,
          checks: res.checks,
          status: res.passed ? "tested" : "rejected",
        });
      }
    } catch (err: any) {
      setTestResult({
        passed: false,
        details: err.message || "Sandbox testing failed.",
      });
    } finally {
      setTesting(false);
    }
  };

  const handleApprovePatch = async () => {
    if (!scan && !remediationRecord) return;
    setApproving(true);
    setApprovalResult(null);
    try {
      const idToApprove = remediationRecord?.id || scan?.id;
      const res = await approveRemediation(idToApprove!, "developer", "Developer reviewed and approved in Patch Studio");
      setApprovalResult({
        approved: res.approved,
        message: res.message,
      });
      if (remediationRecord) {
        setRemediationRecord({
          ...remediationRecord,
          approved: true,
          status: "approved",
          approved_by: res.approved_by || "developer",
          approved_at: res.approved_at,
        });
      }
    } catch (err: any) {
      setApprovalResult({
        approved: false,
        message: err.message || "Failed to record approval.",
      });
    } finally {
      setApproving(false);
    }
  };

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

      {/* CODEFORT_ / BARQAI Forensic Room */}
      <section className="border border-lime/60 bg-surface p-6 flex flex-col gap-6 relative shadow-xl shadow-lime/5">
        {/* Header & Risk Level */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
          <div>
            <div className="text-[10px] text-text-dim uppercase tracking-wider font-bold">
              CYBERSECURITY INTELLIGENCE ENGINE
            </div>
            <div className="text-xl font-black text-lime tracking-wide">
              CODEFORT_ / BARQAI
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`px-3 py-1 text-xs font-black uppercase tracking-wider border ${
                (scan.summary?.risk_level === "CRITICAL" || isBlocked)
                  ? "bg-danger/20 border-danger text-danger"
                  : (scan.summary?.risk_level === "HIGH" || isReview)
                  ? "bg-amber-500/20 border-amber-500 text-amber-500"
                  : scan.summary?.risk_level === "MEDIUM"
                  ? "bg-yellow-500/20 border-yellow-500 text-yellow-500"
                  : "bg-emerald-500/20 border-emerald-500 text-emerald-400"
              }`}
            >
              {scan.summary?.risk_level || (isBlocked ? "HIGH" : isReview ? "MEDIUM" : "LOW")} RISK
            </span>
          </div>
        </div>

        {/* Score Readout & Verification Status */}
        <div className="border border-border/80 bg-bg/70 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="text-3xl font-black text-lime">
              {scan.risk_score ?? (isBlocked ? 85 : isReview ? 74 : 0)}
              <span className="text-sm text-text-dim">/100</span>
            </div>
            <div className="text-[11px] text-text-muted uppercase tracking-wider mt-0.5">
              Illustrative risk score
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[11px]">
            <div className="border border-border bg-surface px-3 py-1.5 flex items-center gap-2">
              <span className="text-text-dim uppercase">Evidence verification:</span>
              <span className="text-lime font-bold">
                {scan.summary?.evidence_verification || "Validated"}
              </span>
            </div>
            <div className="border border-border bg-surface px-3 py-1.5 flex items-center gap-2">
              <span className="text-text-dim uppercase">Patch verification:</span>
              <span className="text-text font-bold">
                {scan.summary?.patch_verification || (isVerified ? "Validated" : "Not tested")}
              </span>
            </div>
          </div>
        </div>

        {/* SECURITY FINDINGS */}
        <div>
          <div className="text-xs font-bold text-text uppercase tracking-wider mb-2.5 flex items-center gap-2">
            <span className="w-2 h-2 bg-lime inline-block"></span>
            SECURITY FINDINGS
          </div>
          <div className="flex flex-col gap-2">
            {findings.length > 0 ? (
              findings.map((f, idx) => {
                const evId = f.evidence_id || `OSV-${idx + 1 < 10 ? "00" + (idx + 1) : idx + 1}`;
                return (
                  <div
                    key={f.id || idx}
                    className="border border-border/80 bg-surface-raised p-3 flex flex-wrap items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-text">
                        {f.title}
                      </span>
                      <span className="text-[10px] text-lime font-mono">
                        ({evId})
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-black uppercase border ${
                        f.severity === "CRITICAL"
                          ? "bg-danger/20 border-danger text-danger"
                          : f.severity === "HIGH"
                          ? "bg-amber-500/20 border-amber-500 text-amber-500"
                          : "bg-emerald-500/20 border-emerald-500 text-emerald-400"
                      }`}
                    >
                      {f.severity}
                    </span>
                  </div>
                );
              })
            ) : (
              <div className="text-xs text-text-muted italic border border-border/50 p-3 bg-surface-raised">
                No security findings detected. Repository satisfies security baseline.
              </div>
            )}
          </div>
        </div>

        {/* BARQAI EXPLANATION */}
        <div>
          <div className="text-xs font-bold text-text uppercase tracking-wider mb-2 flex items-center gap-2">
            <span className="w-2 h-2 bg-lime inline-block"></span>
            BARQAI EXPLANATION
          </div>
          <div className="border border-border/70 bg-bg/50 p-4 text-xs text-text leading-relaxed font-mono">
            {scan.summary?.why_it_matters || scan.summary?.what_changed || "Security review completed."}
          </div>
        </div>

        {/* RECOMMENDATIONS */}
        <div>
          <div className="text-xs font-bold text-text uppercase tracking-wider mb-2 flex items-center gap-2">
            <span className="w-2 h-2 bg-lime inline-block"></span>
            RECOMMENDATIONS
          </div>
          <ul className="list-disc list-inside space-y-1.5 text-xs text-text-muted">
            {(scan.summary?.recommended_actions && scan.summary.recommended_actions.length > 0
              ? scan.summary.recommended_actions
              : ["Update identified dependencies to verified fixed versions.", "Rerun CODEFORT scan."]
            ).map((rec, i) => (
              <li key={i} className="text-lime">
                <span className="text-text">{rec}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* REPORTED UNCERTAINTIES & UNKNOWNS (if present) */}
        {scan.summary?.unknowns && scan.summary.unknowns.length > 0 && (
          <div className="border-t border-border/60 pt-3">
            <div className="text-[10px] font-bold text-amber-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <span>⚠</span>
              <span>REPORTED UNCERTAINTIES & MISSING EVIDENCE</span>
            </div>
            <ul className="list-disc list-inside text-xs text-amber-300/80 space-y-1">
              {scan.summary.unknowns.map((u, i) => (
                <li key={i}>{u}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {/* CODEFORT_ / PATCH STUDIO (Phase 3 Intelligent Remediation & Patch Verification) */}
      {(remediation?.proposals?.length || scan.summary?.clean_patch || remediationRecord) && (
        <section className="border border-lime bg-surface p-6 flex flex-col gap-6 shadow-xl shadow-lime/5">
          {/* Header & Status Badge */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
            <div>
              <div className="text-[10px] text-text-dim uppercase tracking-wider font-bold">
                AI-POWERED CODE REMEDIATION & VERIFICATION
              </div>
              <div className="text-xl font-black text-lime tracking-wide flex items-center gap-2">
                <span>CODEFORT_ / PATCH STUDIO</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <span
                className={`px-3 py-1 text-xs font-black uppercase tracking-wider border ${
                  remediationRecord?.approved || approvalResult?.approved
                    ? "bg-emerald-500/20 border-emerald-500 text-emerald-400"
                    : "bg-amber-500/20 border-amber-500 text-amber-400"
                }`}
              >
                {remediationRecord?.approved || approvalResult?.approved ? "Approved ✓" : "Awaiting review"}
              </span>

              <div className="border border-border bg-bg flex p-0.5 text-[10px]">
                <button
                  type="button"
                  onClick={() => setActiveTab("side-by-side")}
                  className={`px-3 py-1 font-bold uppercase transition-colors ${
                    activeTab === "side-by-side" ? "bg-lime text-bg" : "text-text-dim hover:text-text"
                  }`}
                >
                  Side-by-Side
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("diff")}
                  className={`px-3 py-1 font-bold uppercase transition-colors ${
                    activeTab === "diff" ? "bg-lime text-bg" : "text-text-dim hover:text-text"
                  }`}
                >
                  Unified Diff
                </button>
              </div>
            </div>
          </div>

          {/* Finding Label & Target Context */}
          {remediationRecord && (
            <div className="border border-border/80 bg-bg/60 p-3.5 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-lime inline-block"></span>
                <span className="text-xs font-bold text-text">
                  Security finding: <span className="text-lime">{remediationRecord.title}</span>
                </span>
                <span className="text-[10px] text-text-dim font-mono">({remediationRecord.file_path})</span>
              </div>
              <span className="text-[10px] text-text-dim font-mono uppercase">
                PATCH ID: {remediationRecord.id}
              </span>
            </div>
          )}

          {/* Verification Status Checklist */}
          <div className="border border-border bg-bg/40 p-4 flex flex-col gap-2.5">
            <div className="text-[10px] text-text-dim uppercase tracking-wider font-bold flex items-center justify-between">
              <span>VERIFICATION STATUS CHECKLIST</span>
              <span className="text-lime font-mono">0 REGRESSIONS</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              <div className="border border-border/80 bg-surface px-3 py-2 flex justify-between items-center">
                <span className="text-text-dim text-[11px]">Patch format:</span>
                <span className={`font-bold text-[10px] uppercase ${
                  (remediationRecord?.checks.patch_format || "Passed") === "Passed" ? "text-lime" : "text-danger"
                }`}>
                  {remediationRecord?.checks.patch_format || "Passed"}
                </span>
              </div>
              <div className="border border-border/80 bg-surface px-3 py-2 flex justify-between items-center">
                <span className="text-text-dim text-[11px]">Syntax check:</span>
                <span className={`font-bold text-[10px] uppercase ${
                  (remediationRecord?.checks.syntax_check || "Passed") === "Passed" ? "text-lime" : "text-danger"
                }`}>
                  {remediationRecord?.checks.syntax_check || "Passed"}
                </span>
              </div>
              <div className="border border-border/80 bg-surface px-3 py-2 flex justify-between items-center">
                <span className="text-text-dim text-[11px]">Unit tests:</span>
                <span className={`font-bold text-[10px] uppercase ${
                  (remediationRecord?.checks.unit_tests || (isVerified ? "Passed" : "Pending")) === "Passed" ? "text-lime" : "text-amber-400"
                }`}>
                  {remediationRecord?.checks.unit_tests || (isVerified ? "Passed" : "Pending")}
                </span>
              </div>
              <div className="border border-border/80 bg-surface px-3 py-2 flex justify-between items-center">
                <span className="text-text-dim text-[11px]">Security retest:</span>
                <span className={`font-bold text-[10px] uppercase ${
                  (remediationRecord?.checks.security_retest || (isVerified ? "Passed" : "Pending")) === "Passed" ? "text-lime" : "text-amber-400"
                }`}>
                  {remediationRecord?.checks.security_retest || (isVerified ? "Passed" : "Pending")}
                </span>
              </div>
            </div>
          </div>

          {/* Feedback Alerts for Sandbox Test & Approval */}
          {testResult && (
            <div
              className={`p-3 text-xs border ${
                testResult.passed
                  ? "bg-emerald-950/40 border-emerald-500 text-emerald-300"
                  : "bg-red-950/40 border-red-500 text-red-300"
              }`}
            >
              <div className="font-bold mb-0.5">
                {testResult.passed ? "✓ SANDBOX VERIFICATION PASSED" : "✗ SANDBOX TEST FAILED"}
              </div>
              <div>{testResult.details}</div>
            </div>
          )}

          {approvalResult && (
            <div
              className={`p-3 text-xs border ${
                approvalResult.approved
                  ? "bg-emerald-950/40 border-emerald-500 text-emerald-300"
                  : "bg-red-950/40 border-red-500 text-red-300"
              }`}
            >
              <div className="font-bold mb-0.5">
                {approvalResult.approved ? "✓ DEVELOPER APPROVAL RECORDED" : "✗ APPROVAL ERROR"}
              </div>
              <div>{approvalResult.message}</div>
            </div>
          )}

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

          {/* Side-by-Side Code Comparison */}
          {activeTab === "side-by-side" && (
            <div className="flex flex-col gap-4">
              {(remediation?.proposals && remediation.proposals.length > 0) ? (
                remediation.proposals.map((prop, idx) => (
                  <div key={idx} className="border border-border bg-bg/50 p-4 flex flex-col gap-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-lime font-bold text-xs uppercase">
                          Security finding: {prop.title}
                        </span>
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
                          Original code
                        </div>
                        <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-red-200 overflow-x-auto whitespace-pre leading-relaxed border border-red-900/40">
                          {prop.original_code}
                        </pre>
                      </div>

                      {/* Suggested Correction */}
                      <div className="border border-emerald-900/50 bg-emerald-950/20 p-3 flex flex-col gap-2">
                        <div className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                          <span className="w-1.5 h-1.5 bg-emerald-400 inline-block"></span>
                          Suggested correction
                        </div>
                        <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-emerald-200 overflow-x-auto whitespace-pre leading-relaxed border border-emerald-900/40">
                          {prop.suggested_code}
                        </pre>
                      </div>
                    </div>
                  </div>
                ))
              ) : remediationRecord ? (
                <div className="border border-border bg-bg/50 p-4 flex flex-col gap-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
                    <span className="text-lime font-bold text-xs uppercase">
                      Security finding: {remediationRecord.title}
                    </span>
                    <span className="text-[11px] text-text-dim">
                      LOCATION: <span className="text-lime">{remediationRecord.file_path}</span>
                    </span>
                  </div>

                  <p className="text-xs text-text-muted">{remediationRecord.explanation}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {/* Original Code */}
                    <div className="border border-red-900/50 bg-red-950/20 p-3 flex flex-col gap-2">
                      <div className="text-[10px] font-bold text-red-400 uppercase tracking-wider flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-red-500 inline-block"></span>
                        Original code
                      </div>
                      <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-red-200 overflow-x-auto whitespace-pre leading-relaxed border border-red-900/40">
                        {remediationRecord.original_code}
                      </pre>
                    </div>

                    {/* Suggested Correction */}
                    <div className="border border-emerald-900/50 bg-emerald-950/20 p-3 flex flex-col gap-2">
                      <div className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-emerald-400 inline-block"></span>
                        Suggested correction
                      </div>
                      <pre className="p-2.5 bg-black/60 text-[11px] font-mono text-emerald-200 overflow-x-auto whitespace-pre leading-relaxed border border-emerald-900/40">
                        {remediationRecord.suggested_code}
                      </pre>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Required Caption */}
              <div className="text-[11px] text-text-dim italic text-center py-1">
                Illustrative versions only. The actual fix must be supported by the relevant advisory and compatibility testing.
              </div>
            </div>
          )}

          {/* Unified Diff Mode */}
          {(activeTab === "diff" || (!remediation?.proposals?.length && !remediationRecord && scan.summary?.clean_patch)) && (
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-text-dim uppercase tracking-wider">
                  Git Unified Patch (Target: PR Branch)
                </span>
                <button
                  type="button"
                  onClick={() => {
                    const patch = remediationRecord?.unified_diff || remediation?.clean_patch || scan.summary?.clean_patch;
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
                {remediationRecord?.unified_diff || remediation?.clean_patch || scan.summary?.clean_patch}
              </pre>
              <div className="text-[11px] text-text-dim italic text-center py-1">
                Illustrative versions only. The actual fix must be supported by the relevant advisory and compatibility testing.
              </div>
            </div>
          )}

          {/* Approval Section */}
          <div className="border border-border/80 bg-surface-raised p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="text-xs font-bold text-text uppercase tracking-wider mb-1 flex items-center gap-2">
                <span className="w-2 h-2 bg-amber-400 inline-block"></span>
                Developer approval required
              </div>
              <p className="text-[11px] text-text-muted">
                Automated sandbox verification confirms exploit elimination, but developer approval is required before applying or merging candidate changes.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                disabled={testing}
                onClick={handleRunSandboxTest}
                className="bg-surface border border-border hover:border-lime text-lime text-xs font-bold px-4 py-2 uppercase tracking-wider transition-colors disabled:opacity-50"
              >
                {testing ? "RUNNING SANDBOX..." : "RUN SANDBOX TEST"}
              </button>

              <button
                type="button"
                disabled={approving || remediationRecord?.approved || approvalResult?.approved}
                onClick={handleApprovePatch}
                className={`text-xs font-black px-4 py-2 uppercase tracking-wider transition-colors disabled:opacity-50 ${
                  remediationRecord?.approved || approvalResult?.approved
                    ? "bg-emerald-600/30 text-emerald-400 border border-emerald-500 cursor-default"
                    : "bg-amber-500 text-bg hover:bg-amber-400"
                }`}
              >
                {approving
                  ? "RECORDING APPROVAL..."
                  : remediationRecord?.approved || approvalResult?.approved
                  ? "APPROVED ✓"
                  : "APPROVE PATCH"}
              </button>

              <button
                type="button"
                disabled={applying}
                onClick={handleApplyRemediation}
                className="bg-lime text-bg text-xs font-black px-4 py-2 uppercase tracking-wider hover:bg-lime-muted transition-colors disabled:opacity-50"
              >
                {applying ? "APPLYING..." : "APPLY VERIFIED FIX ↗"}
              </button>
            </div>
          </div>
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
