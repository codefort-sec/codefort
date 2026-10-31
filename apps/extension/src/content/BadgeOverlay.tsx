import React, { useState } from "react";
import { ExtensionPRStatusResponse, ExtensionSummaryResponse } from "../shared/types";

interface BadgeOverlayProps {
  status: ExtensionPRStatusResponse | null;
  summary: ExtensionSummaryResponse | null;
  loading: boolean;
  error?: string | null;
}

export const BadgeOverlay: React.FC<BadgeOverlayProps> = ({
  status,
  summary,
  loading,
  error,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  if (loading) {
    return (
      <div className="codefort-badge-container">
        <div className="codefort-badge verdict-pending">
          <span>●</span>
          <span>CODEFORT: SCANNING...</span>
        </div>
      </div>
    );
  }

  if (error || !status) {
    return (
      <div className="codefort-badge-container">
        <div
          className="codefort-badge verdict-error"
          title={error || "Could not retrieve CodeFort status"}
        >
          <span>⚠</span>
          <span>CODEFORT: ERROR</span>
        </div>
      </div>
    );
  }

  const verdictClass = `verdict-${status.verdict.toLowerCase().replace(/_/g, "_")}`;
  const totalFindings =
    status.findings_count.critical +
    status.findings_count.high +
    status.findings_count.medium +
    status.findings_count.low;

  return (
    <div className="codefort-badge-container">
      <button
        type="button"
        className={`codefort-badge ${verdictClass}`}
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
      >
        <span>🛡 CODEFORT:</span>
        <span>{status.verdict.replace(/_/g, " ")}</span>
        {status.risk_score !== null && status.risk_score !== undefined && (
          <span className="codefort-score-pill">RISK {status.risk_score}</span>
        )}
        {totalFindings > 0 && (
          <span style={{ opacity: 0.85, fontSize: "10px" }}>
            ({totalFindings} finding{totalFindings > 1 ? "s" : ""})
          </span>
        )}
      </button>

      {isOpen && (
        <div className="codefort-summary-popover" role="dialog">
          <div className="codefort-summary-header">
            <span className="codefort-summary-title">BARQAI Security Analysis</span>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              style={{
                background: "none",
                border: "none",
                color: "#a2a59a",
                cursor: "pointer",
                fontSize: "14px",
              }}
            >
              ✕
            </button>
          </div>

          {summary?.summary ? (
            <>
              <div className="codefort-summary-section">
                <div className="codefort-summary-label">What Changed</div>
                <div className="codefort-summary-text">{summary.summary.what_changed}</div>
              </div>

              {summary.summary.evidence_observed.length > 0 && (
                <div className="codefort-summary-section">
                  <div className="codefort-summary-label">Observed Evidence</div>
                  {summary.summary.evidence_observed.map((ev, i) => (
                    <div key={i} className="codefort-summary-evidence-item">
                      {ev}
                    </div>
                  ))}
                </div>
              )}

              <div className="codefort-summary-section">
                <div className="codefort-summary-label">Why It Matters</div>
                <div className="codefort-summary-text">{summary.summary.why_it_matters}</div>
              </div>
            </>
          ) : (
            <div className="codefort-summary-text" style={{ color: "#a2a59a" }}>
              Scan completed. No critical anomalies reported.
            </div>
          )}

          <div
            style={{
              marginTop: "12px",
              paddingTop: "8px",
              borderTop: "1px solid #222622",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: "10px", color: "#686d64" }}>CodeFort v0.1.1</span>
            <a
              href="https://codefort-web.vercel.app/dashboard"
              target="_blank"
              rel="noreferrer"
              style={{
                color: "#d7ff35",
                fontSize: "11px",
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              Open Dashboard ↗
            </a>
          </div>
        </div>
      )}
    </div>
  );
};
