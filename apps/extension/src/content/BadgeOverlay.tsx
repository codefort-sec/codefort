import React, { useEffect, useRef, useState } from "react";
import { ExtensionPRStatusResponse, ExtensionSummaryResponse } from "../shared/types";

interface BadgeOverlayProps {
  status: ExtensionPRStatusResponse | null;
  summary: ExtensionSummaryResponse | null;
  loading: boolean;
  error?: string | null;
  onRetry?: () => void;
}

export const BadgeOverlay: React.FC<BadgeOverlayProps> = ({
  status,
  summary,
  loading,
  error,
  onRetry,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Close popover when clicking outside or pressing Escape
  useEffect(() => {
    if (!isOpen) return;

    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  if (loading) {
    return (
      <div className="codefort-badge-container" ref={containerRef}>
        <div className="codefort-badge verdict-pending">
          <span className="codefort-pulse-dot">●</span>
          <span>CODEFORT: SCANNING...</span>
        </div>
      </div>
    );
  }

  if (error || !status) {
    return (
      <div className="codefort-badge-container" ref={containerRef}>
        <button
          type="button"
          className="codefort-badge verdict-error"
          title={error || "Could not retrieve CodeFort status. Click to retry."}
          onClick={onRetry}
        >
          <span>⚠</span>
          <span>CODEFORT: ERROR</span>
          {onRetry && <span className="codefort-retry-action">↻ RETRY</span>}
        </button>
      </div>
    );
  }

  const verdictClass = `verdict-${status.verdict.toLowerCase().replace(/_/g, "_")}`;
  const totalFindings =
    status.findings_count.critical +
    status.findings_count.high +
    status.findings_count.medium +
    status.findings_count.low;

  const isClean = status.verdict === "PASS" && totalFindings === 0;

  return (
    <div className="codefort-badge-container" ref={containerRef}>
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
        {totalFindings > 0 ? (
          <span className="codefort-findings-tag">
            ({totalFindings} finding{totalFindings > 1 ? "s" : ""})
          </span>
        ) : isClean ? (
          <span className="codefort-clean-check">✓ CLEAN</span>
        ) : null}
      </button>

      {isOpen && (
        <div className="codefort-summary-popover" role="dialog">
          <div className="codefort-summary-header">
            <div className="codefort-summary-brand">
              <span className="codefort-brand-pill">BARQAI</span>
              <span className="codefort-summary-title">Security Analysis</span>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              className="codefort-close-btn"
              title="Close (Esc)"
            >
              ✕
            </button>
          </div>

          {/* Engine Coverage Bar */}
          {status.coverage && (
            <div className="codefort-coverage-row">
              <div
                className={`codefort-engine-chip chip-${status.coverage.static_analysis || "not_configured"}`}
                title="Static Pattern & AST Rules"
              >
                STATIC {status.coverage.static_analysis === "completed" ? "✓" : "–"}
              </div>
              <div
                className={`codefort-engine-chip chip-${status.coverage.dependency_intel || "not_configured"}`}
                title="Package Intelligence & Typosquatting"
              >
                DEPS {status.coverage.dependency_intel === "completed" ? "✓" : "–"}
              </div>
              <div
                className={`codefort-engine-chip chip-${status.coverage.workflow_linter || "not_configured"}`}
                title="GitHub Actions CI Permissions"
              >
                ACTIONS {status.coverage.workflow_linter === "completed" ? "✓" : "–"}
              </div>
            </div>
          )}

          {summary?.summary ? (
            <>
              <div className="codefort-summary-section">
                <div className="codefort-summary-label">What Changed</div>
                <div className="codefort-summary-text">{summary.summary.what_changed}</div>
              </div>

              {summary.summary.evidence_observed && summary.summary.evidence_observed.length > 0 && (
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

              {summary.summary.recommended_actions && summary.summary.recommended_actions.length > 0 && (
                <div className="codefort-summary-section">
                  <div className="codefort-summary-label">Recommended Actions</div>
                  {summary.summary.recommended_actions.map((act, i) => (
                    <div key={i} className="codefort-summary-action-item">
                      › {act}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : isClean ? (
            <div className="codefort-clean-box">
              <div style={{ color: "#3fb950", fontWeight: 700, marginBottom: "4px" }}>
                ✓ Zero Malicious Indicators Detected
              </div>
              <div className="codefort-summary-text" style={{ color: "#a2a59a" }}>
                Pull request verified clean against static rules, package intelligence, and workflow linter policies.
              </div>
            </div>
          ) : (
            <div className="codefort-summary-text" style={{ color: "#a2a59a" }}>
              Scan completed. View full details in the CodeFort Dashboard.
            </div>
          )}

          <div className="codefort-popover-footer">
            <span className="codefort-version-label">CodeFort Guard v0.1.2</span>
            <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
              {onRetry && (
                <button
                  type="button"
                  onClick={onRetry}
                  className="codefort-footer-rescan"
                  title="Trigger fresh scan"
                >
                  ↻ Re-scan
                </button>
              )}
              <a
                href={`https://codefort-web.vercel.app/dashboard?repo=${encodeURIComponent(
                  status.repository
                )}`}
                target="_blank"
                rel="noreferrer"
                className="codefort-footer-link"
              >
                Dashboard ↗
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
