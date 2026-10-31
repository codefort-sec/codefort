import React, { useEffect, useState } from "react";
import { getStoredConfig } from "../shared/storage";
import {
  ExtensionConfig,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionResponse,
} from "../shared/types";

export const App: React.FC = () => {
  const [config, setConfig] = useState<ExtensionConfig | null>(null);
  const [pairingToken, setPairingToken] = useState("");
  const [activePR, setActivePR] = useState<{ repo: string; pr: number } | null>(null);
  const [prStatus, setPRStatus] = useState<ExtensionPRStatusResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
    detectActiveTabPR();
  }, []);

  async function loadConfig() {
    const cfg = await getStoredConfig();
    setConfig(cfg);
  }

  async function detectActiveTabPR() {
    if (typeof chrome === "undefined" || !chrome.tabs?.query) {
      // Mock for local testing
      setActivePR({ repo: "muhammadfarshi/Faar-Pos", pr: 1 });
      fetchStatusForPR("muhammadfarshi/Faar-Pos", 1);
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const match = tab.url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
        if (match) {
          const repo = `${match[1]}/${match[2]}`;
          const pr = parseInt(match[3], 10);
          setActivePR({ repo, pr });
          fetchStatusForPR(repo, pr);
        }
      }
    } catch {
      // Ignore tab query errors
    }
  }

  async function fetchStatusForPR(repo: string, pr: number, force = false) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr, force };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<ExtensionPRStatusResponse>
      >(msg);

      if (res?.success) {
        setPRStatus(res.data);
      } else {
        setErrorMsg(res?.error?.message || "Failed to load scan");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to communicate with service worker");
    } finally {
      setLoading(false);
    }
  }

  async function handleTriggerScan() {
    if (!activePR) return;
    setScanning(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = {
        type: "TRIGGER_PR_SCAN",
        repo: activePR.repo,
        pr: activePR.pr,
      };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<ExtensionPRStatusResponse>
      >(msg);

      if (res?.success) {
        setPRStatus(res.data);
      } else {
        setErrorMsg(res?.error?.message || "Scan failed to initiate");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to trigger scan");
    } finally {
      setScanning(false);
    }
  }

  async function handlePair() {
    if (!pairingToken.trim()) return;
    setLoading(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = {
        type: "PAIR_WITH_TOKEN",
        pairingToken: pairingToken.trim(),
      };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<{ paired: boolean }>
      >(msg);

      if (!res?.success) {
        setErrorMsg(res?.error?.message || "Invalid or expired token");
      } else if (!res.data.paired) {
        setErrorMsg("Invalid or expired token");
      } else {
        setPairingToken("");
        await loadConfig();
        if (activePR) {
          fetchStatusForPR(activePR.repo, activePR.pr, true);
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to pair");
    } finally {
      setLoading(false);
    }
  }

  async function handleQuickDemoPair() {
    setLoading(true);
    setErrorMsg(null);
    try {
      const msg: ExtensionMessage = {
        type: "PAIR_WITH_TOKEN",
        pairingToken: "demo-pairing-token",
      };
      const res = await chrome.runtime.sendMessage<
        ExtensionMessage,
        ExtensionResponse<{ paired: boolean }>
      >(msg);

      if (res?.success && res.data.paired) {
        await loadConfig();
        if (activePR) {
          fetchStatusForPR(activePR.repo, activePR.pr, true);
        }
      } else {
        setErrorMsg("Failed to connect demo session");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to pair demo");
    } finally {
      setLoading(false);
    }
  }

  async function handleUnpair() {
    setLoading(true);
    try {
      const msg: ExtensionMessage = { type: "UNPAIR" };
      await chrome.runtime.sendMessage(msg);
      await loadConfig();
    } finally {
      setLoading(false);
    }
  }

  const totalFindings = prStatus
    ? prStatus.findings_count.critical +
      prStatus.findings_count.high +
      prStatus.findings_count.medium +
      prStatus.findings_count.low
    : 0;

  return (
    <div className="popup-container">
      {/* Header */}
      <header className="popup-header">
        <div className="popup-brand">
          <span className="brand-badge">CF</span>
          <span className="brand-title">CODEFORT GUARD</span>
        </div>
        <div className="status-indicator">
          <span className={`status-dot ${config?.paired ? "" : "offline"}`} />
          <span>{config?.paired ? "ONLINE" : "UNPAIRED"}</span>
        </div>
      </header>

      {/* Body */}
      <main className="popup-body">
        {/* Pairing Status Card */}
        {config?.paired ? (
          <div className="card" style={{ padding: "8px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ color: "#3fb950", fontSize: "10px" }}>●</span>
                <span style={{ fontSize: "11px", fontWeight: 700, color: "#f2f2ed" }}>
                  Connected to CodeFort
                </span>
              </div>
              <button
                type="button"
                className="unpair-link"
                onClick={handleUnpair}
                title="Disconnect paired session"
              >
                Disconnect
              </button>
            </div>
            {config.token && (
              <div style={{ color: "#686d64", fontSize: "10px", marginTop: "2px" }}>
                Token: {config.token.slice(0, 8)}...
              </div>
            )}
          </div>
        ) : (
          <div className="card">
            <div className="card-title">Connect to CodeFort</div>
            <p style={{ color: "#a2a59a", fontSize: "11px", marginBottom: "10px" }}>
              Pair this extension with your CodeFort web session to access private repository scans and organization policies.
            </p>
            <input
              type="text"
              className="input-field"
              placeholder="Enter pairing token..."
              value={pairingToken}
              onChange={(e) => setPairingToken(e.target.value)}
            />
            <button
              type="button"
              className="btn-primary"
              disabled={loading}
              onClick={handlePair}
            >
              {loading ? "PAIRING..." : "PAIR EXTENSION"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={handleQuickDemoPair}
              disabled={loading}
            >
              USE DEMO PAIRING TOKEN
            </button>
          </div>
        )}

        {/* Active PR Context */}
        {activePR ? (
          <div className="card">
            <div className="section-label">Active Pull Request</div>
            <div style={{ fontWeight: 700, fontSize: "13px", color: "#f2f2ed", marginBottom: "4px" }}>
              {activePR.repo} #{activePR.pr}
            </div>

            {loading && <p style={{ color: "#a2a59a", fontSize: "11px" }}>Fetching latest scan...</p>}

            {prStatus && (
              <>
                <div className="score-display">
                  <span className="score-val">{prStatus.risk_score ?? 0}</span>
                  <span
                    className={`score-verdict verdict-tag-${
                      prStatus.verdict === "PASS"
                        ? "pass"
                        : prStatus.verdict === "BLOCKED"
                        ? "blocked"
                        : "review"
                    }`}
                  >
                    {prStatus.verdict.replace(/_/g, " ")}
                  </span>
                </div>

                {prStatus.verdict === "PASS" && totalFindings === 0 && (
                  <div
                    style={{
                      background: "rgba(63, 185, 80, 0.08)",
                      border: "1px solid #238636",
                      borderRadius: "3px",
                      padding: "4px 8px",
                      fontSize: "10px",
                      color: "#3fb950",
                      fontWeight: 700,
                      marginBottom: "6px",
                    }}
                  >
                    ✓ Verified Safe — Zero Malicious Indicators
                  </div>
                )}

                <div className="findings-grid">
                  <div className="finding-counter">
                    <div className="finding-counter-val" style={{ color: "#ff6b5e" }}>
                      {prStatus.findings_count.critical}
                    </div>
                    <div className="finding-counter-lbl">CRIT</div>
                  </div>
                  <div className="finding-counter">
                    <div className="finding-counter-val" style={{ color: "#d29922" }}>
                      {prStatus.findings_count.high}
                    </div>
                    <div className="finding-counter-lbl">HIGH</div>
                  </div>
                  <div className="finding-counter">
                    <div className="finding-counter-val" style={{ color: "#e3b341" }}>
                      {prStatus.findings_count.medium}
                    </div>
                    <div className="finding-counter-lbl">MED</div>
                  </div>
                  <div className="finding-counter">
                    <div className="finding-counter-val" style={{ color: "#8b949e" }}>
                      {prStatus.findings_count.low}
                    </div>
                    <div className="finding-counter-lbl">LOW</div>
                  </div>
                </div>

                {/* Security Engine Coverage */}
                {prStatus.coverage && (
                  <div className="coverage-row">
                    <div className={`engine-pill status-${prStatus.coverage.static_analysis || "skipped"}`}>
                      STATIC {prStatus.coverage.static_analysis === "completed" ? "✓" : "–"}
                    </div>
                    <div className={`engine-pill status-${prStatus.coverage.dependency_intel || "skipped"}`}>
                      DEPS {prStatus.coverage.dependency_intel === "completed" ? "✓" : "–"}
                    </div>
                    <div className={`engine-pill status-${prStatus.coverage.workflow_linter || "skipped"}`}>
                      ACTIONS {prStatus.coverage.workflow_linter === "completed" ? "✓" : "–"}
                    </div>
                  </div>
                )}

                {/* Re-scan and Refresh Action Row */}
                <div className="btn-action-row">
                  <button
                    type="button"
                    className="btn-scan"
                    disabled={scanning || loading}
                    onClick={handleTriggerScan}
                  >
                    {scanning ? "SCANNING..." : "⚡ RE-SCAN PR"}
                  </button>
                  <button
                    type="button"
                    className="btn-refresh"
                    disabled={scanning || loading}
                    onClick={() => fetchStatusForPR(activePR.repo, activePR.pr, true)}
                    title="Refresh cached status"
                  >
                    ↻ Refresh
                  </button>
                </div>

                {/* Direct Dashboard Link */}
                <a
                  href={`https://codefort-web.vercel.app/dashboard?repo=${encodeURIComponent(
                    activePR.repo
                  )}`}
                  target="_blank"
                  rel="noreferrer"
                  className="link-dashboard"
                >
                  OPEN IN CODEFORT DASHBOARD ↗
                </a>
              </>
            )}

            {errorMsg && (
              <p style={{ color: "#ff6b5e", fontSize: "11px", marginTop: "8px" }}>
                {errorMsg}
              </p>
            )}
          </div>
        ) : (
          <div className="card" style={{ textAlign: "center", padding: "24px 12px" }}>
            <div style={{ fontSize: "22px", marginBottom: "8px" }}>🔍</div>
            <div className="card-title">No Active PR Detected</div>
            <p style={{ color: "#a2a59a", fontSize: "11px", lineHeight: "1.5" }}>
              Navigate to any GitHub Pull Request to view inline risk analysis, BARQAI reasoning, and supply chain findings.
            </p>
          </div>
        )}

        {/* Backend Info Card */}
        <div className="card" style={{ padding: "8px 12px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ color: "#686d64", fontSize: "10px" }}>Target API:</span>
            <span style={{ color: "#a2a59a", fontSize: "10px" }}>
              {config?.apiUrl || "https://codefort-lilac.vercel.app"}
            </span>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="popup-footer">
        <span>CodeFort Guard v0.1.2</span>
        <div style={{ display: "flex", gap: "8px" }}>
          <a href="https://codefort-web.vercel.app/extension" target="_blank" rel="noreferrer">
            Guide ↗
          </a>
          <span style={{ color: "#343832" }}>|</span>
          <a href="https://codefort-web.vercel.app/dashboard" target="_blank" rel="noreferrer">
            Dashboard ↗
          </a>
        </div>
      </footer>
    </div>
  );
};
