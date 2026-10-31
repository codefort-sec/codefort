"use client";

import React, { useState } from "react";
import { createPairingToken } from "@/lib/api";

export default function SettingsPage() {
  const [pairingToken, setPairingToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const [isPaired, setIsPaired] = useState(false);

  // Live polling for pairing status
  React.useEffect(() => {
    if (!pairingToken || isPaired) return;
    let active = true;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/v1/extension/pairing-status?token=${encodeURIComponent(pairingToken)}`);
        if (res.ok) {
          const data = await res.json();
          if (data.paired && active) {
            setIsPaired(true);
            clearInterval(interval);
          }
        }
      } catch (err) {
        // Silently retry polling
      }
    }, 2500);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [pairingToken, isPaired]);

  async function handleGenerateToken() {
    setLoading(true);
    setCopied(false);
    setIsPaired(false);
    try {
      const res = await createPairingToken();
      setPairingToken(res.pairing_token);
      setExpiresIn(res.expires_in_seconds);
    } catch (err) {
      console.error("Failed to generate pairing token:", err);
    } finally {
      setLoading(false);
    }
  }

  function handleCopy() {
    if (pairingToken) {
      navigator.clipboard.writeText(pairingToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 font-mono flex flex-col gap-8 w-full">
      <div className="border-b border-border pb-4">
        <div className="text-xs text-lime uppercase tracking-widest">/03 SETTINGS & PAIRING</div>
        <h1 className="text-2xl font-black text-text uppercase">EXTENSION PAIRING & REPO POLICY</h1>
      </div>

      {/* Chrome Extension Pairing Card */}
      <section className="border border-border bg-surface p-6 flex flex-col gap-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="bg-lime text-bg text-[10px] font-extrabold px-1.5 py-0.5">AUTH_PAIR</span>
            <h2 className="text-sm font-bold text-text uppercase">Pair CodeFort Guard Extension</h2>
          </div>
          <p className="text-xs text-text-muted leading-relaxed">
            Generate a short-lived, single-use pairing token to authenticate your CodeFort Guard Chrome or Firefox extension. Once paired, the extension queries repository PR scan status and line-level warnings directly on GitHub.
          </p>
        </div>

        <div className="border border-border bg-bg p-5 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-text-dim uppercase">PAIRING CREDENTIAL STATUS</span>
            <span className="text-[11px] text-lime">SINGLE_USE / 300 SECONDS</span>
          </div>

          {isPaired ? (
            <div className="p-4 border border-lime bg-lime/10 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-lime text-base font-extrabold">✓</span>
                <div>
                  <div className="text-xs font-extrabold text-lime uppercase tracking-wider">PAIRING COMPLETE // EXTENSION CONNECTED</div>
                  <div className="text-[10px] text-text-muted">CodeFort Guard extension has been authenticated and linked to this workspace.</div>
                </div>
              </div>
              <button
                type="button"
                onClick={handleGenerateToken}
                className="text-[10px] text-text border border-border hover:border-lime px-2 py-1 uppercase"
              >
                Pair Another ↗
              </button>
            </div>
          ) : pairingToken ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={pairingToken}
                  className="w-full bg-surface-raised border border-lime text-lime px-3 py-2 text-xs font-mono select-all"
                />
                <button
                  type="button"
                  onClick={handleCopy}
                  className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-4 py-2 uppercase shrink-0"
                >
                  {copied ? "COPIED ✓" : "COPY"}
                </button>
              </div>
              <div className="flex items-center justify-between text-[10px] text-text-dim">
                <span>Paste this token into the CodeFort Guard extension popup to complete pairing.</span>
                <span className="text-lime animate-pulse">Waiting for extension...</span>
              </div>
            </div>
          ) : (
            <button
              type="button"
              disabled={loading}
              onClick={handleGenerateToken}
              className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-5 py-3 tracking-wider uppercase transition-colors self-start"
            >
              {loading ? "GENERATING TOKEN..." : "GENERATE PAIRING TOKEN ↗"}
            </button>
          )}

          {/* Extension Downloads */}
          <div className="border-t border-border pt-4 flex flex-col gap-2">
            <div className="text-[11px] font-bold text-text uppercase">Install CodeFort Guard:</div>
            <div className="flex flex-wrap gap-3">
              <a
                href="https://github.com/codefort-sec/barqai/releases/download/v0.1.2/codefort-guard-chrome-v0.1.2.zip"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border hover:border-lime text-text hover:text-lime text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>📦 Chrome (.zip)</span>
                <span>↓</span>
              </a>
              <a
                href="https://github.com/codefort-sec/barqai/releases/download/v0.1.2/codefort-guard-firefox-v0.1.2.xpi"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border hover:border-lime text-text hover:text-lime text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>🦊 Firefox (.xpi)</span>
                <span>↓</span>
              </a>
              <a
                href="https://github.com/codefort-sec/barqai/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border hover:border-text-dim text-text-dim hover:text-text text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>All Releases ↗</span>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Security Policy Settings */}
      <section className="border border-border bg-surface p-6 flex flex-col gap-4">
        <div>
          <h2 className="text-sm font-bold text-text uppercase mb-1">Default Security Policy</h2>
          <p className="text-xs text-text-muted">
            Configure automated policy thresholds for connected repositories.
          </p>
        </div>

        <div className="flex flex-col gap-3 text-xs">
          <label className="flex items-center gap-3 p-3 bg-surface-raised border border-border cursor-pointer">
            <input type="checkbox" defaultChecked className="accent-lime" />
            <div>
              <div className="font-bold text-text">Block Pull Requests on CRITICAL Findings</div>
              <div className="text-[11px] text-text-dim">Automatically sets verdict to BLOCKED when malicious scripts are verified.</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 bg-surface-raised border border-border cursor-pointer">
            <input type="checkbox" defaultChecked className="accent-lime" />
            <div>
              <div className="font-bold text-text">Require Human Review on HIGH Severity or Typosquats</div>
              <div className="text-[11px] text-text-dim">Sets verdict to REVIEW_REQUIRED for suspicious package names.</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 bg-surface-raised border border-border cursor-pointer">
            <input type="checkbox" defaultChecked className="accent-lime" />
            <div>
              <div className="font-bold text-text">Fail-Safe: Disclose Incomplete Engine Coverage</div>
              <div className="text-[11px] text-text-dim">Never issue PASS if static analysis or dependency intelligence fails.</div>
            </div>
          </label>
        </div>
      </section>
    </div>
  );
}
