"use client";

import React, { useState } from "react";
import Link from "next/link";
import { apiFetch, createPairingToken } from "@/lib/api";

export default function SettingsPage() {
  const [pairingToken, setPairingToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isPaired, setIsPaired] = useState(false);
  const [pairedAt, setPairedAt] = useState<string | null>(null);

  // Check stored pairing state
  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const stored = localStorage.getItem("codefort_extension_paired");
      if (stored === "true") {
        setIsPaired(true);
        setPairedAt(localStorage.getItem("codefort_extension_paired_at") || "Active");
      }
    }
  }, []);

  // Poll for token pairing confirmation in real-time
  React.useEffect(() => {
    if (!pairingToken || isPaired) return;

    const interval = setInterval(async () => {
      try {
        const res = await apiFetch<{ token: string; status: string; paired_at?: number }>(
          `/api/v1/extension/pairing-tokens/${pairingToken}/status`
        );
        if (res?.status === "paired") {
          setIsPaired(true);
          const timeStr = new Date().toLocaleTimeString();
          setPairedAt(timeStr);
          if (typeof window !== "undefined") {
            localStorage.setItem("codefort_extension_paired", "true");
            localStorage.setItem("codefort_extension_paired_at", timeStr);
          }
          clearInterval(interval);
        }
      } catch {
        // Non-blocking status polling
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [pairingToken, isPaired]);

  async function handleGenerateToken() {
    setLoading(true);
    setCopied(false);
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

  function handleUnpair() {
    setIsPaired(false);
    setPairingToken(null);
    setPairedAt(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem("codefort_extension_paired");
      localStorage.removeItem("codefort_extension_paired_at");
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 font-mono flex flex-col gap-8 w-full">
      <div className="border-b border-border pb-4">
        <div className="text-xs text-lime uppercase tracking-widest">/03 SETTINGS &amp; PAIRING</div>
        <h1 className="text-2xl font-black text-text uppercase">EXTENSION PAIRING &amp; REPO POLICY</h1>
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
            <span className={`text-[11px] font-bold ${isPaired ? "text-emerald-400" : "text-lime"}`}>
              {isPaired ? "AUTHENTICATED // LIVE" : "SINGLE_USE / 300 SECONDS"}
            </span>
          </div>

          {isPaired ? (
            <div className="border border-emerald-500/40 bg-emerald-500/10 p-4 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-emerald-400 font-extrabold text-xs uppercase tracking-wide">
                    ✓ EXTENSION PAIRED &amp; ACTIVE
                  </span>
                </div>
                {pairedAt && (
                  <span className="text-[10px] text-text-dim">Paired at {pairedAt}</span>
                )}
              </div>
              <p className="text-xs text-text leading-relaxed">
                Your CodeFort Guard extension is authenticated and listening to GitHub PR events. Real-time malicious pull request banners and inline diff forensics will appear on GitHub.
              </p>
              <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-emerald-500/20">
                <a
                  href="https://github.com/codefort-sec/vulnerable-test-repo/pull/1"
                  target="_blank"
                  rel="noreferrer"
                  className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-3.5 py-1.5 uppercase transition-colors"
                >
                  Test On Demo PR #1 ↗
                </a>
                <button
                  type="button"
                  onClick={handleUnpair}
                  className="border border-border hover:border-danger text-text-muted hover:text-danger text-xs px-3 py-1.5 uppercase transition-colors"
                >
                  Unpair / Generate New Token
                </button>
              </div>
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
              <div className="flex items-center gap-2 text-[10px] text-lime mt-1">
                <span className="w-1.5 h-1.5 rounded-full bg-lime animate-ping" />
                <span>Waiting for extension to pair... Paste this token into the CodeFort Guard extension popup.</span>
              </div>
            </div>
          ) : (
            <button
              type="button"
              disabled={loading}
              onClick={handleGenerateToken}
              className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-5 py-3 tracking-wider uppercase transition-colors self-start cursor-pointer"
            >
              {loading ? "GENERATING TOKEN..." : "GENERATE PAIRING TOKEN ↗"}
            </button>
          )}

          {/* Extension Downloads */}
          <div className="border-t border-border pt-4 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-text uppercase">Install CodeFort Guard:</span>
              <Link href="/extension" className="text-lime text-[11px] hover:underline font-bold uppercase">
                Step-by-step Guide ↗
              </Link>
            </div>
            <div className="flex flex-wrap gap-3">
              <Link
                href="/extension"
                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-3.5 py-2 uppercase tracking-wider flex items-center gap-1.5 transition-colors"
              >
                <span>Interactive Setup Guide</span>
                <span>↗</span>
              </Link>
              <a
                href="/downloads/codefort-guard-chrome-v0.1.3.zip"
                download
                className="border border-border hover:border-lime text-text hover:text-lime text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>📦 Chrome (.zip)</span>
                <span>↓</span>
              </a>
              <a
                href="/downloads/codefort-guard-firefox-v0.1.3.xpi"
                download
                className="border border-border hover:border-lime text-text hover:text-lime text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>🦊 Firefox (.xpi)</span>
                <span>↓</span>
              </a>
              <a
                href="https://github.com/codefort-sec/codefort/releases/tag/v0.1.3"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-border hover:border-text-dim text-text-dim hover:text-text text-xs font-mono px-3 py-2 flex items-center gap-2 transition-colors"
              >
                <span>Release v0.1.3 ↗</span>
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
