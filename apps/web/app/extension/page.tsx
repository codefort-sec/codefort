"use client";

import React, { useState } from "react";
import Link from "next/link";
import { createPairingToken } from "@/lib/api";

export default function ExtensionGuidePage() {
  const [activeTab, setActiveTab] = useState<"chrome" | "firefox">("chrome");
  const [pairingToken, setPairingToken] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied] = useState(false);

  async function handleGenerateToken() {
    setGenerating(true);
    setCopied(false);
    try {
      const res = await createPairingToken();
      setPairingToken(res.pairing_token);
    } catch (err) {
      console.error("Failed to generate token:", err);
    } finally {
      setGenerating(false);
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
    <div className="max-w-6xl mx-auto px-4 py-8 font-mono flex flex-col gap-10 w-full">
      {/* Header / Hero */}
      <div className="border border-border bg-surface p-6 md:p-8 relative">
        <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-lime" />
        <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-lime" />
        <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-lime" />
        <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-lime" />

        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-xs text-lime tracking-widest uppercase">
            <span>/04 EXTENSION INSTALLATION</span>
            <span>•</span>
            <span>CODEFORT GUARD BROWSER COPILOT</span>
          </div>

          <h1 className="text-2xl md:text-4xl font-black text-text uppercase tracking-tight">
            INSTALL CODEFORT GUARD <span className="text-lime">v0.1.2</span>
          </h1>

          <p className="text-xs md:text-sm text-text-muted max-w-3xl leading-relaxed">
            CodeFort Guard brings real-time zero-trust supply chain analysis directly into GitHub Pull Requests. It overlays inline risk badges, flags dangerous lifecycle hooks, and inspects untrusted CI/CD workflows before you merge.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <a
              href="https://github.com/codefort-sec/codefort/releases/tag/v0.1.2"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-4 py-2.5 uppercase tracking-wider flex items-center gap-2 transition-colors"
            >
              <span>GitHub Release v0.1.2</span>
              <span>↗</span>
            </a>

            <a
              href="#pairing-section"
              className="border border-border hover:border-lime text-text hover:text-lime font-bold text-xs px-4 py-2.5 uppercase tracking-wider transition-colors"
            >
              Pair Extension Token ↓
            </a>
          </div>
        </div>
      </div>

      {/* Browser Selector Tabs */}
      <div className="flex flex-col gap-6">
        <div className="flex border-b border-border">
          <button
            type="button"
            onClick={() => setActiveTab("chrome")}
            className={`py-3 px-6 text-xs font-black uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "chrome"
                ? "border-lime text-lime bg-surface-raised"
                : "border-transparent text-text-muted hover:text-text hover:bg-surface"
            }`}
          >
            Google Chrome / Chromium (Brave, Edge, Arc)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("firefox")}
            className={`py-3 px-6 text-xs font-black uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "firefox"
                ? "border-lime text-lime bg-surface-raised"
                : "border-transparent text-text-muted hover:text-text hover:bg-surface"
            }`}
          >
            Mozilla Firefox (Developer & AMO)
          </button>
        </div>

        {/* Tab 1: Chrome / Chromium Guide */}
        {activeTab === "chrome" && (
          <div className="flex flex-col gap-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 01</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Download Extension Zip</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    Download the pre-packaged Manifest V3 archive for Chrome and Chromium-based browsers.
                  </p>
                </div>
                <a
                  href="/downloads/codefort-guard-chrome-v0.1.2.zip"
                  download
                  className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs py-2 px-3 text-center uppercase tracking-wider flex items-center justify-center gap-1"
                >
                  <span>Download Chrome ZIP</span>
                  <span>↓</span>
                </a>
              </div>

              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 02</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Enable Developer Mode</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    Open <span className="text-lime bg-surface-raised px-1 py-0.5">chrome://extensions</span> in your address bar and toggle the <strong>Developer mode</strong> switch in the top-right corner.
                  </p>
                </div>
                <div className="text-[11px] text-text-dim border-t border-border pt-2 font-mono">
                  Brave: brave://extensions <br /> Edge: edge://extensions
                </div>
              </div>

              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 03</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Load Unpacked Folder</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    Extract the downloaded zip archive, click <strong>Load unpacked</strong>, and select the extracted folder.
                  </p>
                </div>
                <div className="text-[11px] text-lime font-bold border-t border-border pt-2">
                  ✓ CodeFort Guard activates instantly
                </div>
              </div>
            </div>

            {/* Chrome Deep-Dive Box */}
            <div className="border border-border bg-bg p-5 flex flex-col gap-3">
              <div className="text-xs font-bold text-text uppercase flex items-center gap-2">
                <span className="text-lime">⚡</span>
                <span>Verification Checklist:</span>
              </div>
              <ul className="text-xs text-text-muted space-y-1.5 list-disc list-inside">
                <li>Pin the <strong>CF_ CodeFort Guard</strong> icon to your browser toolbar for quick access.</li>
                <li>Navigate to any pull request on GitHub (e.g. <a href="https://github.com/codefort-sec/vulnerable-test-repo/pull/1" target="_blank" rel="noreferrer" className="text-lime hover:underline">vulnerable-test-repo#1</a>).</li>
                <li>The inline <strong>🛡 CODEFORT: BLOCKED</strong> badge appears right under the PR title. Click it to inspect the BARQAI risk breakdown!</li>
              </ul>
            </div>
          </div>
        )}

        {/* Tab 2: Firefox Guide */}
        {activeTab === "firefox" && (
          <div className="flex flex-col gap-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 01</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Download Firefox Add-on</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    Download the signed XPI package or zip archive tailored for Mozilla Firefox.
                  </p>
                </div>
                <div className="flex flex-col gap-2">
                  <a
                    href="/downloads/codefort-guard-firefox-v0.1.2.xpi"
                    download
                    className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs py-2 px-3 text-center uppercase tracking-wider flex items-center justify-center gap-1"
                  >
                    <span>Download Firefox XPI</span>
                    <span>↓</span>
                  </a>
                  <a
                    href="/downloads/codefort-guard-firefox-v0.1.2.zip"
                    download
                    className="border border-border hover:border-lime text-text hover:text-lime text-xs py-1.5 px-3 text-center uppercase tracking-wider"
                  >
                    Download Firefox ZIP (.zip)
                  </a>
                </div>
              </div>

              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 02</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Open Debugging Page</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    In Firefox, open a new tab and navigate to <span className="text-lime bg-surface-raised px-1 py-0.5">about:debugging#/runtime/this-firefox</span>.
                  </p>
                </div>
                <div className="text-[11px] text-text-dim border-t border-border pt-2 font-mono">
                  Gecko ID: codefort-guard@codefort.sec
                </div>
              </div>

              <div className="border border-border bg-surface p-5 flex flex-col justify-between">
                <div>
                  <div className="text-lime font-bold text-xs mb-1">STEP 03</div>
                  <div className="text-sm font-bold text-text uppercase mb-2">Load Temporary Add-on</div>
                  <p className="text-xs text-text-muted mb-4 leading-relaxed">
                    Click <strong>Load Temporary Add-on...</strong> and select the downloaded <code className="text-lime">.xpi</code> or <code className="text-lime">manifest.json</code> from the extracted zip.
                  </p>
                </div>
                <div className="text-[11px] text-lime font-bold border-t border-border pt-2">
                  ✓ Activates with full MV3 background worker
                </div>
              </div>
            </div>

            {/* Firefox Store Note */}
            <div className="border border-border bg-bg p-5 flex flex-col gap-2">
              <div className="text-xs font-bold text-text uppercase flex items-center gap-2">
                <span className="text-lime">🦊</span>
                <span>Mozilla Add-on Store (AMO) Notice:</span>
              </div>
              <p className="text-xs text-text-muted leading-relaxed">
                CodeFort Guard uses clean, unminified source code adhering strictly to Mozilla's Add-on Policies. It has been validated against Mozilla's automated review pipeline.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Pairing Section */}
      <section id="pairing-section" className="border border-border bg-surface p-6 md:p-8 flex flex-col gap-6">
        <div>
          <div className="flex items-center gap-2 text-xs text-lime uppercase tracking-widest mb-1">
            <span>// CREDENTIAL PAIRING</span>
          </div>
          <h2 className="text-xl font-black text-text uppercase">
            PAIR EXTENSION WITH YOUR CODEFORT SESSION
          </h2>
          <p className="text-xs text-text-muted leading-relaxed mt-1">
            Pairing grants the extension secure, read-only access to query private scan results and synchronize custom repository policies.
          </p>
        </div>

        <div className="border border-border bg-bg p-5 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex flex-col gap-2 w-full md:w-auto flex-1">
            <span className="text-xs font-bold text-text-dim uppercase">One-Click Pairing Token:</span>
            {pairingToken ? (
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
            ) : (
              <p className="text-xs text-text-muted">
                Click below to generate a single-use token valid for 300 seconds. Or enter <code className="text-lime">demo-pairing-token</code> in the popup for instant testing.
              </p>
            )}
          </div>

          <div className="shrink-0">
            <button
              type="button"
              disabled={generating}
              onClick={handleGenerateToken}
              className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-5 py-3 uppercase tracking-wider transition-colors disabled:opacity-50"
            >
              {generating ? "GENERATING..." : "GENERATE PAIRING TOKEN ↗"}
            </button>
          </div>
        </div>

        {/* Pairing Flow Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="border border-border bg-surface-raised p-4">
            <div className="text-lime font-bold mb-1">1. COPY TOKEN</div>
            <p className="text-text-muted">Generate and copy the single-use token from the box above.</p>
          </div>
          <div className="border border-border bg-surface-raised p-4">
            <div className="text-lime font-bold mb-1">2. OPEN POPUP</div>
            <p className="text-text-muted">Click the CodeFort Guard icon in your browser toolbar.</p>
          </div>
          <div className="border border-border bg-surface-raised p-4">
            <div className="text-lime font-bold mb-1">3. PASTE & CONNECT</div>
            <p className="text-text-muted">Paste the token and click Pair. Status updates to ONLINE.</p>
          </div>
        </div>
      </section>

      {/* Test Scenarios Section */}
      <section className="flex flex-col gap-4">
        <div className="text-xs text-text-dim uppercase tracking-wider flex items-center justify-between">
          <span>Test Extension on Live Scenarios</span>
          <span className="text-lime text-[11px]">Click to open on GitHub ↗</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <a
            href="https://github.com/codefort-sec/vulnerable-test-repo/pull/1"
            target="_blank"
            rel="noreferrer"
            className="border border-border hover:border-danger bg-surface p-4 flex flex-col justify-between group transition-all"
          >
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-[9px] px-1.5 py-0.5 bg-danger/10 border border-danger text-danger font-bold uppercase">
                  BLOCKED
                </span>
                <span className="text-[10px] text-text-dim font-bold">RISK 95</span>
              </div>
              <div className="text-xs font-bold text-text uppercase group-hover:text-danger mb-1">
                PR #1: Dropper Hook
              </div>
              <p className="text-[11px] text-text-muted">
                Inspect curl pipe to bash in package.json preinstall hook.
              </p>
            </div>
            <div className="text-[10px] text-lime mt-3">Open on GitHub ↗</div>
          </a>

          <a
            href="https://github.com/codefort-sec/vulnerable-test-repo/pull/2"
            target="_blank"
            rel="noreferrer"
            className="border border-border hover:border-amber-500 bg-surface p-4 flex flex-col justify-between group transition-all"
          >
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-[9px] px-1.5 py-0.5 bg-amber-500/10 border border-amber-500 text-amber-500 font-bold uppercase">
                  REVIEW
                </span>
                <span className="text-[10px] text-text-dim font-bold">RISK 65</span>
              </div>
              <div className="text-xs font-bold text-text uppercase group-hover:text-amber-500 mb-1">
                PR #2: Typosquatting
              </div>
              <p className="text-[11px] text-text-muted">
                Flags fake package "reqeusts" targeting the official "requests".
              </p>
            </div>
            <div className="text-[10px] text-lime mt-3">Open on GitHub ↗</div>
          </a>

          <a
            href="https://github.com/codefort-sec/vulnerable-test-repo/pull/3"
            target="_blank"
            rel="noreferrer"
            className="border border-border hover:border-danger bg-surface p-4 flex flex-col justify-between group transition-all"
          >
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-[9px] px-1.5 py-0.5 bg-danger/10 border border-danger text-danger font-bold uppercase">
                  BLOCKED
                </span>
                <span className="text-[10px] text-text-dim font-bold">RISK 92</span>
              </div>
              <div className="text-xs font-bold text-text uppercase group-hover:text-danger mb-1">
                PR #3: Workflow Inject
              </div>
              <p className="text-[11px] text-text-muted">
                Catches pull_request_target checkout of untrusted fork.
              </p>
            </div>
            <div className="text-[10px] text-lime mt-3">Open on GitHub ↗</div>
          </a>

          <a
            href="https://github.com/codefort-sec/clean-test-repo/pull/1"
            target="_blank"
            rel="noreferrer"
            className="border border-border hover:border-emerald-500 bg-surface p-4 flex flex-col justify-between group transition-all"
          >
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-[9px] px-1.5 py-0.5 bg-emerald-500/10 border border-emerald-500 text-emerald-500 font-bold uppercase">
                  PASS
                </span>
                <span className="text-[10px] text-text-dim font-bold">RISK 0</span>
              </div>
              <div className="text-xs font-bold text-text uppercase group-hover:text-emerald-500 mb-1">
                PR #1: Clean Baseline
              </div>
              <p className="text-[11px] text-text-muted">
                Clean telemetry utility verifying 0 false positives.
              </p>
            </div>
            <div className="text-[10px] text-lime mt-3">Open on GitHub ↗</div>
          </a>
        </div>
      </section>
    </div>
  );
}
