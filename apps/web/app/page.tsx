import Link from "next/link";

export default function HomePage() {
  return (
    <div className="max-w-7xl mx-auto px-4 py-8 font-mono flex flex-col gap-12">
      {/* 6.2 HERO / INTRO (/01) */}
      <section className="border border-border bg-surface p-6 md:p-10 relative">
        {/* Corner marks */}
        <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-lime" />
        <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-lime" />
        <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-lime" />
        <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-lime" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Left Column (Text & CTAs) */}
          <div className="lg:col-span-7 flex flex-col gap-4">
            <div className="flex items-center gap-2 text-xs text-lime tracking-widest uppercase">
              <span>/01</span>
              <span>•</span>
              <span>SUPPLY CHAIN DEFENSE // SYS_01</span>
            </div>

            <h1 className="text-3xl md:text-5xl font-black tracking-tight text-text uppercase leading-none">
              MALICIOUS PR <br />
              <span className="text-lime">DETECTOR</span>
            </h1>

            <p className="text-sm font-bold text-lime-muted tracking-wider uppercase">
              THE FUTURE ISN'T MINIMAL. IT'S SYSTEMATIC.
            </p>

            <p className="text-xs md:text-sm text-text-muted max-w-xl leading-relaxed">
              Detects malicious lifecycle scripts, typosquatted dependencies, and unsafe GitHub Actions workflows before pull requests merge. Powered by the BARQAI explanation engine with traceable evidence.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-4">
              <Link
                href="/dashboard"
                className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs px-5 py-3 tracking-wider uppercase transition-colors flex items-center gap-2"
              >
                <span>OPEN DASHBOARD</span>
                <span>↗</span>
              </Link>

              <Link
                href="/settings"
                className="border border-border hover:border-lime text-text hover:text-lime font-bold text-xs px-5 py-3 tracking-wider uppercase transition-colors"
              >
                PAIR BROWSER GUARD
              </Link>
            </div>
          </div>

          {/* Right Column (Technical HUD Display) */}
          <div className="lg:col-span-5 border border-border bg-bg p-5 flex flex-col gap-4 relative">
            <div className="flex justify-between items-center text-[10px] text-text-dim border-b border-border pb-2">
              <span>TARGET: GITHUB_PR_PIPELINE</span>
              <span className="text-lime">STATUS: ACTIVE</span>
            </div>

            {/* Risk HUD Meter */}
            <div className="bg-surface p-4 border border-border">
              <div className="flex justify-between items-baseline mb-2">
                <span className="text-xs font-bold text-text-muted uppercase">LATEST INCIDENT RISK</span>
                <span className="text-2xl font-black text-lime">67 / 100</span>
              </div>
              <div className="w-full bg-bg h-2 border border-border overflow-hidden">
                <div className="bg-lime h-full" style={{ width: "67%" }} />
              </div>
              <div className="flex justify-between text-[10px] text-text-dim mt-2">
                <span>VERDICT: REVIEW_REQUIRED</span>
                <span>CONFIDENCE: 95%</span>
              </div>
            </div>

            {/* Engine Readiness List */}
            <div className="flex flex-col gap-2 text-xs">
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">STATIC ANALYZER (SEMGREP)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">DEPENDENCY INTEL (OSV)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-border/50 text-[11px]">
                <span className="text-text-muted">WORKFLOW LINTER (GH ACTIONS)</span>
                <span className="text-lime font-bold">READY</span>
              </div>
              <div className="flex justify-between items-center py-1 text-[11px]">
                <span className="text-text-muted">BARQAI EXPLANATION ENGINE</span>
                <span className="text-lime font-bold">ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 6.3 CORE PRINCIPLES (/02) */}
      <section className="flex flex-col gap-4">
        <div className="flex items-center gap-2 text-xs text-text-dim tracking-widest uppercase">
          <span>/02</span>
          <span>•</span>
          <span>SYSTEM SECURITY PRINCIPLES</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="border border-border bg-surface p-4">
            <div className="text-lime font-bold text-xs mb-1">01. TRACEABLE</div>
            <div className="text-xs font-bold text-text uppercase mb-2">EVIDENCE OVER SPECULATION</div>
            <p className="text-[11px] text-text-muted">Every finding is anchored to file paths, AST checks, or CVE lookups.</p>
          </div>

          <div className="border border-border bg-surface p-4">
            <div className="text-lime font-bold text-xs mb-1">02. FAIL-SAFE</div>
            <div className="text-xs font-bold text-text uppercase mb-2">NEVER SILENT PASS</div>
            <p className="text-[11px] text-text-muted">Failed checks result in REVIEW_REQUIRED or SCAN_ERROR, never silent approvals.</p>
          </div>

          <div className="border border-border bg-surface p-4">
            <div className="text-lime font-bold text-xs mb-1">03. IN-FLOW</div>
            <div className="text-xs font-bold text-text uppercase mb-2">INJECTED ON GITHUB</div>
            <p className="text-[11px] text-text-muted">CodeFort Guard injects verdicts and inline line warnings directly on GitHub PRs.</p>
          </div>

          <div className="border border-border bg-surface p-4">
            <div className="text-lime font-bold text-xs mb-1">04. ISOLATED</div>
            <div className="text-xs font-bold text-text uppercase mb-2">HOSTILE CODE ISOLATION</div>
            <p className="text-[11px] text-text-muted">Untrusted repository scripts are never executed on trusted API servers.</p>
          </div>

          <div className="border border-border bg-surface p-4">
            <div className="text-lime font-bold text-xs mb-1">05. ACTIONABLE</div>
            <div className="text-xs font-bold text-text uppercase mb-2">EXPLAINABLE PATCHES</div>
            <p className="text-[11px] text-text-muted">BARQAI provides plain-language impact summaries and remediations.</p>
          </div>
        </div>
      </section>

      {/* 6.5 LOWER PANELS (/04 - /06) */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="border border-border bg-surface p-5 flex flex-col justify-between">
          <div>
            <div className="text-[10px] text-lime mb-2">/04 REPOSITORY INTEGRATION</div>
            <div className="text-sm font-bold text-text uppercase mb-2">Connect GitHub Repos</div>
            <p className="text-xs text-text-muted mb-4">
              Authorize CodeFort App to listen for PR opened, reopened, and synchronize events.
            </p>
          </div>
          <Link
            href="/dashboard"
            className="bg-surface-raised border border-border hover:border-lime text-lime font-bold text-xs py-2 px-3 text-center uppercase tracking-wider"
          >
            VIEW REPOSITORIES ↗
          </Link>
        </div>

        <div className="border border-border bg-surface p-5 flex flex-col justify-between">
          <div>
            <div className="text-[10px] text-lime mb-2">/05 CHROME GUARD EXTENSION</div>
            <div className="text-sm font-bold text-text uppercase mb-2">Browser Copilot</div>
            <p className="text-xs text-text-muted mb-4">
              Pair your Chrome extension to inspect verdicts and flagged diff lines directly within GitHub.
            </p>
          </div>
          <Link
            href="/settings"
            className="bg-lime hover:bg-lime-muted text-bg font-extrabold text-xs py-2 px-3 text-center uppercase tracking-wider"
          >
            PAIR EXTENSION ↗
          </Link>
        </div>

        <div className="border border-border bg-surface p-5 flex flex-col justify-between">
          <div>
            <div className="text-[10px] text-lime mb-2">/06 LIVE SCAN FORENSICS</div>
            <div className="text-sm font-bold text-text uppercase mb-2">Inspect Malicious PR #1</div>
            <p className="text-xs text-text-muted mb-4">
              Review suspicious shell script execution, typosquatted dependencies, and BARQAI analysis.
            </p>
          </div>
          <Link
            href="/scans/scan_pr_1"
            className="bg-surface-raised border border-border hover:border-lime text-text hover:text-lime font-bold text-xs py-2 px-3 text-center uppercase tracking-wider"
          >
            OPEN FORENSIC VIEW ↗
          </Link>
        </div>
      </section>
    </div>
  );
}
