import React from "react";
import Link from "next/link";

export const Navbar: React.FC = () => {
  return (
    <header className="w-full border-b border-border bg-surface sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 h-12 flex items-center justify-between font-mono">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-2 group">
          <span className="bg-lime text-bg font-extrabold px-1.5 py-0.5 text-xs tracking-wider">
            CF_
          </span>
          <span className="font-bold text-sm tracking-widest text-text group-hover:text-lime transition-colors">
            CODEFORT
          </span>
        </Link>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-6 text-xs text-text-muted">
          <Link href="/dashboard" className="hover:text-lime transition-colors">
            /01 DASHBOARD
          </Link>
          <span className="text-text-dim">+</span>
          <Link href="/scans/scan_pr_1" className="hover:text-lime transition-colors">
            /02 SCAN FORENSICS
          </Link>
          <span className="text-text-dim">+</span>
          <Link href="/settings" className="hover:text-lime transition-colors">
            /03 EXTENSION PAIR
          </Link>
        </nav>

        {/* Right HUD info & CTA */}
        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2 text-[10px] text-text-dim">
            <span className="w-2 h-2 rounded-full bg-lime animate-pulse" />
            <span>SYS_ONLINE: 8000</span>
          </div>

          <Link
            href="/settings"
            className="bg-lime hover:bg-lime-muted text-bg font-bold text-xs px-3 py-1.5 transition-colors uppercase tracking-wider flex items-center gap-1"
          >
            <span>PAIR EXTENSION</span>
            <span>↗</span>
          </Link>
        </div>
      </div>
    </header>
  );
};
