import "./globals.css";
import type { Metadata } from "next";
import { Navbar } from "@/components/Navbar";

export const metadata: Metadata = {
  title: "CodeFort // Malicious PR & Supply Chain Defense",
  description: "Real-time AI-driven malicious PR detector, dependency risk checker, and workflow security copilot.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-bg text-text tech-grid-bg">
        <Navbar />
        <main className="flex-1 flex flex-col">{children}</main>
        
        {/* Footer with Hazard Stripe from design.md */}
        <footer className="border-t border-border bg-surface mt-auto">
          <div className="hazard-stripe" />
          <div className="max-w-7xl mx-auto px-4 py-8 flex flex-col md:flex-row items-center justify-between text-xs text-text-dim font-mono gap-4">
            <div className="flex items-center gap-3">
              <span className="text-lime font-bold">CODEFORT_SYS // 2026</span>
              <span>•</span>
              <span>BARQAI EXPLANATION ENGINE ENABLED</span>
            </div>
            <div className="flex items-center gap-4">
              <span>STATUS: ALL ENGINES OPERATIONAL</span>
              <span>•</span>
              <span className="text-lime">&gt; ACCESS GRANTED_</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
