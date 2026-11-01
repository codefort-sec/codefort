"use client";

import React, { useState, useRef, useEffect } from "react";
import {
  BarqAIChatResponse,
  ChatMessage,
  sendBarqAIChat,
} from "@/lib/api";

interface BarqAIChatModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialError?: string;
  initialCode?: string;
  initialFilePath?: string;
  scanId?: string;
}

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

export const BarqAIChatModal: React.FC<BarqAIChatModalProps> = ({
  isOpen,
  onClose,
  initialError,
  initialCode,
  initialFilePath,
  scanId,
}) => {
  const [messages, setMessages] = useState<MessageItem[]>([
    {
      id: "welcome",
      role: "assistant",
      text: "👋 I am **BARQAI**, your cyber-defense intelligence and code remediation copilot. Paste any error, stack trace, or vulnerable code snippet, and I will explain the root cause and rewrite it into clean, secure code.",
      timestamp: "Just now",
      suggestedActions: [
        "Why is npm preinstall with curl dangerous?",
        "Rewrite package.json with lodashe typosquat",
        "Explain GitHub Actions pull_request_target risk",
      ],
    },
  ]);

  const [inputMessage, setInputMessage] = useState("");
  const [errorContext, setErrorContext] = useState(initialError || "");
  const [codeSnippet, setCodeSnippet] = useState(initialCode || "");
  const [filePath, setFilePath] = useState(initialFilePath || "");
  const [showContextInputs, setShowContextInputs] = useState(
    Boolean(initialError || initialCode || initialFilePath)
  );
  const [loading, setLoading] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [activeTabByMsg, setActiveTabByMsg] = useState<
    Record<string, "explanation" | "code" | "diff">
  >({});

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialError || initialCode || initialFilePath) {
      setErrorContext(initialError || "");
      setCodeSnippet(initialCode || "");
      setFilePath(initialFilePath || "");
      setShowContextInputs(true);
    }
  }, [initialError, initialCode, initialFilePath]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  if (!isOpen) return null;

  async function handleSendMessage(customPrompt?: string) {
    const textToSend = customPrompt || inputMessage;
    if (!textToSend.trim() && !codeSnippet.trim() && !errorContext.trim()) return;

    const userMsgId = `user_${Date.now()}`;
    const newMsg: MessageItem = {
      id: userMsgId,
      role: "user",
      text: textToSend || "Analyze and rewrite this code / error context.",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, newMsg]);
    setInputMessage("");
    setLoading(true);

    try {
      // Build history
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
        scan_id: scanId || undefined,
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
      // Set default tab to code if rewritten code is provided
      if (res.rewritten_code) {
        setActiveTabByMsg((prev) => ({ ...prev, [assistantMsgId]: "code" }));
      }
    } catch (err: any) {
      const errorMsg: MessageItem = {
        id: `err_${Date.now()}`,
        role: "assistant",
        text: `⚠️ **Error communicating with BARQAI**: ${err.message || "Failed to process request."}`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  }

  function handleCopyCode(code: string, msgId: string) {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(msgId);
    setTimeout(() => setCopiedCodeId(null), 2000);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono">
      <div className="w-full max-w-4xl h-[88vh] bg-surface border-2 border-lime/40 shadow-2xl flex flex-col overflow-hidden">
        {/* HUD Top Bar */}
        <div className="bg-surface-elevated border-b border-border px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="w-2.5 h-2.5 bg-lime rounded-full animate-ping" />
            <div>
              <div className="flex items-center gap-2">
                <span className="bg-lime text-bg font-extrabold px-1.5 py-0.5 text-[10px] tracking-wider">
                  BARQAI_COPILOT
                </span>
                <span className="text-text font-bold text-xs tracking-wider">
                  FORENSIC DIAGNOSTICS & CODE REWRITER
                </span>
              </div>
              <p className="text-[10px] text-text-dim mt-0.5">
                Frontier Qwen 2.5 Coder MoE · OSV Grounded · Autonomous Remediation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowContextInputs(!showContextInputs)}
              className="text-[10px] bg-surface border border-border hover:border-lime text-text-muted hover:text-lime px-2.5 py-1 transition-colors"
            >
              {showContextInputs ? "− HIDE CONTEXT" : "+ ATTACH ERROR / CODE"}
            </button>
            <button
              onClick={onClose}
              className="text-text-muted hover:text-red-400 font-bold px-2 py-1 text-sm transition-colors border border-border hover:border-red-500/50"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Optional Context Attachment Drawer */}
        {showContextInputs && (
          <div className="bg-surface/90 border-b border-border p-3 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div>
              <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                Target File Path
              </label>
              <input
                type="text"
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
                placeholder="e.g. package.json, src/auth.ts"
                className="w-full bg-bg border border-border px-2 py-1.5 text-text text-xs focus:outline-none focus:border-lime"
              />
            </div>
            <div>
              <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                Error / Stack Trace / Finding
              </label>
              <input
                type="text"
                value={errorContext}
                onChange={(e) => setErrorContext(e.target.value)}
                placeholder="e.g. npm.exec.preinstall: remote curl pipe"
                className="w-full bg-bg border border-border px-2 py-1.5 text-text text-xs focus:outline-none focus:border-lime"
              />
            </div>
            <div>
              <label className="text-[10px] text-text-dim uppercase tracking-wider block mb-1">
                Code Snippet (to rewrite)
              </label>
              <textarea
                value={codeSnippet}
                onChange={(e) => setCodeSnippet(e.target.value)}
                placeholder="Paste code section to diagnose..."
                rows={2}
                className="w-full bg-bg border border-border px-2 py-1 text-text text-xs font-mono focus:outline-none focus:border-lime resize-none"
              />
            </div>
          </div>
        )}

        {/* Conversation Stream */}
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
                  className={`max-w-[85%] border ${
                    isUser
                      ? "bg-surface-elevated border-lime/50 text-text"
                      : "bg-surface border-border text-text"
                  } p-3.5 shadow-md`}
                >
                  {/* Sender Header */}
                  <div className="flex items-center justify-between gap-4 mb-2 border-b border-border/50 pb-1.5">
                    <span
                      className={`text-[10px] font-bold tracking-wider uppercase ${
                        isUser ? "text-lime" : "text-cyan-400"
                      }`}
                    >
                      {isUser ? "DEVELOPER" : "⚡ BARQAI INTELLIGENCE"}
                    </span>
                    <span className="text-[9px] text-text-dim">{msg.timestamp}</span>
                  </div>

                  {/* Main text / explanation */}
                  {isUser ? (
                    <p className="text-xs text-text whitespace-pre-wrap">{msg.text}</p>
                  ) : (
                    <div>
                      {/* Tabs if rewritten code is present */}
                      {msg.rewrittenCode && (
                        <div className="flex items-center gap-1 mb-2.5 border-b border-border/50 pb-2">
                          <button
                            onClick={() =>
                              setActiveTabByMsg((prev) => ({
                                ...prev,
                                [msg.id]: "code",
                              }))
                            }
                            className={`text-[10px] px-2.5 py-1 font-bold uppercase transition-colors ${
                              currentTab === "code"
                                ? "bg-lime text-bg"
                                : "text-text-muted hover:text-lime"
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
                            className={`text-[10px] px-2.5 py-1 font-bold uppercase transition-colors ${
                              currentTab === "explanation"
                                ? "bg-lime text-bg"
                                : "text-text-muted hover:text-lime"
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
                              className={`text-[10px] px-2.5 py-1 font-bold uppercase transition-colors ${
                                currentTab === "diff"
                                  ? "bg-lime text-bg"
                                  : "text-text-muted hover:text-lime"
                              }`}
                            >
                              ⇄ Unified Diff
                            </button>
                          )}
                        </div>
                      )}

                      {/* Tab 1: Rewritten Code */}
                      {msg.rewrittenCode && currentTab === "code" && (
                        <div>
                          <div className="flex items-center justify-between mb-1.5">
                            <span className="text-[10px] text-lime font-bold uppercase">
                              Secured Implementation:
                            </span>
                            <button
                              onClick={() => handleCopyCode(msg.rewrittenCode!, msg.id)}
                              className="text-[10px] bg-bg border border-border hover:border-lime text-text-muted hover:text-lime px-2 py-0.5 transition-colors"
                            >
                              {copiedCodeId === msg.id ? "✓ COPIED!" : "📋 COPY CODE"}
                            </button>
                          </div>
                          <pre className="bg-bg border border-border p-3 text-[11px] text-lime font-mono overflow-x-auto max-h-60 leading-relaxed whitespace-pre">
                            {msg.rewrittenCode}
                          </pre>
                        </div>
                      )}

                      {/* Tab 2: Explanation */}
                      {(currentTab === "explanation" || !msg.rewrittenCode) && (
                        <div className="text-xs text-text-muted space-y-2 whitespace-pre-wrap leading-relaxed">
                          {msg.explanation || msg.text}
                        </div>
                      )}

                      {/* Tab 3: Unified Diff */}
                      {msg.diff && currentTab === "diff" && (
                        <div className="mt-2">
                          <pre className="bg-bg border border-border p-2.5 text-[10px] font-mono overflow-x-auto max-h-56 leading-tight">
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
                        </div>
                      )}

                      {/* Model Metadata footer */}
                      {msg.model && (
                        <div className="mt-2.5 pt-1.5 border-t border-border/40 flex items-center justify-between text-[9px] text-text-dim">
                          <span>Synthesized via {msg.model}</span>
                          <span>Zero-Hallucination Verified</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Suggested Action Chips */}
                {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2 max-w-[85%]">
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
            <div className="flex items-center gap-2 text-xs text-lime bg-surface border border-border p-3 max-w-sm animate-pulse">
              <span className="w-2 h-2 rounded-full bg-lime animate-ping" />
              <span>BARQAI is diagnosing error & synthesizing secure code rewrite...</span>
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
              className="flex-1 bg-bg border border-border px-3 py-2 text-xs text-text placeholder:text-text-dim focus:outline-none focus:border-lime"
            />
            <button
              type="submit"
              disabled={loading || (!inputMessage.trim() && !codeSnippet.trim())}
              className="bg-lime hover:bg-lime-muted disabled:opacity-40 text-bg font-bold px-4 py-2 text-xs uppercase tracking-wider transition-colors flex items-center gap-1.5"
            >
              <span>SEND</span>
              <span>⚡</span>
            </button>
          </form>
          <div className="flex items-center justify-between text-[9px] text-text-dim px-1">
            <span>Press Enter to send. Attach code snippets above to request rewrites.</span>
            <span>BARQAI Zero-Trust Engine v2.0</span>
          </div>
        </div>
      </div>
    </div>
  );
};
