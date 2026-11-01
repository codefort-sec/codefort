import { NextRequest, NextResponse } from "next/server";
import { synthesizeBarqAIChatResponse, BarqAIChatRequest } from "@/lib/barqai_engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body: BarqAIChatRequest = await req.json();

    // 1. If backend API is reachable at process.env.BACKEND_API_URL or http://localhost:8000, attempt proxy
    const backendUrl = process.env.BACKEND_API_URL || "http://localhost:8000";
    if (backendUrl && !backendUrl.includes("codefort-lilac.vercel.app")) {
      try {
        const proxyRes = await fetch(`${backendUrl}/api/v1/barqai/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(3000),
        });
        if (proxyRes.ok) {
          const data = await proxyRes.json();
          return NextResponse.json(data);
        }
      } catch {
        // Fall through to internal BARQAI synthesis engine
      }
    }

    // 2. If OPENROUTER_API_KEY is available in the environment, attempt Qwen MoE
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    if (openrouterKey) {
      try {
        const prompt = `User prompt: ${body.message}\nError Context: ${body.error_context || "None"}\nCode Snippet: ${body.code_snippet || "None"}`;
        const llmRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${openrouterKey}`,
            "HTTP-Referer": "https://codefort.sec",
            "X-Title": "CodeFort BARQAI",
          },
          body: JSON.stringify({
            model: "qwen/qwen-2.5-coder-32b-instruct",
            messages: [
              {
                role: "system",
                content:
                  "You are BARQAI, the AI cybersecurity intelligence and code remediation copilot of CODEFORT.\n" +
                  "Explain the error/vulnerability root cause and rewrite the code safely.\n" +
                  "Return JSON with: {\"reply\": \"...\", \"explanation\": \"...\", \"rewritten_code\": \"...\"}",
              },
              { role: "user", content: prompt },
            ],
            temperature: 0.1,
          }),
          signal: AbortSignal.timeout(5000),
        });

        if (llmRes.ok) {
          const llmData = await llmRes.json();
          const rawContent = llmData.choices?.[0]?.message?.content || "";
          try {
            const cleanJson = rawContent.replace(/```json|```/g, "").trim();
            const parsed = JSON.parse(cleanJson);
            return NextResponse.json({
              reply: parsed.reply || rawContent,
              explanation: parsed.explanation || "Analyzed by BARQAI Frontier Qwen MoE.",
              rewritten_code: parsed.rewritten_code || body.code_snippet,
              original_code: body.code_snippet || "",
              diff: parsed.diff || undefined,
              model: "Qwen 2.5 Coder 32B Instruct (MoE)",
              suggested_actions: ["Explain root cause in depth", "Show unified git diff"],
            });
          } catch {
            return NextResponse.json({
              reply: rawContent,
              explanation: "Analyzed by BARQAI Frontier Qwen MoE.",
              rewritten_code: body.code_snippet,
              original_code: body.code_snippet || "",
              model: "Qwen 2.5 Coder 32B Instruct (MoE)",
              suggested_actions: ["Explain root cause in depth", "Show unified git diff"],
            });
          }
        }
      } catch {
        // Fall through to deterministic engine
      }
    }

    // 3. Fallback to resilient deterministic BARQAI synthesis (100% Guaranteed 200 OK)
    const result = synthesizeBarqAIChatResponse(body);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: { message: err?.message || "Internal chat error", code: "CHAT_ERROR" } },
      { status: 500 }
    );
  }
}
