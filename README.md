# CodeFort

> Malicious Pull Request & Repository Security Platform

CodeFort detects suspicious code patterns, vulnerable/typosquatted dependencies, and risky GitHub Actions workflows before pull requests merge. It combines:
- **FastAPI Backend (`services/api`)**: Orchestrates static analysis, dependency checks, workflow linting, policy evaluation, and BARQAI explanation generation.
- **CodeFort Guard Chrome Extension (`apps/extension`)**: Manifest V3 extension providing in-page GitHub PR badges, line-level security warnings, and side-panel summaries.
- **Web Dashboard (`apps/web`)**: Next.js dashboard for repository security management, scan forensics, and incident audits.
- **Shared Contracts (`packages/types`)**: Typed TypeScript contracts shared across frontend and extension.

---

## Documentation Pack
- [docs/communicate.PRD.md](file:///home/nichroot/codefort/docs/communicate.PRD.md) — Product requirements, user journey, goals, and acceptance criteria.
- [docs/architecture.md](file:///home/nichroot/codefort/docs/architecture.md) — System architecture, scan lifecycle, and technology choices.
- [docs/agents.md](file:///home/nichroot/codefort/docs/agents.md) — Component responsibilities, worker pipeline contracts, and failure handling.
- [docs/api.md](file:///home/nichroot/codefort/docs/api.md) — REST API conventions, routes, payload schemas, and error shapes.
- [docs/connect.TRD.md](file:///home/nichroot/codefort/docs/connect.TRD.md) — Integration requirements (GitHub, Extension, Engines, DB, LLM).
- [docs/database.md](file:///home/nichroot/codefort/docs/database.md) — PostgreSQL schema, tables, relationships, and integrity rules.
- [docs/security.md](file:///home/nichroot/codefort/docs/security.md) — Security policy, HMAC verification, credential handling, and isolation.
- [docs/appflow.md](file:///home/nichroot/codefort/docs/appflow.md) — Application flows (sign-in, repo connect, PR scan, extension overlay).
- [docs/implementationplan.md](file:///home/nichroot/codefort/docs/implementationplan.md) — Phased delivery plan.

---

## Monorepo Layout
```
codefort/
├── apps/
│   ├── web/          # Next.js App Router Web Dashboard
│   └── extension/    # Chrome MV3 Extension (Vite + React)
├── services/
│   └── api/          # FastAPI Backend & Orchestration Service
├── packages/
│   └── types/        # Shared TypeScript interfaces & types
└── docs/             # Technical specifications & documentation
```
