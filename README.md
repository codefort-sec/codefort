# CODEFORT // ZERO-TRUST PR & SUPPLY CHAIN DEFENSE

[![CodeFort CI](https://github.com/codefort-sec/codefort/actions/workflows/ci.yml/badge.svg)](https://github.com/codefort-sec/codefort/actions/workflows/ci.yml)
[![Web Dashboard](https://img.shields.io/badge/Web_Dashboard-Vercel_Live-00ff66?style=flat-square&logo=vercel)](https://codefort-web.vercel.app)
[![API Engine](https://img.shields.io/badge/FastAPI_Engine-Vercel_Live-00e5ff?style=flat-square&logo=fastapi)](https://codefort-lilac.vercel.app/docs)
[![Extension Release](https://img.shields.io/badge/Chrome_Extension-v0.1.1-ff0055?style=flat-square&logo=googlechrome)](https://github.com/codefort-sec/codefort/releases/tag/v0.1.1)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

> **Next-generation AI security platform that intercepts malicious pull requests, detects software supply chain poisoning, and prevents CI/CD workflow injection attacks before code merges into production.**

---

## ⚡ Live Deployments & Assets

| Component | Target URL / Asset | Description |
| :--- | :--- | :--- |
| **Web Dashboard** | [`https://codefort-web.vercel.app`](https://codefort-web.vercel.app) | Cyber Brutalist UI for PR forensics, policy toggles, & audits |
| **Backend API** | [`https://codefort-lilac.vercel.app`](https://codefort-lilac.vercel.app) | FastAPI core, multi-engine detection, & BARQAI explainability |
| **API Documentation** | [`https://codefort-lilac.vercel.app/docs`](https://codefort-lilac.vercel.app/docs) | Interactive Swagger UI with all schemas & OpenAPI 3.0 spec |
| **Chrome Extension** | [`v0.1.1 Release Asset (.zip)`](https://github.com/codefort-sec/codefort/releases/tag/v0.1.1) | CodeFort Guard MV3 extension with inline PR badges & diff warnings |
| **Malicious Test Repo** | [`codefort-sec/vulnerable-test-repo`](https://github.com/codefort-sec/vulnerable-test-repo) | Live playground with active attack PRs for judge demonstration |
| **Clean Baseline Repo** | [`codefort-sec/clean-test-repo`](https://github.com/codefort-sec/clean-test-repo) | Compliant baseline repository demonstrating verified PASS PRs |
| **GitHub Organization** | [`https://github.com/codefort-sec`](https://github.com/codefort-sec) | Organization holding platform monorepo and demo repositories |

---

## 🛡️ The Problem: Supply Chain & PR Compromise

Modern software engineering trusts external contributions too early:
1. **Malicious Lifecycle Scripts**: Attackers submit benign-looking PRs containing hidden `preinstall` or `postinstall` scripts that curl and pipe remote bash droppers during CI `npm install`.
2. **Typosquatting & Dependency Hijacking**: Subtle name mutations (`reqeusts`, `crypt0-js`, `cross-env-x`) inject trojaned packages into dependencies.
3. **Privilege Escalation via Workflows**: Insecure `pull_request_target` triggers combined with untrusted fork checkouts give malicious contributors full write tokens to repository secrets.

**CodeFort solves this by shifting zero-trust security directly into the code review lifecycle.**

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph GitHub["GitHub Platform"]
        PR["Pull Request Created / Synced"]
        DOM["PR Page & Diff Viewer"]
    end

    subgraph Chrome["Chrome Extension (CodeFort Guard)"]
        SW["Service Worker (15s Cache)"]
        CS["Content Script Observer"]
        Badge["Cyber Brutalist Inline Badge"]
        LineWarn["Diff Line-Level Warnings"]
        Popup["Auth & Token Pairing Popup"]
    end

    subgraph Cloud["CodeFort Backend (FastAPI on Vercel)"]
        Router["API Gateway / v1"]
        Orch["Scan Orchestrator"]
        SE1["Engine 1: Static Analyzer"]
        SE2["Engine 2: Dependency Intel (OSV + Levenshtein)"]
        SE3["Engine 3: Workflow Linter (AST & Actions Rules)"]
        Pol["Deterministic Policy Evaluator"]
        BARQ["BARQAI Explainability Layer"]
    end

    subgraph Web["Web Dashboard (Next.js 14)"]
        Dash["/dashboard — Multi-Repo PR Scans"]
        Foren["/scans/[id] — Forensics & Remediation"]
        Sett["/settings — Extension Pairing Tokens"]
    end

    PR -->|Webhook / On-Demand| Router
    DOM -->|Injected by| CS
    CS <-->|Cached Status| SW
    SW <-->|Secure API Query| Router
    CS --> Badge
    CS --> LineWarn

    Router --> Orch
    Orch --> SE1 & SE2 & SE3
    SE1 & SE2 & SE3 --> Pol
    Pol --> BARQ
    BARQ --> Dash & Foren

    Web <-->|Single-Use Token Pairing| Popup
```

---

## 🔍 Core Detection Engines

1. **Static Shell & Dropper Analyzer (`StaticAnalyzer`)**:
   - Detects remote execution pipes (`curl -sL ... | bash`, `wget | sh`).
   - Flags obfuscated payloads (`base64 -d`, `eval(Buffer.from)`, hex sequences).
   - Identifies reverse shell hooks (`/dev/tcp/`, netcat spawns, subprocess sockets).

2. **Dependency Intelligence & Typosquat Detector (`DependencyIntelligence`)**:
   - Evaluates dependency names using Levenshtein distance metrics against top-tier packages.
   - Integrates with OSV (Open Source Vulnerabilities) feeds for CVE lookups.
   - Computes package risk scores based on registry age, author reputation, and typosquat heuristics.

3. **CI/CD Workflow Linter (`WorkflowLinter`)**:
   - Catches privilege escalation patterns in GitHub Actions (`pull_request_target` with explicit checkout of fork ref).
   - Flags dangerous permission scopes (`permissions: write-all`).
   - Detects untrusted script injection vulnerabilities (e.g., inline `${{ github.event.pull_request.title }}`).

4. **BARQAI Explainability & Remediation Engine**:
   - Generates structured, deterministic explanations:
     - **What Changed**: Concise file and code modification summary.
     - **Evidence Observed**: Concrete indicators, line numbers, and rule matches.
     - **Why It Matters**: Concrete impact analysis (e.g. runner compromise, secret exfiltration).
     - **Recommended Actions**: Clear remediation steps and diff preview modal.

---

## 🚀 Quick Start: Running & Testing

### 1. Test the Live Dashboard
Navigate directly to **[`https://codefort-web.vercel.app/dashboard`](https://codefort-web.vercel.app/dashboard)**:
- Click on **`codefort-sec/codefort`** to inspect the live scenario PR scans.
- Click **`FORENSICS ↗`** on any PR to view the BARQAI incident explanation, coverage checklist, and remediation diff modal.

### 2. Install the Chrome Extension
1. Download **[`codefort-guard-v0.1.1.zip`](https://github.com/codefort-sec/codefort/releases/tag/v0.1.1)** from GitHub Releases.
2. Unzip the file to extract the `dist` folder.
3. In Chrome, open `chrome://extensions/` and toggle **Developer mode** on (top-right).
4. Click **Load unpacked** and select the unzipped `dist` folder.
5. Click the CodeFort Guard icon in the browser toolbar — it comes pre-connected to the cloud API (`https://codefort-lilac.vercel.app`).
6. Browse any pull request on `https://github.com/codefort-sec/codefort/pull/1` or `https://github.com/owner/repo/pull/42` to see the badge and inline warnings inject into the page!

### 3. Running Locally

```bash
# Clone the repository
git clone https://github.com/codefort-sec/codefort.git
cd codefort

# Run Backend API
cd services/api
uv sync
uv run uvicorn app.main:app --reload --port 8000

# Run Web Dashboard
cd ../../apps/web
npm install
npm run dev

# Build Chrome Extension
cd ../extension
npm install
npm run build
```

---

## 🧪 Verified Attack Scenarios

| Scenario ID | Live PR Link | Attack Vector | Detection Rule | Verdict | Risk Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`01_malicious_preinstall`** | [`vulnerable-test-repo#1`](https://github.com/codefort-sec/vulnerable-test-repo/pull/1) | `curl \| bash` dropper in `package.json` preinstall | `npm.exec.preinstall` | **`BLOCKED`** | 95 / 100 |
| **`02_typosquat_dependency`** | [`vulnerable-test-repo#2`](https://github.com/codefort-sec/vulnerable-test-repo/pull/2) | Typosquatted package `reqeusts` (edit distance 1) | `dep.typosquat` | **`REVIEW_REQUIRED`** | 65 / 100 |
| **`03_unsafe_workflow_injection`** | [`vulnerable-test-repo#3`](https://github.com/codefort-sec/vulnerable-test-repo/pull/3) | `pull_request_target` + write-all + `${{ github.event... }}` | `workflow.target.checkout` | **`BLOCKED`** | 92 / 100 |
| **`04_clean_feature_pr`** | [`clean-test-repo#1`](https://github.com/codefort-sec/clean-test-repo/pull/1) | Standard zero-trust telemetry contribution | *N/A (clean baseline)* | **`PASS`** | 0 / 100 |

---

## 📂 Monorepo Structure

```
codefort/
├── apps/
│   ├── web/                     # Next.js 14 Cyber Brutalist Dashboard
│   └── extension/               # Chrome MV3 Extension (Vite + React)
├── services/
│   └── api/                     # FastAPI Detection Engine & Scan Orchestrator
├── packages/
│   └── types/                   # Shared TypeScript contracts & schemas
├── fixtures/
│   └── scenarios/               # Attack scenarios for testing & grading
└── docs/                        # Complete PRD, TRD, Architecture, and Database specs
```

---

## 👥 Contributors & Hackathon Team
- **CodeFort Security** ([@codefort-sec](https://github.com/codefort-sec))
- Built for next-generation developer tooling & zero-trust supply chain security.
