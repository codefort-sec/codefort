import ReactDOM from "react-dom/client";
import { BadgeOverlay } from "./BadgeOverlay";
import {
  ExtensionLineFinding,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionRemediationResponse,
  ExtensionResponse,
  ExtensionSummaryResponse,
} from "../shared/types";
import "./content.css";

const BADGE_ROOT_ID = "codefort-guard-badge-root";

// Parse GitHub PR URL: https://github.com/:owner/:repo/pull/:number[/...]
function parsePRUrl(url: string): { repo: string; pr: number } | null {
  const match = url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!match) return null;
  return {
    repo: `${match[1]}/${match[2]}`,
    pr: parseInt(match[3], 10),
  };
}

// Find optimal insertion target in GitHub PR header (prefer right next to PR State badge)
function findTargetHeader(): { parent: Element; insertBefore?: Element | null } | null {
  const stateBadge =
    document.querySelector(".gh-header-meta .State") ||
    document.querySelector(".gh-header-meta [class*=\"State\"]") ||
    document.querySelector("[data-testid=\"issue-state-badge\"]") ||
    document.querySelector(".State");

  if (stateBadge && stateBadge.parentElement) {
    return {
      parent: stateBadge.parentElement,
      insertBefore: stateBadge.nextElementSibling,
    };
  }

  const meta =
    document.querySelector(".gh-header-meta") ||
    document.querySelector("[data-testid=\"issue-metadata\"]") ||
    document.querySelector("[data-testid=\"header-metadata\"]") ||
    document.querySelector(".gh-header-title") ||
    document.querySelector("#partial-discussion-header") ||
    document.querySelector(".gh-header-actions") ||
    document.querySelector("div[class*=\"pr-header\"]") ||
    document.querySelector("[data-testid=\"pull-request-header\"]") ||
    document.querySelector("#discussion_bucket") ||
    document.querySelector(".timeline-comment-header");

  if (meta) {
    return { parent: meta, insertBefore: null };
  }

  return null;
}

let activeBadgeRoot: ReactDOM.Root | null = null;
let injectionRetryTimer: ReturnType<typeof setTimeout> | null = null;
let cachedFindings: ExtensionLineFinding[] = [];
let diffObserver: MutationObserver | null = null;
let diffDebounceTimer: ReturnType<typeof setTimeout> | null = null;
let currentObservingPR: string | null = null;

async function injectPRBadge(repo: string, pr: number, retryCount = 0, force = false) {
  if (injectionRetryTimer) {
    clearTimeout(injectionRetryTimer);
    injectionRetryTimer = null;
  }

  // 1. Remove existing badge if present
  const existing = document.getElementById(BADGE_ROOT_ID);
  if (existing) {
    if (activeBadgeRoot) {
      activeBadgeRoot.unmount();
      activeBadgeRoot = null;
    }
    existing.remove();
  }

  // 2. Find target GitHub insertion point with retry for dynamic hydration
  const target = findTargetHeader();

  if (!target || !target.parent) {
    if (retryCount < 24) {
      injectionRetryTimer = setTimeout(() => injectPRBadge(repo, pr, retryCount + 1, force), 250);
      return;
    }
    console.warn("CodeFort Guard: Header anchor not found after retries, mounting fallback to body");
  }

  // 3. Create host container
  const container = document.createElement("span");
  container.id = BADGE_ROOT_ID;

  const parent = target?.parent || document.body;
  if (target?.insertBefore) {
    parent.insertBefore(container, target.insertBefore);
  } else {
    parent.appendChild(container);
  }

  activeBadgeRoot = ReactDOM.createRoot(container);

  const handleRetry = () => {
    injectPRBadge(repo, pr, 0, true);
  };

  // Render initial loading state
  activeBadgeRoot.render(
    <BadgeOverlay status={null} summary={null} loading={true} />
  );

  // 4. Fetch status FIRST (fast, <500ms) without waiting for slow LLM summaries
  try {
    const statusMsg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr, force };
    const statusRes = await chrome.runtime.sendMessage<
      ExtensionMessage,
      ExtensionResponse<ExtensionPRStatusResponse>
    >(statusMsg);

    if (!statusRes?.success) {
      const errorMsg = (statusRes as any)?.error?.message || "Failed to fetch scan status";
      activeBadgeRoot.render(
        <BadgeOverlay
          status={null}
          summary={null}
          loading={false}
          error={errorMsg}
          onRetry={handleRetry}
        />
      );
      return;
    }

    const currentStatus = statusRes.data;

    // Immediately render the badge and trigger the floating screen alert banner!
    activeBadgeRoot.render(
      <BadgeOverlay
        status={currentStatus}
        summary={null}
        loading={false}
        onRetry={handleRetry}
      />
    );

    // 5. Fetch line findings and set up dynamic diff observer
    loadAndApplyFindings(repo, pr, force);
    ensureDiffObserver(repo, pr);

    // 6. Asynchronously fetch rich AI summary in background without blocking UI
    const summaryMsg: ExtensionMessage = { type: "GET_PR_SUMMARY", repo, pr, force };
    chrome.runtime
      .sendMessage<ExtensionMessage, ExtensionResponse<ExtensionSummaryResponse>>(summaryMsg)
      .then((summaryRes) => {
        if (summaryRes?.success && summaryRes.data && activeBadgeRoot) {
          activeBadgeRoot.render(
            <BadgeOverlay
              status={currentStatus}
              summary={summaryRes.data}
              loading={false}
              onRetry={handleRetry}
            />
          );
        }
      })
      .catch((summaryErr) => {
        console.warn("Background summary fetch note:", summaryErr);
      });
  } catch (err: any) {
    activeBadgeRoot.render(
      <BadgeOverlay
        status={null}
        summary={null}
        loading={false}
        error={err.message || "Failed to communicate with CodeFort"}
        onRetry={handleRetry}
      />
    );
  }
}

async function loadAndApplyFindings(repo: string, pr: number, force = false) {
  try {
    const findingsMsg: ExtensionMessage = { type: "GET_PR_FINDINGS", repo, pr, force };
    const findingsRes = await chrome.runtime.sendMessage<
      ExtensionMessage,
      ExtensionResponse<{ findings: ExtensionLineFinding[] }>
    >(findingsMsg);

    if (findingsRes?.success && findingsRes.data?.findings) {
      cachedFindings = findingsRes.data.findings;
      applyLineWarnings(cachedFindings, repo, pr);
    }
  } catch {
    // Non-blocking for diff line warnings
  }
}

function applyLineWarnings(findings: ExtensionLineFinding[], repo: string, pr: number) {
  if (!findings || findings.length === 0) return;

  findings.forEach((finding) => {
    // Normalize file path for selector matching
    const cleanPath = finding.file_path.replace(/^[./]+/, "");
    const baseName = cleanPath.split("/").pop() || cleanPath;

    // Find file boxes across classic and modern GitHub diff views
    const fileBoxes = document.querySelectorAll(
      `div[data-path*="${cleanPath}"], div[data-tagsearch-path*="${cleanPath}"], div[data-file-path*="${cleanPath}"], .file[data-path*="${cleanPath}"], div[data-path*="${baseName}"]`
    );

    fileBoxes.forEach((fileBox) => {
      // Avoid duplicate injection for the same finding in this file container
      if (fileBox.querySelector(`[data-codefort-finding="${finding.id}"]`)) {
        return;
      }

      let targetRow: Element | null = null;

      if (finding.line_start) {
        // Find line cell: td[data-line-number="12"], tr[data-line-number="12"], or [data-line-number]
        const lineCell = fileBox.querySelector(
          `td[data-line-number="${finding.line_start}"], [data-line-number="${finding.line_start}"]`
        );
        if (lineCell) {
          targetRow = lineCell.closest("tr") || lineCell.closest(".diff-table tr") || lineCell.closest("div[class*=\"diff-line\"]");
        }
      }

      // If specific line cell not found (e.g. file-level finding or diff chunk collapsed),
      // attach to the first line row of the diff table or under file header
      if (!targetRow) {
        targetRow = fileBox.querySelector("table.diff-table tr, .js-file-content tr, .file-body tr");
      }

      if (targetRow) {
        const warningRow = document.createElement("tr");
        warningRow.className = "codefort-diff-warning-row";
        warningRow.setAttribute("data-codefort-finding", finding.id);

        const cell = document.createElement("td");
        cell.colSpan = 20;

        const box = document.createElement("div");
        box.className = "codefort-diff-warning-box";

        const tag = document.createElement("span");
        const sevClass = finding.severity.toLowerCase();
        tag.className = `codefort-diff-warning-tag codefort-tag-${sevClass}`;
        tag.textContent = finding.severity;
        box.appendChild(tag);

        const contentDiv = document.createElement("div");
        contentDiv.className = "codefort-diff-warning-content";

        const titleDiv = document.createElement("div");
        titleDiv.className = "codefort-diff-warning-title";
        titleDiv.textContent = `🛡 ${finding.title} (${finding.rule_id})`;
        contentDiv.appendChild(titleDiv);

        if (finding.recommendation) {
          const recomDiv = document.createElement("div");
          recomDiv.className = "codefort-diff-warning-recom";
          recomDiv.textContent = finding.recommendation;
          contentDiv.appendChild(recomDiv);
        }

        box.appendChild(contentDiv);

        // Phase 4: Interactive 1-Click Fix with BARQAI button
        const fixBtn = document.createElement("button");
        fixBtn.type = "button";
        fixBtn.className = "codefort-diff-fix-btn";
        fixBtn.textContent = "⚡ Fix with BARQAI";

        fixBtn.onclick = async (e) => {
          e.preventDefault();
          e.stopPropagation();

          const existingDrawer = box.querySelector(".codefort-inline-remediation-drawer");
          if (existingDrawer) {
            existingDrawer.remove();
            fixBtn.textContent = "⚡ Fix with BARQAI";
            return;
          }

          fixBtn.textContent = "Synthesizing Fix...";
          try {
            const remRes = await chrome.runtime.sendMessage<
              ExtensionMessage,
              ExtensionResponse<ExtensionRemediationResponse>
            >({ type: "GET_PR_REMEDIATION", repo, pr });

            if (!remRes.success || !remRes.data) {
              fixBtn.textContent = "No Fix Available";
              return;
            }

            const data = remRes.data;
            const proposal =
              data.proposals?.find(
                (p) => p.finding_id === finding.id || p.rule_id === finding.rule_id
              ) || data.proposals?.[0];

            if (!proposal) {
              fixBtn.textContent = "No Patch Found";
              return;
            }

            fixBtn.textContent = "Hide Fix";

            const drawer = document.createElement("div");
            drawer.className = "codefort-inline-remediation-drawer";

            const header = document.createElement("div");
            header.className = "codefort-drawer-header";
            header.innerHTML = `
              <span style="font-weight:700;color:#d7ff35;font-size:10px;">BARQAI VERIFIED FIX (${proposal.rule_id})</span>
              <span class="codefort-verified-pill">${proposal.verification_status || "verified"}</span>
            `;
            drawer.appendChild(header);

            const grid = document.createElement("div");
            grid.className = "codefort-drawer-code-grid";

            const beforeBox = document.createElement("div");
            beforeBox.className = "codefort-code-before";
            beforeBox.textContent = `// Original Vulnerable\n${proposal.original_code}`;
            grid.appendChild(beforeBox);

            const afterBox = document.createElement("div");
            afterBox.className = "codefort-code-after";
            afterBox.textContent = `// BARQAI Verified Fix\n${proposal.suggested_code}`;
            grid.appendChild(afterBox);

            drawer.appendChild(grid);

            const actions = document.createElement("div");
            actions.className = "codefort-drawer-actions";

            const copyBtn = document.createElement("button");
            copyBtn.type = "button";
            copyBtn.className = "codefort-copy-fix-btn";
            copyBtn.textContent = "Copy Patch";
            copyBtn.onclick = () => {
              navigator.clipboard.writeText(proposal.unified_diff || data.clean_patch || "");
              copyBtn.textContent = "Copied!";
              setTimeout(() => {
                copyBtn.textContent = "Copy Patch";
              }, 2000);
            };
            actions.appendChild(copyBtn);

            const applyBtn = document.createElement("button");
            applyBtn.type = "button";
            applyBtn.className = "codefort-apply-fix-btn";
            applyBtn.textContent = "Apply Fix to PR Branch ↗";
            applyBtn.onclick = async () => {
              applyBtn.disabled = true;
              applyBtn.textContent = "Applying...";
              try {
                const applyRes = await chrome.runtime.sendMessage<
                  ExtensionMessage,
                  ExtensionResponse<{ status: string; message: string }>
                >({ type: "APPLY_PR_REMEDIATION", repo, pr });

                if (applyRes.success) {
                  applyBtn.textContent = "✓ Fix Applied to Branch!";
                  applyBtn.style.background = "#3fb950";
                  applyBtn.style.color = "#070807";
                } else {
                  applyBtn.textContent = "Failed to Apply";
                  applyBtn.disabled = false;
                }
              } catch {
                applyBtn.textContent = "Error Applying";
                applyBtn.disabled = false;
              }
            };
            actions.appendChild(applyBtn);

            drawer.appendChild(actions);
            contentDiv.appendChild(drawer);
          } catch {
            fixBtn.textContent = "Fix Failed";
          }
        };

        box.appendChild(fixBtn);
        warningRow.appendChild(cell);
        cell.appendChild(box);

        targetRow.after(warningRow);
      }
    });
  });
}

function ensureDiffObserver(repo: string, pr: number) {
  const prKey = `${repo}#${pr}`;
  if (currentObservingPR === prKey && diffObserver) {
    return;
  }
  currentObservingPR = prKey;

  if (diffObserver) {
    diffObserver.disconnect();
    diffObserver = null;
  }

  diffObserver = new MutationObserver(() => {
    if (cachedFindings.length === 0) return;

    if (diffDebounceTimer) {
      clearTimeout(diffDebounceTimer);
    }
    diffDebounceTimer = setTimeout(() => {
      applyLineWarnings(cachedFindings, repo, pr);
    }, 250);
  });

  const diffContainer =
    document.querySelector("#files_bucket") ||
    document.querySelector("#files") ||
    document.querySelector(".js-diff-progressive-container") ||
    document.querySelector(".diff-view") ||
    document.body;

  diffObserver.observe(diffContainer, {
    childList: true,
    subtree: true,
  });
}

function handleNavigation() {
  const prInfo = parsePRUrl(window.location.href);
  if (prInfo) {
    injectPRBadge(prInfo.repo, prInfo.pr);
  } else {
    // If navigated away from a PR page, cleanup badge and observers
    if (injectionRetryTimer) {
      clearTimeout(injectionRetryTimer);
      injectionRetryTimer = null;
    }
    if (diffObserver) {
      diffObserver.disconnect();
      diffObserver = null;
      currentObservingPR = null;
    }
    const existing = document.getElementById(BADGE_ROOT_ID);
    if (existing) {
      if (activeBadgeRoot) {
        activeBadgeRoot.unmount();
        activeBadgeRoot = null;
      }
      existing.remove();
    }
    cachedFindings = [];
  }
}

// 1. Listen for background service worker awakening triggers
chrome.runtime.onMessage.addListener((message: any) => {
  if (message.type === "AWAKE_PR_SCAN") {
    handleNavigation();
  }
});

// 2. Initial execution on page load
handleNavigation();

// 3. Listen to GitHub Turbo / SPA events
document.addEventListener("turbo:render", handleNavigation);
document.addEventListener("turbo:load", handleNavigation);
document.addEventListener("pjax:end", handleNavigation);
window.addEventListener("popstate", handleNavigation);

// 4. Fallback URL change observer
let lastUrl = window.location.href;
const urlObserver = new MutationObserver(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    handleNavigation();
  }
});
urlObserver.observe(document.body, { childList: true, subtree: true });
