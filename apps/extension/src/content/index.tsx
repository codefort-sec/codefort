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

let activeBadgeRoot: ReactDOM.Root | null = null;
let injectionRetryTimer: any = null;
let currentObservingPR: string | null = null;

async function injectPRBadge(repo: string, pr: number, retryCount = 0) {
  // Clear any pending retry
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

  // 2. Find target GitHub insertion point across modern GitHub DOM variants
  const targetHeader =
    document.querySelector(".gh-header-meta") ||
    document.querySelector(".gh-header-actions") ||
    document.querySelector(".gh-header-title") ||
    document.querySelector("#partial-discussion-header") ||
    document.querySelector("[data-testid='issue-metadata-fixed']") ||
    document.querySelector(".js-issue-title");

  if (!targetHeader) {
    // Retry up to 12 times (3 seconds total) to handle dynamic Turbo / React mounting
    if (retryCount < 12) {
      injectionRetryTimer = setTimeout(() => {
        injectPRBadge(repo, pr, retryCount + 1);
      }, 250);
    }
    return;
  }

  // 3. Create host container
  const container = document.createElement("span");
  container.id = BADGE_ROOT_ID;
  targetHeader.appendChild(container);

  activeBadgeRoot = ReactDOM.createRoot(container);

  // Render initial loading state
  activeBadgeRoot.render(
    <BadgeOverlay status={null} summary={null} loading={true} />
  );

  // 4. Fetch status and summary via background service worker
  try {
    const statusMsg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr };
    const summaryMsg: ExtensionMessage = { type: "GET_PR_SUMMARY", repo, pr };

    const [statusRes, summaryRes] = await Promise.all([
      chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionPRStatusResponse>>(statusMsg),
      chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionSummaryResponse>>(summaryMsg),
    ]);

    if (!statusRes.success) {
      activeBadgeRoot.render(
        <BadgeOverlay
          status={null}
          summary={null}
          loading={false}
          error={statusRes.error?.message || "Failed to fetch scan"}
        />
      );
      return;
    }

    activeBadgeRoot.render(
      <BadgeOverlay
        status={statusRes.data}
        summary={summaryRes.success ? summaryRes.data : null}
        loading={false}
      />
    );

    // 5. If findings exist, also inject inline line warnings into the diff view
    injectLineWarnings(repo, pr);
    observeDiffContainer(repo, pr);
  } catch (err: any) {
    activeBadgeRoot.render(
      <BadgeOverlay
        status={null}
        summary={null}
        loading={false}
        error={err.message || "Failed to communicate with CodeFort"}
      />
    );
  }
}

async function injectLineWarnings(repo: string, pr: number) {
  try {
    const findingsMsg: ExtensionMessage = { type: "GET_PR_FINDINGS", repo, pr };
    const findingsRes = await chrome.runtime.sendMessage<
      ExtensionMessage,
      ExtensionResponse<{ findings: ExtensionLineFinding[] }>
    >(findingsMsg);

    if (!findingsRes.success || !findingsRes.data?.findings?.length) {
      return;
    }

    // Clean up previously injected line warnings to avoid duplicates
    document.querySelectorAll(".codefort-diff-warning-row").forEach((el) => el.remove());

    const findings = findingsRes.data.findings;

    findings.forEach((finding) => {
      // Find file container in GitHub diff view: div[data-tagsearch-path="filename"] or div[data-path="filename"]
      const fileBoxes = document.querySelectorAll(
        `div[data-path*="${finding.file_path}"], div[data-tagsearch-path*="${finding.file_path}"], div.file[data-file-type]`
      );

      fileBoxes.forEach((fileBox) => {
        // Find line row in diff table: tr td[data-line-number="12"]
        const lineCell = fileBox.querySelector(
          `td[data-line-number="${finding.line_start}"]`
        );
        const row = lineCell?.closest("tr");

        if (row && !row.nextElementSibling?.classList.contains("codefort-diff-warning-row")) {
          const warningRow = document.createElement("tr");
          warningRow.className = "codefort-diff-warning-row";

          const cell = document.createElement("td");
          cell.colSpan = 10;

          const box = document.createElement("div");
          box.className = "codefort-diff-warning-box";

          const tag = document.createElement("span");
          tag.className = "codefort-diff-warning-tag";
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
          row.after(warningRow);
        }
      });
    });
  } catch {
    // Non-blocking for line warnings
  }
}

// Observe dynamic diff loading (e.g. switching to "Files changed" tab or progressive loading)
let diffObserver: MutationObserver | null = null;
function observeDiffContainer(repo: string, pr: number) {
  const prKey = `${repo}#${pr}`;
  if (currentObservingPR === prKey && diffObserver) {
    return;
  }
  currentObservingPR = prKey;

  if (diffObserver) {
    diffObserver.disconnect();
  }

  diffObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        // Check if any added node is or contains a diff table or file container
        for (let i = 0; i < m.addedNodes.length; i++) {
          const node = m.addedNodes[i] as HTMLElement;
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (
              node.classList?.contains("file") ||
              node.querySelector?.("div[data-path], table.diff-table")
            ) {
              injectLineWarnings(repo, pr);
              return;
            }
          }
        }
      }
    }
  });

  const diffContainer =
    document.querySelector("#files") ||
    document.querySelector(".js-diff-progressive-container") ||
    document.body;

  diffObserver.observe(diffContainer, { childList: true, subtree: true });
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
const observer = new MutationObserver(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    handleNavigation();
  }
});
observer.observe(document.body, { childList: true, subtree: true });
