import ReactDOM from "react-dom/client";
import { BadgeOverlay } from "./BadgeOverlay";
import {
  ExtensionLineFinding,
  ExtensionMessage,
  ExtensionPRStatusResponse,
  ExtensionResponse,
  ExtensionSummaryResponse,
} from "../shared/types";
import "./content.css";

const BADGE_ROOT_ID = "codefort-guard-badge-root";

// Parse GitHub PR URL: https://github.com/:owner/:repo/pull/:number
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
    document.querySelector(".gh-header-title") ||
    document.querySelector("#partial-discussion-header") ||
    document.querySelector(".gh-header-actions") ||
    document.querySelector("div[class*=\"pr-header\"]");

  if (meta) {
    return { parent: meta, insertBefore: null };
  }

  return null;
}

let activeBadgeRoot: ReactDOM.Root | null = null;
let cachedFindings: ExtensionLineFinding[] = [];
let diffObserver: MutationObserver | null = null;
let diffDebounceTimer: ReturnType<typeof setTimeout> | null = null;

async function injectPRBadge(repo: string, pr: number, retryCount = 0, force = false) {
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
    if (retryCount < 8) {
      setTimeout(() => injectPRBadge(repo, pr, retryCount + 1, force), 250);
    }
    return;
  }

  // 3. Create host container
  const container = document.createElement("span");
  container.id = BADGE_ROOT_ID;

  if (target.insertBefore) {
    target.parent.insertBefore(container, target.insertBefore);
  } else {
    target.parent.appendChild(container);
  }

  activeBadgeRoot = ReactDOM.createRoot(container);

  const handleRetry = () => {
    injectPRBadge(repo, pr, 0, true);
  };

  // Render initial loading state
  activeBadgeRoot.render(
    <BadgeOverlay status={null} summary={null} loading={true} />
  );

  // 4. Fetch status and summary via background service worker
  try {
    const statusMsg: ExtensionMessage = { type: "GET_PR_STATUS", repo, pr, force };
    const summaryMsg: ExtensionMessage = { type: "GET_PR_SUMMARY", repo, pr, force };

    const [statusRes, summaryRes] = await Promise.all([
      chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionPRStatusResponse>>(statusMsg),
      chrome.runtime.sendMessage<ExtensionMessage, ExtensionResponse<ExtensionSummaryResponse>>(summaryMsg),
    ]);

    if (!statusRes?.success) {
      activeBadgeRoot.render(
        <BadgeOverlay
          status={null}
          summary={null}
          loading={false}
          error={statusRes?.error?.message || "Failed to fetch scan"}
          onRetry={handleRetry}
        />
      );
      return;
    }

    activeBadgeRoot.render(
      <BadgeOverlay
        status={statusRes.data}
        summary={summaryRes?.success ? summaryRes.data : null}
        loading={false}
        onRetry={handleRetry}
      />
    );

    // 5. Fetch line findings and set up dynamic diff observer
    await loadAndApplyFindings(repo, pr, force);
    ensureDiffObserver();
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
      applyLineWarnings(cachedFindings);
    }
  } catch {
    // Non-blocking for diff line warnings
  }
}

function applyLineWarnings(findings: ExtensionLineFinding[]) {
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
        warningRow.appendChild(cell);
        cell.appendChild(box);

        targetRow.after(warningRow);
      }
    });
  });
}

function ensureDiffObserver() {
  if (diffObserver) return;

  diffObserver = new MutationObserver(() => {
    if (cachedFindings.length === 0) return;

    if (diffDebounceTimer) {
      clearTimeout(diffDebounceTimer);
    }
    diffDebounceTimer = setTimeout(() => {
      applyLineWarnings(cachedFindings);
    }, 250);
  });

  const diffContainer =
    document.querySelector("#files_bucket") ||
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
    // If navigated away from a PR page, cleanup
    const existing = document.getElementById(BADGE_ROOT_ID);
    if (existing) {
      if (activeBadgeRoot) {
        activeBadgeRoot.unmount();
        activeBadgeRoot = null;
      }
      existing.remove();
    }
    if (diffObserver) {
      diffObserver.disconnect();
      diffObserver = null;
    }
    cachedFindings = [];
  }
}

// 1. Initial execution on page load
handleNavigation();

// 2. Listen to GitHub Turbo / SPA events
document.addEventListener("turbo:render", handleNavigation);
document.addEventListener("turbo:load", handleNavigation);
document.addEventListener("pjax:end", handleNavigation);
window.addEventListener("popstate", handleNavigation);

// 3. Fallback URL change observer
let lastUrl = window.location.href;
const urlObserver = new MutationObserver(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    handleNavigation();
  }
});
urlObserver.observe(document.body, { childList: true, subtree: true });
