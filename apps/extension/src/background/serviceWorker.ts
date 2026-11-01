/**
 * CodeFort Guard Background Service Worker (Manifest V3)
 * Powered by Barq-AI
 */

import {
  applyPRRemediation,
  fetchPRFindings,
  fetchPRRemediation,
  fetchPRStatus,
  fetchPRSummary,
  pairWithToken,
  triggerPRScan,
} from "../shared/api";
import { clearStoredAuth, getStoredConfig } from "../shared/storage";
import { ExtensionMessage, ExtensionResponse } from "../shared/types";

// Short-lived memory cache to avoid thrashing GitHub DOM navigations
const cache = new Map<string, { timestamp: number; data: any }>();
const CACHE_TTL_MS = 15000; // 15 seconds

function getCached<T>(key: string): T | null {
  const item = cache.get(key);
  if (item && Date.now() - item.timestamp < CACHE_TTL_MS) {
    return item.data as T;
  }
  cache.delete(key);
  return null;
}

function setCache(key: string, data: any) {
  cache.set(key, { timestamp: Date.now(), data });
}

function invalidateCacheForPR(repo: string, pr: number) {
  cache.delete(`status:${repo}:${pr}`);
  cache.delete(`findings:${repo}:${pr}`);
  cache.delete(`summary:${repo}:${pr}`);
}

// Parse GitHub PR URL: https://github.com/:owner/:repo/pull/:number
function parsePRUrl(url?: string): { repo: string; pr: number } | null {
  if (!url) return null;
  const match = url.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!match) return null;
  return {
    repo: `${match[1]}/${match[2]}`,
    pr: parseInt(match[3], 10),
  };
}

/**
 * Automatically awakes the extension when a GitHub Pull Request is opened or visited.
 * Updates the browser action icon badge in real-time and alerts content scripts.
 */
async function awakeExtensionForPR(tabId: number, url: string) {
  const prInfo = parsePRUrl(url);
  if (!prInfo) {
    // Navigated away from a PR: clear toolbar badge
    try {
      await chrome.action.setBadgeText({ tabId, text: "" });
    } catch {
      // Tab may have closed
    }
    return;
  }

  // 1. Indicate active scanning state on toolbar icon
  try {
    await chrome.action.setBadgeText({ tabId, text: "SCAN" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#00E5FF" }); // Cyan
    await chrome.action.setTitle({
      tabId,
      title: `CodeFort Guard (Barq-AI): Scanning ${prInfo.repo} #${prInfo.pr}...`,
    });
  } catch {
    // Non-critical if tab not ready
  }

  // 2. Pre-fetch status and update badge
  try {
    const cacheKey = `status:${prInfo.repo}:${prInfo.pr}`;
    let statusData = getCached<any>(cacheKey);
    if (!statusData) {
      statusData = await fetchPRStatus(prInfo.repo, prInfo.pr);
      setCache(cacheKey, statusData);
    }

    const verdict = statusData?.verdict || "UNKNOWN";
    const riskScore = statusData?.risk_score ?? 0;

    let badgeText = "OK";
    let badgeColor = "#00FF66"; // Lime

    if (verdict === "BLOCKED" || riskScore >= 70) {
      badgeText = "BLK";
      badgeColor = "#FF0055"; // Cyber Red
    } else if (verdict === "REVIEW_REQUIRED" || riskScore >= 30) {
      badgeText = "REV";
      badgeColor = "#FFAA00"; // Amber
    } else if (verdict === "PASS") {
      badgeText = "PASS";
      badgeColor = "#00FF66"; // Lime
    }

    await chrome.action.setBadgeText({ tabId, text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
    await chrome.action.setTitle({
      tabId,
      title: `CodeFort Guard (Barq-AI): [${verdict}] (Risk: ${riskScore}/100) on ${prInfo.repo} #${prInfo.pr}`,
    });

    // 3. Dispatch wakeup trigger to the content script in this tab
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: "AWAKE_PR_SCAN",
        repo: prInfo.repo,
        pr: prInfo.pr,
        status: statusData,
      });
    } catch {
      // Content script may still be initializing
    }
  } catch (err: any) {
    try {
      await chrome.action.setBadgeText({ tabId, text: "!" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#777777" });
      await chrome.action.setTitle({
        tabId,
        title: `CodeFort Guard (Barq-AI): ${err.message || "Unpaired or server unavailable"}`,
      });
    } catch {
      // Ignore
    }
  }
}

// 1. Listen for GitHub Navigation & Tab Updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const currentUrl = changeInfo.url || tab.url;
  if (currentUrl && currentUrl.includes("github.com")) {
    awakeExtensionForPR(tabId, currentUrl);
  }
});

// 2. Listen for Active Tab Switches
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab?.url && tab.url.includes("github.com")) {
      awakeExtensionForPR(activeInfo.tabId, tab.url);
    }
  } catch {
    // Ignore tab errors
  }
});

// 3. Listen for WebNavigation History State Updates (GitHub Turbo / SPA pushes)
if (chrome.webNavigation?.onHistoryStateUpdated) {
  chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.url && details.url.includes("github.com")) {
      awakeExtensionForPR(details.tabId, details.url);
    }
  });
}

// 4. Handle runtime messages from Popup and Content Scripts
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((err) => {
      sendResponse({
        success: false,
        error: {
          code: err.code || "UNKNOWN_ERROR",
          message: err.message || "An unexpected error occurred in background worker.",
        },
      } as ExtensionResponse);
    });

  // Return true to indicate asynchronous response to chrome.runtime
  return true;
});

async function handleMessage(
  message: ExtensionMessage,
  _sender: chrome.runtime.MessageSender
): Promise<ExtensionResponse> {
  switch (message.type) {
    case "CHECK_PAIRING_STATUS": {
      const config = await getStoredConfig();
      return { success: true, data: { paired: config.paired, apiUrl: config.apiUrl } };
    }

    case "PAIR_WITH_TOKEN": {
      const success = await pairWithToken(message.pairingToken);
      return { success: true, data: { paired: success } };
    }

    case "UNPAIR": {
      await clearStoredAuth();
      return { success: true, data: { paired: false } };
    }

    case "TRIGGER_PR_SCAN": {
      invalidateCacheForPR(message.repo, message.pr);
      const data = await triggerPRScan(message.repo, message.pr);
      setCache(`status:${message.repo}:${message.pr}`, data);
      return { success: true, data };
    }

    case "GET_PR_STATUS": {
      const cacheKey = `status:${message.repo}:${message.pr}`;
      if (message.force) {
        cache.delete(cacheKey);
      } else {
        const cached = getCached(cacheKey);
        if (cached) {
          return { success: true, data: cached };
        }
      }
      const data = await fetchPRStatus(message.repo, message.pr);
      setCache(cacheKey, data);
      return { success: true, data };
    }

    case "GET_PR_FINDINGS": {
      const cacheKey = `findings:${message.repo}:${message.pr}`;
      if (message.force) {
        cache.delete(cacheKey);
      } else {
        const cached = getCached(cacheKey);
        if (cached) {
          return { success: true, data: cached };
        }
      }
      const data = await fetchPRFindings(message.repo, message.pr);
      setCache(cacheKey, data);
      return { success: true, data };
    }

    case "GET_PR_SUMMARY": {
      const cacheKey = `summary:${message.repo}:${message.pr}`;
      if (message.force) {
        cache.delete(cacheKey);
      } else {
        const cached = getCached(cacheKey);
        if (cached) {
          return { success: true, data: cached };
        }
      }
      const data = await fetchPRSummary(message.repo, message.pr);
      setCache(cacheKey, data);
      return { success: true, data };
    }

    case "GET_PR_REMEDIATION": {
      const cacheKey = `remediation:${message.repo}:${message.pr}`;
      const cached = getCached(cacheKey);
      if (cached) {
        return { success: true, data: cached };
      }
      const data = await fetchPRRemediation(message.repo, message.pr);
      setCache(cacheKey, data);
      return { success: true, data };
    }

    case "APPLY_PR_REMEDIATION": {
      const data = await applyPRRemediation(message.repo, message.pr);
      // Invalidate caches upon patch application
      cache.delete(`status:${message.repo}:${message.pr}`);
      cache.delete(`findings:${message.repo}:${message.pr}`);
      cache.delete(`summary:${message.repo}:${message.pr}`);
      cache.delete(`remediation:${message.repo}:${message.pr}`);
      return { success: true, data };
    }

    case "AWAKE_PR_SCAN": {
      if (_sender.tab?.id && _sender.tab.url) {
        await awakeExtensionForPR(_sender.tab.id, _sender.tab.url);
      }
      return { success: true, data: { status: "AWOKEN" } };
    }

    default:
      return {
        success: false,
        error: { code: "UNSUPPORTED_MESSAGE", message: "Unsupported message type." },
      };
  }
}
