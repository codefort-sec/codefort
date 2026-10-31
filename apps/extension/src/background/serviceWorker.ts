/**
 * CodeFort Guard Background Service Worker (Manifest V3)
 */

import {
  fetchPRFindings,
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

    default:
      return {
        success: false,
        error: { code: "UNSUPPORTED_MESSAGE", message: "Unsupported message type." },
      };
  }
}
