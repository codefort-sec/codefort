/**
 * Type-safe storage helpers using chrome.storage.local
 */

import { ExtensionConfig } from "./types";

const DEFAULT_CONFIG: ExtensionConfig = {
  apiUrl: "https://codefort-lilac.vercel.app",
  token: null,
  paired: false,
};

export async function getStoredConfig(): Promise<ExtensionConfig> {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      resolve(DEFAULT_CONFIG);
      return;
    }
    chrome.storage.local.get(["apiUrl", "token", "paired"], (res) => {
      resolve({
        apiUrl: res.apiUrl || DEFAULT_CONFIG.apiUrl,
        token: res.token || null,
        paired: Boolean(res.paired),
      });
    });
  });
}

export async function setStoredConfig(config: Partial<ExtensionConfig>): Promise<void> {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      resolve();
      return;
    }
    chrome.storage.local.set(config, () => {
      resolve();
    });
  });
}

export async function clearStoredAuth(): Promise<void> {
  return setStoredConfig({ token: null, paired: false });
}

