/**
 * background.js — Sentinel Zero Chrome Extension
 * Service worker (Manifest V3) that manages URL checking, caching,
 * and communication with the Sentinel Zero Local API.
 *
 * Responsibilities:
 *   - Maintain a session cache of checked URLs (max 500 entries)
 *   - Handle messages from content.js requesting URL analysis
 *   - Update extension badge with current risk summary
 *   - Persist session statistics to chrome.storage.local
 */

const API_BASE = "http://localhost:5050";
const CACHE_MAX_SIZE = 500;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory URL → result cache
// { url: string → { result: object, timestamp: number } }
const urlCache = new Map();

/**
 * Evict cache entries older than CACHE_TTL_MS and enforce max size.
 */
function pruneCache() {
  const now = Date.now();
  for (const [key, entry] of urlCache.entries()) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      urlCache.delete(key);
    }
  }
  // If still over limit, remove oldest entries
  while (urlCache.size > CACHE_MAX_SIZE) {
    urlCache.delete(urlCache.keys().next().value);
  }
}

/**
 * Check a URL against the Sentinel Zero Local API.
 * Returns null if the API is unreachable (fail-open: user is not blocked).
 *
 * @param {string} url
 * @returns {Promise<object|null>}
 */
async function checkUrl(url) {
  pruneCache();

  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3s timeout

    const resp = await fetch(`${API_BASE}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!resp.ok) return null;

    const result = await resp.json();
    urlCache.set(url, { result, timestamp: Date.now() });
    return result;
  } catch (err) {
    // API unreachable or timed out — fail open (don't block user)
    console.warn("[Sentinel Zero] API unreachable:", err.message);
    return null;
  }
}

/**
 * Update the extension badge with a summary of current session stats.
 *
 * @param {object} stats  { checks, phishing, suspicious }
 */
function updateBadge(stats) {
  const threats = (stats.phishing || 0) + (stats.suspicious || 0);
  if (threats === 0) {
    chrome.action.setBadgeText({ text: "" });
  } else {
    chrome.action.setBadgeText({ text: String(threats) });
    chrome.action.setBadgeBackgroundColor({
      color: stats.phishing > 0 ? "#dc2626" : "#d97706",
    });
  }
}

/**
 * Persist detection stats and update badge.
 *
 * @param {object} result  API response from /check-url
 */
async function recordResult(result) {
  const { sz_stats: existing } = await chrome.storage.local.get("sz_stats");
  const stats = existing || { checks: 0, phishing: 0, suspicious: 0, last_check: null };

  stats.checks += 1;
  if (result.verdict === "PHISHING") stats.phishing += 1;
  if (result.verdict === "SUSPICIOUS") stats.suspicious += 1;
  stats.last_check = {
    url: result.url, // Already anonymised by the API
    verdict: result.verdict,
    score: result.risk_score,
    timestamp: new Date().toISOString(),
  };

  await chrome.storage.local.set({ sz_stats: stats });
  updateBadge(stats);
}

// ── Message handler ──────────────────────────────────────────────────────────

/**
 * Handle messages from content scripts.
 *
 * Supported actions:
 *   - "CHECK_URL" → check URL via API, return result
 *   - "GET_STATS" → return session stats from storage
 *   - "CLEAR_CACHE" → clear the URL cache
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === "CHECK_URL") {
    (async () => {
      const { url } = message;
      if (!url) {
        sendResponse({ error: "No URL provided" });
        return;
      }

      const result = await checkUrl(url);
      if (result) {
        await recordResult(result);
      }
      sendResponse(result);
    })();
    return true; // Keep message channel open for async response
  }

  if (message.action === "GET_STATS") {
    chrome.storage.local.get("sz_stats", ({ sz_stats }) => {
      sendResponse(sz_stats || { checks: 0, phishing: 0, suspicious: 0 });
    });
    return true;
  }

  if (message.action === "CLEAR_CACHE") {
    urlCache.clear();
    sendResponse({ success: true, message: "Cache cleared" });
    return false;
  }
});

// ── Startup: restore badge state ─────────────────────────────────────────────

chrome.runtime.onStartup.addListener(async () => {
  const { sz_stats } = await chrome.storage.local.get("sz_stats");
  if (sz_stats) updateBadge(sz_stats);
});

chrome.runtime.onInstalled.addListener(async () => {
  // Reset stats on fresh install (not on update)
  const { sz_stats } = await chrome.storage.local.get("sz_stats");
  if (!sz_stats) {
    await chrome.storage.local.set({
      sz_stats: { checks: 0, phishing: 0, suspicious: 0, last_check: null },
    });
  }
});
