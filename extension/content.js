/**
 * content.js — Sentinel Zero Chrome Extension
 * Intercepts link clicks and checks URLs against the Sentinel Zero Local API.
 */

const API_BASE = "http://localhost:5050";
const CHECKED_CACHE = new Map(); // url -> verdict
const CACHE_MAX_SIZE = 200;
const HIGH_RISK_VERDICTS = new Set(["PHISHING", "SUSPICIOUS"]);

// Schemes that must never be sent to the API or followed for analysis
const SAFE_TO_ANALYSE_SCHEMES = new Set(["http:", "https:"]);

/** Banner IDs to avoid duplicates */
const BANNER_AUTO_DISMISS_MS = 8000;
const BANNER_ID = "sentinel-zero-banner";

function removeBanner() {
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showBanner(verdict, url, riskScore) {
  removeBanner();
  const isHigh = verdict === "PHISHING";
  const bgColor = isHigh ? "#dc2626" : "#d97706";
  const emoji = isHigh ? "🚫" : "⚠️";
  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${bgColor}; color: #fff; font-family: system-ui, sans-serif;
    padding: 12px 20px; display: flex; align-items: center; gap: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,.4); font-size: 14px;
  `;
  banner.innerHTML = `
    <span style="font-size:1.4em">${emoji}</span>
    <span>
      <strong>Sentinel Zero:</strong> This link looks
      <strong>${verdict}</strong> (risk score: ${(riskScore * 100).toFixed(0)}%).
      Proceed with caution.
    </span>
    <button id="sz-dismiss" style="margin-left:auto;background:rgba(255,255,255,.25);
      border:none;color:#fff;padding:4px 12px;border-radius:6px;cursor:pointer;">
      Dismiss
    </button>
  `;
  document.body.prepend(banner);
  document.getElementById("sz-dismiss").addEventListener("click", removeBanner);
  // Auto-dismiss after BANNER_AUTO_DISMISS_MS
  setTimeout(removeBanner, BANNER_AUTO_DISMISS_MS);
}

async function checkUrl(url) {
  if (CHECKED_CACHE.has(url)) return CHECKED_CACHE.get(url);
  // Evict oldest entries when cache is full
  if (CHECKED_CACHE.size >= CACHE_MAX_SIZE) {
    const firstKey = CHECKED_CACHE.keys().next().value;
    CHECKED_CACHE.delete(firstKey);
  }
  try {
    const resp = await fetch(`${API_BASE}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    CHECKED_CACHE.set(url, data);
    // Persist stats to extension storage
    chrome.storage.local.get("sz_stats", (res) => {
      const stats = res.sz_stats || { checks: 0, phishing: 0, suspicious: 0 };
      stats.checks += 1;
      if (data.verdict === "PHISHING") stats.phishing += 1;
      if (data.verdict === "SUSPICIOUS") stats.suspicious += 1;
      stats.last_check = { url: data.url, verdict: data.verdict, score: data.risk_score };
      chrome.storage.local.set({ sz_stats: stats });
    });
    return data;
  } catch {
    return null;
  }
}

document.addEventListener(
  "click",
  async (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor) return;
    const href = anchor.href;
    if (!href) return;
    // Only analyse http/https URLs; skip javascript:, data:, vbscript:, #, etc.
    let parsed;
    try {
      parsed = new URL(href);
      if (!SAFE_TO_ANALYSE_SCHEMES.has(parsed.protocol)) return;
    } catch {
      return; // malformed URL — let the browser handle it naturally
    }

    // Prevent immediate navigation so the async check can complete first
    event.preventDefault();

    const result = await checkUrl(href);
    if (!result) {
      // API unreachable — navigate normally so legitimate links still work
      window.location.href = href;
      return;
    }
    if (HIGH_RISK_VERDICTS.has(result.verdict)) {
      // Block navigation and warn the user
      showBanner(result.verdict, href, result.risk_score);
    } else {
      // SAFE — navigate programmatically
      window.location.href = href;
    }
  },
  true // capture phase so we intercept before navigation
);
