/**
 * content.js — Sentinel Zero Chrome Extension
 * Intercepts link clicks and requests URL analysis from the background
 * service worker (background.js) via Chrome message passing.
 *
 * All network calls are handled in background.js — this script only
 * handles DOM interaction and warning banner display.
 */

const HIGH_RISK_VERDICTS = new Set(["PHISHING", "SUSPICIOUS"]);

// Schemes safe to analyse (skip javascript:, data:, vbscript:, etc.)
const SAFE_TO_ANALYSE_SCHEMES = new Set(["http:", "https:"]);

const BANNER_AUTO_DISMISS_MS = 8000;
const BANNER_ID = "sentinel-zero-banner";

function removeBanner() {
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showBanner(verdict, riskScore, topReasons) {
  removeBanner();
  const isHigh = verdict === "PHISHING";
  const bgColor = isHigh ? "#dc2626" : "#d97706";
  const emoji = isHigh ? "🚫" : "⚠️";

  const reasonsHtml = topReasons && topReasons.length
    ? `<ul style="margin:4px 0 0 0;padding:0 0 0 16px;font-size:12px;opacity:.9;">
        ${topReasons.slice(0, 3).map(r => `<li>${r}</li>`).join("")}
       </ul>`
    : "";

  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${bgColor}; color: #fff; font-family: system-ui, sans-serif;
    padding: 12px 20px; display: flex; align-items: flex-start; gap: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,.4); font-size: 14px;
  `;
  banner.innerHTML = `
    <span style="font-size:1.4em;margin-top:2px">${emoji}</span>
    <span style="flex:1">
      <strong>Sentinel Zero:</strong> This link looks
      <strong>${verdict}</strong> (risk score: ${(riskScore * 100).toFixed(0)}%).
      ${reasonsHtml}
    </span>
    <button id="sz-dismiss" style="margin-left:auto;background:rgba(255,255,255,.25);
      border:none;color:#fff;padding:4px 12px;border-radius:6px;cursor:pointer;flex-shrink:0;">
      Dismiss
    </button>
  `;
  document.body.prepend(banner);
  document.getElementById("sz-dismiss").addEventListener("click", removeBanner);
  setTimeout(removeBanner, BANNER_AUTO_DISMISS_MS);
}

/**
 * Request a URL check from the background service worker.
 * Returns null if the background is unreachable or the API is down.
 *
 * @param {string} url
 * @returns {Promise<object|null>}
 */
async function checkUrl(url) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ action: "CHECK_URL", url }, (response) => {
        if (chrome.runtime.lastError) {
          // Extension context may be invalid (e.g., reloaded) — fail open
          resolve(null);
        } else {
          resolve(response || null);
        }
      });
    } catch {
      resolve(null);
    }
  });
}

document.addEventListener(
  "click",
  async (event) => {
    const anchor = event.target.closest("a[href]");
    if (!anchor) return;

    const href = anchor.href;
    if (!href) return;

    // Only analyse http/https URLs
    try {
      const parsed = new URL(href);
      if (!SAFE_TO_ANALYSE_SCHEMES.has(parsed.protocol)) return;
    } catch {
      return; // Malformed URL
    }

    const result = await checkUrl(href);
    if (!result) return;

    if (HIGH_RISK_VERDICTS.has(result.verdict)) {
      showBanner(result.verdict, result.risk_score, result.top_reasons || []);
    }
  },
  true // Capture phase — intercept before navigation
);

