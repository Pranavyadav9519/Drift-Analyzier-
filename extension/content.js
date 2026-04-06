/**
 * content.js — Drift Analyzer URL Interceptor
 *
 * Intercepts all link clicks on the page and sends the destination URL
 * to the Drift Analyzer phishing API before allowing navigation.
 *
 * If the URL is PHISHING or SUSPICIOUS:
 *   - Navigation is blocked
 *   - An inline warning banner is shown with the threat verdict and top remedy steps
 *   - The background script is notified to show a native OS notification
 *
 * If SAFE: navigation proceeds normally (zero user friction on safe clicks).
 *
 * Privacy: only the URL is sent to localhost — nothing leaves the device.
 */

const PHISHING_API = "http://localhost:5050";

// Cache recently checked URLs so we don't re-check the same link repeatedly.
// Map<url, threatData> — limited to 200 entries to avoid memory bloat.
const URL_CACHE = new Map();
const CACHE_MAX_SIZE = 200;

// Only analyse http and https URLs — skip javascript:, data:, #anchors, etc.
const SAFE_SCHEMES = new Set(["http:", "https:"]);

const BANNER_DISMISS_DELAY_MS = 10000;  // Auto-dismiss warning banner after 10 seconds
const BANNER_ELEMENT_ID = "drift-analyzer-banner";

// ── Cache helpers ─────────────────────────────────────────────────────────────

function cacheGet(url) {
  return URL_CACHE.get(url) || null;
}

function cacheSet(url, threatData) {
  // Evict the oldest entry if we're at the size limit
  if (URL_CACHE.size >= CACHE_MAX_SIZE) {
    const oldestKey = URL_CACHE.keys().next().value;
    URL_CACHE.delete(oldestKey);
  }
  URL_CACHE.set(url, threatData);
}

// ── API call ─────────────────────────────────────────────────────────────────

async function checkUrlThreat(url) {
  const cached = cacheGet(url);
  if (cached !== null) return cached;

  try {
    const response = await fetch(PHISHING_API + "/threat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) return null;

    const threatData = await response.json();
    cacheSet(url, threatData);

    // Update session stats in storage so the popup can display them
    chrome.storage.local.get("drift_stats", function(result) {
      const stats = result.drift_stats || { total: 0, threats: 0 };
      stats.total += 1;
      if (threatData.threat_type) stats.threats += 1;
      chrome.storage.local.set({ drift_stats: stats });
    });

    return threatData;

  } catch {
    // API unreachable — fail open (allow navigation) rather than blocking the user
    return null;
  }
}

// ── Warning banner ────────────────────────────────────────────────────────────

function removeBanner() {
  const existing = document.getElementById(BANNER_ELEMENT_ID);
  if (existing) existing.remove();
}

function showWarningBanner(threatData) {
  removeBanner();

  const isHighSeverity = threatData.severity === "high" || threatData.severity === "critical";
  const backgroundColor = isHighSeverity ? "#dc2626" : "#d97706";
  const icon = isHighSeverity ? "🚨" : "⚠️";
  const threatLabel = (threatData.threat_type || "threat").replace(/_/g, " ").toUpperCase();
  const scorePercent = Math.round((threatData.risk_score || 0) * 100);

  // Build top 2 remedy steps for the inline banner (full list is in the popup)
  const topRemedies = (threatData.remedy_steps || []).slice(0, 2);

  const banner = document.createElement("div");
  banner.id = BANNER_ELEMENT_ID;
  banner.style.cssText = [
    "position: fixed",
    "top: 0",
    "left: 0",
    "right: 0",
    "z-index: 2147483647",
    "background: " + backgroundColor,
    "color: #fff",
    "font-family: system-ui, sans-serif",
    "padding: 12px 16px",
    "box-shadow: 0 2px 12px rgba(0,0,0,.5)",
    "font-size: 13px",
    "line-height: 1.5",
  ].join("; ");

  // Build banner using DOM APIs so user-controlled text is never interpreted as HTML
  const row = document.createElement("div");
  row.style.cssText = "display:flex;align-items:flex-start;gap:10px";

  const iconSpan = document.createElement("span");
  iconSpan.style.fontSize = "1.4em";
  iconSpan.textContent = icon;

  const bodyDiv = document.createElement("div");
  bodyDiv.style.flex = "1";

  const heading = document.createElement("strong");
  heading.textContent = "Drift Analyzer \u2014 " + threatLabel + " DETECTED";

  const riskSpan = document.createElement("span");
  riskSpan.style.cssText = "opacity:.8;margin-left:8px";
  riskSpan.textContent = "Risk: " + scorePercent + "%";

  const descPara = document.createElement("p");
  descPara.style.cssText = "margin:4px 0 0;opacity:.9";
  descPara.textContent = threatData.description || "";

  bodyDiv.appendChild(heading);
  bodyDiv.appendChild(riskSpan);
  bodyDiv.appendChild(descPara);

  if (topRemedies.length > 0) {
    const ol = document.createElement("ol");
    ol.style.cssText = "margin:6px 0 0;padding-left:18px;opacity:.9";
    topRemedies.forEach(function(step) {
      const li = document.createElement("li");
      li.textContent = step;  // textContent prevents XSS — never use innerHTML here
      ol.appendChild(li);
    });
    bodyDiv.appendChild(ol);
  }

  const dismissBtn = document.createElement("button");
  dismissBtn.id = "drift-dismiss-btn";
  dismissBtn.style.cssText = (
    "background:rgba(255,255,255,.25);border:none;color:#fff;" +
    "padding:4px 10px;border-radius:6px;cursor:pointer;white-space:nowrap;"
  );
  dismissBtn.textContent = "Dismiss";
  dismissBtn.addEventListener("click", removeBanner);

  row.appendChild(iconSpan);
  row.appendChild(bodyDiv);
  row.appendChild(dismissBtn);
  banner.appendChild(row);

  document.body.prepend(banner);
  setTimeout(removeBanner, BANNER_DISMISS_DELAY_MS);
}

// ── Click interceptor ─────────────────────────────────────────────────────────

document.addEventListener("click", async function(event) {
  const anchor = event.target.closest("a[href]");
  if (!anchor) return;

  const href = anchor.href;
  if (!href) return;

  // Only intercept http/https links
  let parsedUrl;
  try {
    parsedUrl = new URL(href);
    if (!SAFE_SCHEMES.has(parsedUrl.protocol)) return;
  } catch {
    return;  // Malformed URL — let the browser handle it
  }

  // Hold navigation while we check the URL
  event.preventDefault();

  const threatData = await checkUrlThreat(href);

  if (!threatData) {
    // API unreachable — navigate normally so we never block the user unnecessarily
    window.location.href = href;
    return;
  }

  if (threatData.threat_type) {
    // Threat found — show inline banner and notify the background script
    showWarningBanner(threatData);

    // Tell the background script so it can show a native OS notification
    // and update the extension badge colour
    chrome.runtime.sendMessage({
      type: "THREAT_DETECTED",
      payload: threatData,
    });
  } else {
    // Safe — navigate programmatically
    window.location.href = href;
  }

}, true);  // Capture phase — intercepts before the browser handles the click
