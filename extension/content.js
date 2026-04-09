/**
 * content.js — Drift Analyzer URL Interceptor + Credential Protection
 *
 * 1. Intercepts all link clicks — checks URL against phishing API before navigation.
 * 2. Intercepts all login form submissions — if the CURRENT PAGE is phishing/suspicious,
 *    blocks the submit and shows an OTP protective overlay.
 *
 * Privacy: only URLs are sent to localhost — nothing leaves your device.
 */

const PHISHING_API = "http://localhost:5050";

// Cache recently checked URLs — Map<url, threatData>, max 200 entries.
const URL_CACHE = new Map();
const CACHE_MAX_SIZE = 200;

const SAFE_SCHEMES = new Set(["http:", "https:"]);
const BANNER_DISMISS_DELAY_MS = 10000;
const BANNER_ELEMENT_ID = "drift-analyzer-banner";

// ── Cache helpers ──────────────────────────────────────────────────────────────

function cacheGet(url) {
  return URL_CACHE.get(url) || null;
}

function cacheSet(url, threatData) {
  if (URL_CACHE.size >= CACHE_MAX_SIZE) {
    const oldestKey = URL_CACHE.keys().next().value;
    URL_CACHE.delete(oldestKey);
  }
  URL_CACHE.set(url, threatData);
}

// ── API call ───────────────────────────────────────────────────────────────────

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

    // Update session stats in chrome.storage for the popup display
    chrome.storage.local.get("drift_stats", function(result) {
      const stats = result.drift_stats || { total: 0, threats: 0 };
      stats.total += 1;
      if (threatData.threat_type) stats.threats += 1;
      chrome.storage.local.set({ drift_stats: stats });
    });

    return threatData;

  } catch {
    return null; // API unreachable — fail open
  }
}

// ── Warning banner ─────────────────────────────────────────────────────────────

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

  const topRemedies = (threatData.remedy_steps || []).slice(0, 2);

  const banner = document.createElement("div");
  banner.id = BANNER_ELEMENT_ID;
  banner.style.cssText = [
    "position: fixed", "top: 0", "left: 0", "right: 0",
    "z-index: 2147483647",
    "background: " + backgroundColor,
    "color: #fff", "font-family: system-ui, sans-serif",
    "padding: 12px 16px",
    "box-shadow: 0 2px 12px rgba(0,0,0,.5)",
    "font-size: 13px", "line-height: 1.5",
  ].join("; ");

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
      li.textContent = step;
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

// ── Click interceptor ──────────────────────────────────────────────────────────

document.addEventListener("click", async function(event) {
  const anchor = event.target.closest("a[href]");
  if (!anchor) return;

  const href = anchor.href;
  if (!href) return;

  let parsedUrl;
  try {
    parsedUrl = new URL(href);
    if (!SAFE_SCHEMES.has(parsedUrl.protocol)) return;
  } catch {
    return;
  }

  event.preventDefault();

  const threatData = await checkUrlThreat(href);

  if (!threatData) {
    window.location.href = href;
    return;
  }

  if (threatData.threat_type) {
    showWarningBanner(threatData);
    chrome.runtime.sendMessage({
      type: "THREAT_DETECTED",
      payload: threatData,
    });
  } else {
    window.location.href = href;
  }

}, true);

// ── Credential Protection ──────────────────────────────────────────────────────
//
// When a login form is submitted, we check the CURRENT PAGE URL — not the
// password value. If the page itself is flagged PHISHING or SUSPICIOUS, the
// user's credentials are already at risk. We block the submission and show
// an OTP protective overlay to simulate secure account recovery.

function reportCredentialCompromise(url) {
  // Log a compromised-credential event to the dashboard
  fetch(PHISHING_API + "/check-credential", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: "__phishing_page__", url: url }),
  }).catch(function() {});
}

function showOTPIntervention(threatData) {
  const existing = document.getElementById("drift-analyzer-otp-overlay");
  if (existing) existing.remove();

  const isPhishing = (threatData && threatData.verdict || "").toUpperCase() === "PHISHING";
  const riskPct = Math.round((threatData && threatData.risk_score || 0.9) * 100);

  // ── Overlay container ──
  const overlay = document.createElement("div");
  overlay.id = "drift-analyzer-otp-overlay";
  overlay.style.cssText = [
    "position:fixed", "top:0", "left:0", "width:100vw", "height:100vh",
    "background:rgba(8,12,24,0.93)", "backdrop-filter:blur(10px)",
    "-webkit-backdrop-filter:blur(10px)", "z-index:2147483647",
    "display:flex", "justify-content:center", "align-items:center",
    "font-family:'Inter',system-ui,sans-serif",
  ].join(";");

  // ── Card ──
  const card = document.createElement("div");
  card.style.cssText = [
    "background:#0f172a", "padding:40px", "border-radius:20px", "width:420px",
    "max-width:94vw",
    "box-shadow:0 32px 64px rgba(0,0,0,0.8),0 0 0 1px rgba(239,68,68,0.25)",
    "text-align:center", "border:1px solid #1e293b",
    "animation:driftPop 0.3s cubic-bezier(0.34,1.56,0.64,1) both",
  ].join(";");

  // Keyframe style
  const style = document.createElement("style");
  style.textContent = "@keyframes driftPop{from{transform:scale(0.88) translateY(20px);opacity:0}to{transform:scale(1) translateY(0);opacity:1}}";
  document.head.appendChild(style);

  // ── Icon ──
  const iconWrap = document.createElement("div");
  iconWrap.id = "drift-icon-wrap";
  iconWrap.style.cssText = "background:rgba(239,68,68,0.12);width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;border:2px solid rgba(239,68,68,0.3);transition:all 0.4s;";
  const iconEmoji = document.createElement("span");
  iconEmoji.style.fontSize = "34px";
  iconEmoji.textContent = "\uD83D\uDEA8"; // 🚨
  iconWrap.appendChild(iconEmoji);

  // ── Title ──
  const title = document.createElement("h2");
  title.id = "drift-otp-title";
  title.style.cssText = "color:#f8fafc;margin:0 0 10px;font-size:21px;font-weight:700;letter-spacing:-0.3px;";
  title.textContent = "Credential Risk Detected";

  // ── Risk badge ──
  const badge = document.createElement("div");
  badge.style.cssText = "display:inline-block;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.35);color:#ef4444;font-size:11.5px;font-weight:700;padding:4px 12px;border-radius:100px;margin-bottom:18px;letter-spacing:0.5px;";
  badge.textContent = (isPhishing ? "PHISHING SITE" : "SUSPICIOUS SITE") + " \u2014 " + riskPct + "% RISK";

  // ── Message ──
  const msg = document.createElement("p");
  msg.id = "drift-otp-msg";
  msg.style.cssText = "color:#94a3b8;font-size:14px;line-height:1.65;margin:0 0 26px;";
  const siteType = isPhishing ? "phishing site" : "suspicious site";
  const strong = document.createElement("strong");
  strong.style.color = "#ef4444";
  strong.textContent = siteType;
  msg.appendChild(document.createTextNode("Drift Analyzer detected this is a "));
  msg.appendChild(strong);
  msg.appendChild(document.createTextNode(".\n\nYour credentials are at risk. Login blocked. Verify your identity to receive secure recovery steps."));
  msg.style.whiteSpace = "pre-wrap";

  // ── OTP boxes ──
  const otpRow = document.createElement("div");
  otpRow.id = "otp-inputs";
  otpRow.style.cssText = "display:flex;gap:10px;justify-content:center;margin-bottom:20px;";
  const inputs = [];
  [0, 1, 2, 3].forEach(function(i) {
    const inp = document.createElement("input");
    inp.type = "text";
    inp.inputMode = "numeric";
    inp.maxLength = 1;
    inp.setAttribute("data-idx", i);
    inp.style.cssText = "width:54px;height:62px;background:#1e293b;border:2px solid #334155;border-radius:12px;color:#f8fafc;font-size:28px;text-align:center;font-weight:700;outline:none;transition:border-color 0.2s,box-shadow 0.2s;";
    inputs.push(inp);
    otpRow.appendChild(inp);
  });

  // ── Error ──
  const errMsg = document.createElement("p");
  errMsg.id = "drift-otp-error";
  errMsg.style.cssText = "color:#ef4444;font-size:13px;margin:-6px 0 14px;display:none;font-weight:500;";
  errMsg.textContent = "Incorrect code. Hint: it was sent to your device.";

  // ── Button ──
  const btn = document.createElement("button");
  btn.id = "drift-verify-btn";
  btn.style.cssText = "width:100%;background:linear-gradient(135deg,#3b82f6,#6366f1);color:white;border:none;padding:15px;border-radius:12px;font-weight:700;font-size:15px;cursor:pointer;transition:opacity 0.2s;letter-spacing:0.3px;";
  btn.textContent = "\uD83D\uDD12 Verify & Secure Account"; // 🔒
  btn.addEventListener("mouseenter", function() { btn.style.opacity = "0.88"; });
  btn.addEventListener("mouseleave", function() { btn.style.opacity = "1"; });

  // ── Footer ──
  const footer = document.createElement("p");
  footer.style.cssText = "color:#3f5275;font-size:11px;margin-top:16px;";
  footer.textContent = "Protected by Drift Analyzer \u00B7 Never share this code";

  // Assemble card
  card.appendChild(iconWrap);
  card.appendChild(title);
  card.appendChild(badge);
  card.appendChild(msg);
  card.appendChild(otpRow);
  card.appendChild(errMsg);
  card.appendChild(btn);
  card.appendChild(footer);
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  // ── OTP interaction ──
  inputs.forEach(function(inp, idx) {
    inp.addEventListener("focus", function() {
      inp.style.borderColor = "#3b82f6";
      inp.style.boxShadow = "0 0 0 3px rgba(59,130,246,0.2)";
    });
    inp.addEventListener("blur", function() {
      inp.style.borderColor = "#334155";
      inp.style.boxShadow = "none";
    });
    inp.addEventListener("input", function() {
      inp.value = inp.value.replace(/\D/g, "").slice(-1);
      if (inp.value && idx < inputs.length - 1) {
        inputs[idx + 1].focus();
      }
    });
    inp.addEventListener("keydown", function(e) {
      if (e.key === "Backspace" && !inp.value && idx > 0) {
        inputs[idx - 1].focus();
      }
      if (e.key === "Enter") btn.click();
    });
  });

  // ── Verify click ──
  btn.addEventListener("click", function() {
    const code = inputs.map(function(i) { return i.value; }).join("");
    if (code === "1234") {
      // Success
      iconEmoji.textContent = "\u2705"; // ✅
      iconWrap.style.background = "rgba(34,197,94,0.12)";
      iconWrap.style.borderColor = "rgba(34,197,94,0.3)";
      title.textContent = "\u2705 Identity Verified";
      msg.style.whiteSpace = "normal";
      msg.innerHTML = "Your identity has been confirmed.<br/><br/><strong style='color:#22c55e'>Redirecting to a secure password reset portal&hellip;</strong>";
      otpRow.style.display = "none";
      btn.style.display = "none";
      errMsg.style.display = "none";
      badge.style.background = "rgba(34,197,94,0.1)";
      badge.style.borderColor = "rgba(34,197,94,0.35)";
      badge.style.color = "#22c55e";
      badge.textContent = "ACCOUNT SECURED";
      setTimeout(function() { overlay.remove(); }, 2800);
    } else {
      // Wrong code
      errMsg.style.display = "block";
      inputs.forEach(function(i) {
        i.value = "";
        i.style.borderColor = "#ef4444";
        i.style.boxShadow = "0 0 0 3px rgba(239,68,68,0.2)";
        setTimeout(function() {
          i.style.borderColor = "#334155";
          i.style.boxShadow = "none";
        }, 700);
      });
      inputs[0].focus();
    }
  });

  setTimeout(function() { inputs[0].focus(); }, 120);
}

// ── Form submit interceptor ────────────────────────────────────────────────────
//
// Fires on any form with a password field. Checks the CURRENT PAGE URL:
// - If PHISHING or SUSPICIOUS → show credential warning + OTP overlay
// - If SAFE → allow the form to submit normally

document.addEventListener("submit", async function(event) {
  const form = event.target;
  const passwordInput = form.querySelector('input[type="password"]');
  if (!passwordInput || !passwordInput.value) return;

  event.preventDefault();
  event.stopImmediatePropagation();

  const currentUrl = window.location.href;
  const threatData = await checkUrlThreat(currentUrl);

  const isRiskyPage = threatData &&
    (threatData.verdict === "PHISHING" || threatData.verdict === "SUSPICIOUS");

  if (isRiskyPage) {
    reportCredentialCompromise(currentUrl);
    try {
      chrome.runtime.sendMessage({
        type: "THREAT_DETECTED",
        payload: Object.assign({}, threatData, { threat_type: "compromised_credential" }),
      });
    } catch (ignored) {}
    showOTPIntervention(threatData);
  } else {
    form.submit();
  }

}, true);
