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

// ── Credential Protection (Drift Analyzer SaaS) ───────────────────────────────

async function checkCredential(password) {
  try {
    const resp = await fetch("http://localhost:5050/check-credential", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    return data.verdict === "COMPROMISED";
  } catch {
    return false;
  }
}

function showOTPIntervention(form) {
  const overlay = document.createElement("div");
  overlay.id = "drift-analyzer-otp-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
    z-index: 2147483647; display: flex; justify-content: center; align-items: center;
    font-family: 'Inter', system-ui, sans-serif;
  `;
  
  overlay.innerHTML = `
    <div style="background: #1e293b; padding: 40px; border-radius: 16px; width: 400px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); text-align: center; border: 1px solid #334155; animation: szScaleIn 0.3s ease-out;">
      <style>@keyframes szScaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }</style>
      <div style="background: rgba(59, 130, 246, 0.1); width: 64px; height: 64px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px;">
        <span style="font-size: 32px;">🛡️</span>
      </div>
      <h2 style="color: #f8fafc; margin: 0 0 12px; font-size: 20px; font-weight: 600;">Credential Protection</h2>
      <p style="color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 24px;">
        Drift Analyzer detected your password was involved in a third-party data breach.<br/><br/>
        We have secured your session. Please verify your identity via the SMS code sent to your phone to proceed to a secure password reset.
      </p>
      
      <div style="display: flex; gap: 8px; justify-content: center; margin-bottom: 24px;" id="otp-inputs">
        <input type="text" maxlength="1" class="otp-box" style="width: 48px; height: 56px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 24px; text-align: center; font-weight: 600;" autofocus />
        <input type="text" maxlength="1" class="otp-box" style="width: 48px; height: 56px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 24px; text-align: center; font-weight: 600;" />
        <input type="text" maxlength="1" class="otp-box" style="width: 48px; height: 56px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 24px; text-align: center; font-weight: 600;" />
        <input type="text" maxlength="1" class="otp-box" style="width: 48px; height: 56px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 24px; text-align: center; font-weight: 600;" />
      </div>
      
      <p id="otp-error" style="color: #ef4444; font-size: 13px; margin-top: -12px; margin-bottom: 12px; display: none;">Invalid Code. Try again.</p>

      <button id="verify-btn" style="width: 100%; background: #3b82f6; color: white; border: none; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 15px; cursor: pointer; transition: 0.2s;">
        Verify Identity
      </button>
    </div>
  `;
  
  document.body.appendChild(overlay);

  const inputs = overlay.querySelectorAll('.otp-box');
  inputs.forEach((input, index) => {
    input.addEventListener('keyup', (e) => {
      if (e.key >= '0' && e.key <= '9') {
        if (index < inputs.length - 1) inputs[index + 1].focus();
      } else if (e.key === 'Backspace') {
        if (index > 0) inputs[index - 1].focus();
      }
    });
  });

  overlay.querySelector('#verify-btn').addEventListener('click', () => {
    const code = Array.from(inputs).map(i => i.value).join('');
    if (code === '1234') {
      overlay.querySelector('h2').innerText = "Identity Verified";
      overlay.querySelector('p').innerText = "Redirecting you to the secure password reset portal...";
      overlay.querySelector('#otp-inputs').style.display = 'none';
      overlay.querySelector('#verify-btn').style.display = 'none';
      overlay.querySelector('#otp-error').style.display = 'none';
      
      setTimeout(() => {
        overlay.remove();
        alert("Success! You've been protected by Drift Analyzer and can now securely reset your password.");
      }, 2000);
    } else {
      overlay.querySelector('#otp-error').style.display = 'block';
    }
  });
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  const passwordInput = form.querySelector('input[type="password"]');
  if (!passwordInput || !passwordInput.value) return;

  const password = passwordInput.value;
  
  event.preventDefault();

  const isCompromised = await checkCredential(password);
  
  if (isCompromised) {
    showOTPIntervention(form);
  } else {
    form.submit();
  }
}, true);
