/**
 * content.js — Drift Analyzer Extension
 * Intercepts link clicks and quietly checks URLs against the Drift Analyzer local API.
 */

const API_BASE = "http://localhost:5050";
const CHECKED_CACHE = new Map(); // url -> verdict
const CACHE_MAX_SIZE = 200;
const HIGH_RISK_VERDICTS = new Set(["PHISHING", "SUSPICIOUS"]);

// Schemes that must never be sent to the API or followed for analysis
const SAFE_TO_ANALYSE_SCHEMES = new Set(["http:", "https:"]);

/** Banner IDs to avoid duplicates */
const BANNER_AUTO_DISMISS_MS = 10000;
const BANNER_ID = "drift-analyzer-intervention";

function removeBanner() {
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showIntervention(verdict, url, explanation) {
  removeBanner();
  
  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.style.cssText = `
    position: fixed; bottom: 20px; right: 20px; z-index: 2147483647;
    background: rgba(15, 23, 42, 0.95); color: #f8fafc; font-family: 'Inter', system-ui, sans-serif;
    padding: 20px 24px; display: flex; flex-direction: column; gap: 12px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5); font-size: 14px;
    border-left: 4px solid #3b82f6; border-radius: 12px;
    backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
    animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    max-width: 380px;
    line-height: 1.5;
  `;
  
  banner.innerHTML = `
    <style>
      @keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    </style>
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <strong style="color:#38bdf8; font-size:16px;">Drift Analyzer</strong>
      <span style="background:rgba(59,130,246,0.2); color:#93c5fd; padding:4px 8px; border-radius:12px; font-size:11px; font-weight:600;">Threat Neutralized</span>
    </div>
    <div style="color:#cbd5e1; font-size:13.5px;">
      Navigation to this site was quietly intercepted. Your data remains secure.
    </div>
    <div style="background:rgba(0,0,0,0.3); padding:12px; border-radius:8px; font-size:12.5px; color:#94a3b8; margin-top:4px;">
      <strong style="color:#e2e8f0; font-size:13px; display:block; margin-bottom:4px;">Vulnerability Analysis:</strong>
      ${explanation || 'Suspicious structural patterns were identified within the URL anatomy.'}
    </div>
    <button id="sz-dismiss" style="margin-top:8px; background:#3b82f6; border:none; color:#fff; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:600; transition:0.2s;">
      Acknowledge & Close
    </button>
  `;
  
  document.body.appendChild(banner);
  document.getElementById("sz-dismiss").addEventListener("click", () => {
    banner.style.transform = 'translateX(120%)';
    banner.style.opacity = '0';
    setTimeout(removeBanner, 400);
  });
  
  setTimeout(() => {
    if(document.getElementById(BANNER_ID)) {
      banner.style.transform = 'translateX(120%)';
      banner.style.opacity = '0';
      setTimeout(removeBanner, 400);
    }
  }, BANNER_AUTO_DISMISS_MS);
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
      stats.last_check = { url: data.url, verdict: data.verdict, score: data.risk_score, explanation: data.attack_explanation };
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
      return; // malformed URL — allow navigation
    }

    // Prevent navigation immediately so we can check the URL first
    event.preventDefault();

    const result = await checkUrl(href);
    if (!result) {
      // API unreachable — navigate as normal
      window.location.href = href;
      return;
    }
    if (HIGH_RISK_VERDICTS.has(result.verdict)) {
      showIntervention(result.verdict, href, result.attack_explanation);
      // Do NOT navigate — intervention toast is shown instead
    } else {
      // SAFE verdict — navigate programmatically
      window.location.href = href;
    }
  },
  true // capture phase so we intercept before navigation
);

async function checkCredential(password) {
  try {
    const resp = await fetch(`${API_BASE}/check-credential`, {
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
        // In a real flow, this would redirect. We'll simply let the user know for the demo.
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
  
  // Pause form submission while checking credential
  event.preventDefault();

  const isCompromised = await checkCredential(password);
  
  if (isCompromised) {
    showOTPIntervention(form);
  } else {
    // If safe, programmatically submit the form (bypassing the listener)
    form.submit();
  }
}, true);
