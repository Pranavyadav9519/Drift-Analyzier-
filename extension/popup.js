/**
 * popup.js — Drift Analyzer Extension Popup
 */

const API_BASE = "http://localhost:5050";

const urlInput = document.getElementById("url-input");
const checkBtn = document.getElementById("check-btn");
const resultBox = document.getElementById("result-box");

const statChecks = document.getElementById("stat-checks");
const statPhishing = document.getElementById("stat-phishing");
const statSuspicious = document.getElementById("stat-suspicious");
const statLatency = document.getElementById("stat-latency");

// ── Check URL ────────────────────────────────────────────────────────────────

checkBtn.addEventListener("click", runCheck);
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

async function runCheck() {
  const url = urlInput.value.trim();
  if (!url) return;
  setResult("loading");
  try {
    const resp = await fetch(`${API_BASE}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (resp.status === 403) {
      setResult("blocked");
      return;
    }
    if (!resp.ok) throw new Error("API error");
    const data = await resp.json();
    setResult("success", data);
  } catch {
    setResult("error");
  }
}

function setResult(state, data) {
  resultBox.classList.remove("hidden", "safe", "suspicious", "phishing", "loading-state");
  if (state === "loading") {
    resultBox.classList.add("loading-state");
    resultBox.textContent = "Analysing…";
    return;
  }
  if (state === "error") {
    resultBox.classList.add("suspicious");
    resultBox.textContent = "⚠️ Could not reach Drift Analyzer API. Is it running?";
    return;
  }
  if (state === "blocked") {
    resultBox.classList.add("phishing");
    resultBox.textContent = "🚫 Check blocked by server (high-risk session). Please log in again.";
    return;
  }
  const { verdict, risk_score, latency_ms, attack_explanation } = data;
  const cssClass = verdict === "PHISHING" ? "phishing" : verdict === "SUSPICIOUS" ? "suspicious" : "safe";
  const emoji = verdict === "PHISHING" ? "🚫" : verdict === "SUSPICIOUS" ? "⚠️" : "✅";
  resultBox.classList.add(cssClass);
  resultBox.innerHTML = `
    <div class="verdict-row">
      <span class="verdict-emoji">${emoji}</span>
      <span class="verdict-text">${verdict}</span>
    </div>
    <div class="score-row">Risk score: <strong>${(risk_score * 100).toFixed(1)}%</strong></div>
    ${attack_explanation ? `<div style="font-size: 11px; margin-top:4px; color:rgba(255,255,255,0.7);">${attack_explanation}</div>` : ''}
    <div class="latency-row">Latency: ${latency_ms} ms</div>
  `;
}

// ── Load Stats ────────────────────────────────────────────────────────────────

async function loadStats() {
  // Load session-level stats from extension storage
  chrome.storage.local.get("sz_stats", (res) => {
    const s = res.sz_stats;
    if (!s) return;
    statChecks.textContent = s.checks ?? 0;
    statPhishing.textContent = s.phishing ?? 0;
    statSuspicious.textContent = s.suspicious ?? 0;
  });
  // Load server-level avg latency
  try {
    const resp = await fetch(`${API_BASE}/stats`);
    const d = await resp.json();
    statLatency.textContent = d.avg_latency_ms ? `${d.avg_latency_ms} ms` : "—";
  } catch {
    statLatency.textContent = "—";
  }
}

loadStats();
