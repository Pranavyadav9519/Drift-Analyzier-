/**
 * dashboard.js — Sentinel Zero Live Dashboard
 * Polls the local Flask API every 3 seconds and updates charts / stats.
 */

const API_BASE = "http://localhost:5050";
const STATS_POLL_INTERVAL_MS = 3000;
const PRIVACY_POLL_INTERVAL_MS = 15000;

// ── Chart setup ──────────────────────────────────────────────────────────────

const CHART_DEFAULTS = {
  responsive: true,
  plugins: { legend: { labels: { color: "#e2e8f0" } } },
  scales: {
    x: { ticks: { color: "#94a3b8" }, grid: { color: "#334155" } },
    y: { ticks: { color: "#94a3b8" }, grid: { color: "#334155" }, beginAtZero: true },
  },
};

const latencyCtx = document.getElementById("latencyChart").getContext("2d");
const latencyChart = new Chart(latencyCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "Latency (ms)",
        data: [],
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56,189,248,.12)",
        tension: 0.3,
        pointRadius: 3,
        fill: true,
      },
      {
        label: "SLA limit (200 ms)",
        data: [],
        borderColor: "#f87171",
        borderDash: [6, 3],
        pointRadius: 0,
      },
    ],
  },
  options: { ...CHART_DEFAULTS },
});

const detectionCtx = document.getElementById("detectionChart").getContext("2d");
const detectionChart = new Chart(detectionCtx, {
  type: "doughnut",
  data: {
    labels: ["Safe", "Phishing"],
    datasets: [
      {
        data: [1, 0],
        backgroundColor: ["#22c55e", "#ef4444"],
        borderColor: ["#16a34a", "#dc2626"],
        borderWidth: 2,
      },
    ],
  },
  options: {
    responsive: true,
    plugins: {
      legend: { labels: { color: "#e2e8f0" } },
    },
  },
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function el(id) {
  return document.getElementById(id);
}

function setOnline(online) {
  const dot = el("status-dot");
  dot.className = `status-dot ${online ? "online" : "offline"}`;
  dot.title = online ? "API online" : "API offline";
}

// ── Fetch & render stats ──────────────────────────────────────────────────────

async function refreshStats() {
  try {
    const resp = await fetch(`${API_BASE}/stats`);
    if (!resp.ok) throw new Error("non-200");
    const d = await resp.json();
    setOnline(true);

    el("c-total").textContent = d.request_count ?? 0;
    el("c-phishing").textContent = d.phishing_detected ?? 0;
    el("c-avg-lat").textContent = d.avg_latency_ms ?? "—";
    el("c-p95-lat").textContent = d.p95_latency_ms ?? "—";

    const slaRate = ((d.sla_compliance_rate ?? 1) * 100).toFixed(1);
    el("c-sla").textContent = `${slaRate}%`;
    el("c-sla-card").className = `card ${parseFloat(slaRate) >= 95 ? "" : "warn"}`;
    el("c-uptime").textContent = d.uptime_seconds ?? "—";

    // Latency chart
    const lats = d.latency || [];
    latencyChart.data.labels = lats.map((_, i) => i + 1);
    latencyChart.data.datasets[0].data = lats;
    latencyChart.data.datasets[1].data = lats.map(() => 200);
    latencyChart.update("none");

    // Detection doughnut
    const safe = (d.request_count ?? 0) - (d.phishing_detected ?? 0);
    detectionChart.data.datasets[0].data = [Math.max(safe, 0), d.phishing_detected ?? 0];
    detectionChart.update("none");
  } catch {
    setOnline(false);
  }
}

// ── Fetch & render privacy report ────────────────────────────────────────────

async function refreshPrivacy() {
  try {
    const resp = await fetch(`${API_BASE}/privacy-report`);
    const d = await resp.json();
    const ok = d.local_processing_only;
    el("privacy-report").innerHTML = `
      <div class="privacy-item ${ok ? "ok" : "warn"}">
        ${ok ? "✅" : "⚠️"} Local processing only: <strong>${ok ? "YES" : "NO"}</strong>
      </div>
      <div class="privacy-item ok">✅ External API calls: <strong>${d.external_calls}</strong></div>
      <div class="privacy-item ok">✅ PII protection: <strong>${d.pii_protection ? "enabled" : "disabled"}</strong></div>
      <div class="privacy-item ok">✅ Data retention: <strong>${d.data_retention}</strong></div>
    `;
  } catch {
    el("privacy-report").textContent = "⚠️ Could not load privacy report (API offline?)";
  }
}

// ── Manual URL check ──────────────────────────────────────────────────────────

el("check-btn").addEventListener("click", runCheck);
el("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

async function runCheck() {
  const url = el("url-input").value.trim();
  if (!url) return;
  const box = el("check-result");
  box.className = "check-result loading";
  box.textContent = "Analysing…";

  try {
    const resp = await fetch(`${API_BASE}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const d = await resp.json();
    const cls = d.verdict === "PHISHING" ? "phishing" : d.verdict === "SUSPICIOUS" ? "suspicious" : "safe";
    const emoji = d.verdict === "PHISHING" ? "🚫" : d.verdict === "SUSPICIOUS" ? "⚠️" : "✅";
    box.className = `check-result ${cls}`;
    box.innerHTML = `
      <div class="verdict">${emoji} <strong>${d.verdict}</strong> — Risk: ${(d.risk_score * 100).toFixed(1)}%</div>
      <div class="meta">Latency: ${d.latency_ms} ms · Model: ${d.model_used}</div>
    `;
    await refreshStats();
  } catch {
    box.className = "check-result suspicious";
    box.textContent = "⚠️ API unreachable. Make sure python app.py is running.";
  }
}

// ── Polling ───────────────────────────────────────────────────────────────────

refreshStats();
refreshPrivacy();
setInterval(refreshStats, STATS_POLL_INTERVAL_MS);
setInterval(refreshPrivacy, PRIVACY_POLL_INTERVAL_MS);
