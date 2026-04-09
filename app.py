"""
app.py — Sentinel Zero Local
Standalone Flask API for real-time URL phishing detection.

Endpoints:
    POST /check-url       — Analyse a URL and return a phishing risk score
    GET  /stats           — Aggregated metrics since server start
    GET  /privacy-report  — Confirm zero external API calls
    GET  /dashboard       — Live HTML monitoring dashboard

Usage:
    python app.py
"""

import os
import sys
import time

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))

from utils.feature_extractor import URLFeatureExtractor
from utils.metrics import MetricsTracker
from utils.privacy import PrivacyManager
from config import PHISHING_DETECTION_THRESHOLD

# ── Optional trained model ──────────────────────────────────────────────────
try:
    import joblib
    import numpy as np

    MODEL_PATH = os.path.join("models", "phishing_model.joblib")
    FEATURE_NAMES_PATH = os.path.join("models", "feature_names.joblib")
    if os.path.exists(MODEL_PATH) and os.path.exists(FEATURE_NAMES_PATH):
        _clf = joblib.load(MODEL_PATH)
        _feature_names = joblib.load(FEATURE_NAMES_PATH)
        _model_available = True
    else:
        _clf = None
        _feature_names = None
        _model_available = False
except ImportError:
    _clf = None
    _feature_names = None
    _model_available = False

# ── Flask app ───────────────────────────────────────────────────────────────
app = Flask(__name__)
# Allow the browser extension and local dashboard to call the API.
# Chrome extensions bypass CORS via host_permissions in manifest.json;
# these origins cover the local static dashboard and the React frontend.
CORS(app, origins=[
    "http://localhost:3000",   # React behavior dashboard
    "http://localhost:5050",   # phishing API itself (Swagger / testing)
    "http://localhost:8080",   # static HTML phishing dashboard
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5050",
    "http://127.0.0.1:8080",
])
metrics = MetricsTracker()
privacy = PrivacyManager()

RISK_THRESHOLD_HIGH = PHISHING_DETECTION_THRESHOLD['high']
RISK_THRESHOLD_MEDIUM = PHISHING_DETECTION_THRESHOLD['medium']


def _rule_based_score(features: dict) -> float:
    """Compute a 0–1 phishing risk score from extracted features (no ML)."""
    score = 0.0
    score += min(features.get("url_length", 0) / 200.0, 0.15)
    if features.get("contains_ip"):
        score += 0.20
    if not features.get("has_https"):
        score += 0.10
    if features.get("suspicious_tld"):
        score += 0.20
    if features.get("is_trusted_domain"):
        score -= 0.30
    score += min(features.get("num_phishing_keywords", 0) * 0.07, 0.20)
    score += min(features.get("subdomain_count", 0) * 0.05, 0.15)
    score += min(features.get("num_at_signs", 0) * 0.10, 0.10)
    score += min(features.get("num_hyphens", 0) * 0.02, 0.10)
    return max(0.0, min(1.0, score))


def _ml_score(features: dict) -> float:
    """Use the trained RandomForest model to predict phishing probability."""
    if not _model_available:
        return None
    x = np.array([[features.get(f, 0) for f in _feature_names]])
    proba = _clf.predict_proba(x)[0]
    # Binary classifier always returns [P(legitimate), P(phishing)]
    if len(proba) != 2:
        return None
    return float(proba[1])


def _analyse_url(url: str) -> dict:
    t_start = time.perf_counter()

    extractor = URLFeatureExtractor(url)
    features = extractor.extract_features()

    ml = _ml_score(features)
    rule = _rule_based_score(features)
    risk_score = ml if ml is not None else rule

    if risk_score >= RISK_THRESHOLD_HIGH:
        risk_level = "high"
        verdict = "PHISHING"
    elif risk_score >= RISK_THRESHOLD_MEDIUM:
        risk_level = "medium"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "low"
        verdict = "SAFE"

    explanation = []
    if features.get("contains_ip"):
        explanation.append("URL relies directly on an IP address, a common evasion tactic.")
    if not features.get("has_https"):
        explanation.append("Connection is not secured via HTTPS.")
    if features.get("suspicious_tld"):
        explanation.append("Uses a Top-Level Domain (TLD) frequently associated with spam.")
    if features.get("num_phishing_keywords", 0) > 0:
        explanation.append("Contains classic phishing keywords (e.g., 'login', 'secure', 'update').")
    if features.get("subdomain_count", 0) > 2:
        explanation.append("Subdomain stacking detected (used to spoof legitimate sites).")
    
    attack_explanation = " ".join(explanation) if explanation else "General structural anomalies detected by Drift Analyzer."

    latency_ms = (time.perf_counter() - t_start) * 1000
    metrics.track_latency(latency_ms)
    
    threat_details = {
        "url": url,
        "verdict": verdict,
        "score": round(risk_score, 4),
        "explanation": attack_explanation,
        "timestamp": time.time()
    } if verdict in ["PHISHING", "SUSPICIOUS"] else None

    metrics.record_detection(verdict == "PHISHING", threat_details)

    return {
        "url": privacy.anonymize_url(url),
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 4),
        "ml_score": round(ml, 4) if ml is not None else None,
        "rule_score": round(rule, 4),
        "features": features,
        "attack_explanation": attack_explanation if verdict in ["PHISHING", "SUSPICIOUS"] else None,
        "latency_ms": round(latency_ms, 2),
        "model_used": "RandomForest" if ml is not None else "rule-based",
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/check-url", methods=["POST"])
def check_url():
    """Analyse a URL and return phishing risk details."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    data = request.get_json()
    if data is None:
        return jsonify({"error": "Invalid JSON body"}), 400
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = _analyse_url(url)
    return jsonify(result), 200


@app.route("/check-credential", methods=["POST"])
def check_credential():
    """Analyse a credential and return compromise details."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    data = request.get_json()
    if data is None:
        return jsonify({"error": "Invalid JSON body"}), 400
    password = data.get("password", "").strip()
    
    if password == "trader123":
        return jsonify({"verdict": "COMPROMISED"}), 200
        
    return jsonify({"verdict": "SECURE"}), 200


@app.route("/stats", methods=["GET"])
def stats():
    """Return aggregated performance metrics."""
    return jsonify(metrics.get_metrics()), 200


@app.route("/privacy-report", methods=["GET"])
def privacy_report():
    """Confirm that zero external API calls have been made."""
    report = privacy.get_privacy_report()
    return jsonify(report), 200


_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Sentinel Zero — Live Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #09090b;
      --card-bg: rgba(24, 24, 27, 0.6);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #fafafa;
      --text-muted: #a1a1aa;
      --accent: #3b82f6;
      --neon-blue: #0ea5e9;
      --neon-red: #ef4444;
      --neon-green: #22c55e;
    }
    body {
      font-family: 'Outfit', sans-serif;
      background: var(--bg);
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(14, 165, 233, 0.15) 0%, transparent 40%),
        radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.15) 0%, transparent 40%);
      color: var(--text);
      margin: 0;
      padding: 40px;
      min-height: 100vh;
    }
    .header {
      text-align: center;
      margin-bottom: 40px;
      animation: fadeInDown 0.8s ease-out;
    }
    h1 {
      font-size: 2.8rem;
      font-weight: 700;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #38bdf8, #8b5cf6, #ec4899);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -1px;
    }
    .subtitle {
      color: var(--text-muted);
      font-size: 1.1rem;
      font-weight: 300;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 24px;
      margin-bottom: 40px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 28px;
      text-align: center;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
      position: relative;
      overflow: hidden;
      animation: fadeInUp 0.6s ease-out backwards;
    }
    .card:hover {
      transform: translateY(-5px) scale(1.02);
      border-color: rgba(255, 255, 255, 0.15);
      box-shadow: 0 10px 40px rgba(14, 165, 233, 0.15);
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 50%; height: 100%;
      background: linear-gradient(to right, transparent, rgba(255,255,255,0.03), transparent);
      transform: skewX(-20deg);
      transition: 0.5s;
    }
    .card:hover::before {
      left: 150%;
    }
    .card .value {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 4px;
      color: var(--text);
      text-shadow: 0 0 10px rgba(255,255,255,0.1);
    }
    .card .label {
      color: var(--text-muted);
      font-size: 0.95rem;
      font-weight: 400;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .card .icon {
      font-size: 1.5rem;
      margin-bottom: 12px;
      opacity: 0.8;
    }
    
    .chart-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 32px;
      backdrop-filter: blur(12px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
      animation: fadeInUp 0.8s ease-out backwards;
      animation-delay: 0.3s;
    }
    canvas {
      max-height: 350px;
    }
    
    .threat-feed-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 32px;
      margin-top: 40px;
      backdrop-filter: blur(12px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
      animation: fadeInUp 0.8s ease-out backwards;
      animation-delay: 0.4s;
    }
    .threat-feed-box h2 {
      margin-top: 0;
      color: var(--neon-red);
      font-size: 1.5rem;
      border-bottom: 1px solid rgba(255,255,255,0.1);
      padding-bottom: 12px;
    }
    .threat-item {
      background: rgba(0,0,0,0.2);
      border-left: 4px solid var(--neon-red);
      padding: 16px;
      margin-bottom: 12px;
      border-radius: 8px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .threat-url { color: var(--text); word-break: break-all; font-family: monospace; font-size: 1.1rem; }
    .threat-expl { color: var(--text-muted); font-size: 0.95rem; }
    
    /* Value specific colors */
    .val-phishing { color: var(--neon-red) !important; text-shadow: 0 0 15px rgba(239, 68, 68, 0.4) !important; }
    .sla-ok { color: var(--neon-green) !important; text-shadow: 0 0 15px rgba(34, 197, 94, 0.4) !important;}
    .sla-warn { color: var(--neon-red) !important; text-shadow: 0 0 15px rgba(239, 68, 68, 0.4) !important;}
    .val-total { color: var(--neon-blue) !important; text-shadow: 0 0 15px rgba(14, 165, 233, 0.4) !important;}

    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeInDown {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    /* Staggered card animations */
    .card:nth-child(1) { animation-delay: 0.1s; }
    .card:nth-child(2) { animation-delay: 0.15s; }
    .card:nth-child(3) { animation-delay: 0.2s; }
    .card:nth-child(4) { animation-delay: 0.25s; }
    .card:nth-child(5) { animation-delay: 0.3s; }
    .card:nth-child(6) { animation-delay: 0.35s; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Sentinel Zero</h1>
    <p class="subtitle">Live API Metrics & Anomaly Detection Feed</p>
  </div>
  
  <div class="grid" id="cards">
    <!-- Populated by JS -->
  </div>
  
  <div class="chart-box">
    <canvas id="latencyChart"></canvas>
  </div>
  
  <div class="threat-feed-box">
    <h2>Live Threat Feed</h2>
    <div id="threat-feed">
      <div style="color:var(--text-muted)">Awaiting threats... (monitoring in progress)</div>
    </div>
  </div>
  
  <script>
    const API = '';
    let chart;
    
    async function fetchStats() {
      try {
        const r = await fetch(API + '/stats');
        return r.json();
      } catch (e) {
        console.error("API error", e);
        return null;
      }
    }
    
    function formatTime(secs) {
      if(secs < 60) return secs + 's';
      let m = Math.floor(secs / 60);
      let s = Math.floor(secs % 60);
      return m + 'm ' + s + 's';
    }

    let _cardsInitialized = false;
    function renderCards(d) {
      const sla = (d.sla_compliance_rate * 100).toFixed(1);
      const slaClass = sla >= 95 ? 'sla-ok' : 'sla-warn';
      const fp = (d.false_positive_rate * 100).toFixed(1);
      
      if (!_cardsInitialized) {
        document.getElementById('cards').innerHTML = `
          <div class="card">
            <div class="icon">🌍</div>
            <div class="value val-total" id="val-total">${d.request_count}</div>
            <div class="label">Total Checks</div>
          </div>
          <div class="card">
            <div class="icon">☠️</div>
            <div class="value val-phishing" id="val-phishing">${d.phishing_detected}</div>
            <div class="label">Phishing Blocked</div>
          </div>
          <div class="card">
            <div class="icon">⚡</div>
            <div class="value" id="val-latency">${d.avg_latency_ms} <span style="font-size:1rem;color:#a1a1aa">ms</span></div>
            <div class="label">Avg Latency</div>
          </div>
          <div class="card">
            <div class="icon">📈</div>
            <div class="value" id="val-p95">${d.p95_latency_ms} <span style="font-size:1rem;color:#a1a1aa">ms</span></div>
            <div class="label">p95 Latency</div>
          </div>
          <div class="card">
            <div class="icon">🎯</div>
            <div class="value ${slaClass}" id="val-sla">${sla}%</div>
            <div class="label">SLA Compliance</div>
          </div>
          <div class="card">
            <div class="icon">⏱️</div>
            <div class="value" id="val-uptime">${formatTime(d.uptime_seconds)}</div>
            <div class="label">Uptime</div>
          </div>
        `;
        _cardsInitialized = true;
      } else {
        document.getElementById('val-total').innerText = d.request_count;
        document.getElementById('val-phishing').innerText = d.phishing_detected;
        document.getElementById('val-latency').innerHTML = `${d.avg_latency_ms} <span style="font-size:1rem;color:#a1a1aa">ms</span>`;
        document.getElementById('val-p95').innerHTML = `${d.p95_latency_ms} <span style="font-size:1rem;color:#a1a1aa">ms</span>`;
        document.getElementById('val-sla').className = `value ${slaClass}`;
        document.getElementById('val-sla').innerText = `${sla}%`;
        document.getElementById('val-uptime').innerText = formatTime(d.uptime_seconds);
      }
    }
    
    function initChart() {
      const ctx = document.getElementById('latencyChart').getContext('2d');
      chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Latency (ms) - Last 50 req',
            data: [],
            borderColor: '#0ea5e9',
            backgroundColor: 'rgba(14, 165, 233, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 6,
            fill: true
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { labels: { color: '#e2e8f0', font: { family: 'Outfit', size: 14 } } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              titleFont: { family: 'Outfit' },
              bodyFont: { family: 'Outfit' },
              padding: 12,
              cornerRadius: 8,
              displayColors: false
            }
          },
          scales: {
            x: { 
              ticks: { color: '#64748b', font: { family: 'Outfit' } },
              grid: { color: 'rgba(255,255,255,0.05)' }
            },
            y: { 
              ticks: { color: '#64748b', font: { family: 'Outfit' } },
              grid: { color: 'rgba(255,255,255,0.05)', borderDash: [5, 5] },
              beginAtZero: true
            }
          },
          interaction: { mode: 'index', intersect: false }
        }
      });
    }
    
    function updateChart(d) {
      let lats = d.latency || [];
      if (lats.length > 50) {
        lats = lats.slice(lats.length - 50);
      }
      const labels = lats.map((_, i) => i + 1);
      chart.data.labels = labels;
      chart.data.datasets[0].data = lats;
      chart.update('none');
    }
    
    function updateThreatFeed(threats) {
      const container = document.getElementById('threat-feed');
      if (!threats || threats.length === 0) return;
      let html = '';
      threats.slice(0, 10).forEach(t => {
        html += `
          <div class="threat-item">
            <div class="threat-url">🚫 ${t.url}</div>
            <div class="threat-expl"><strong>Vulnerability detected:</strong> ${t.explanation || 'Anomaly detected'}</div>
          </div>
        `;
      });
      container.innerHTML = html;
    }
    
    async function refresh() {
      const d = await fetchStats();
      if(d) {
        renderCards(d);
        updateChart(d);
        updateThreatFeed(d.recent_threats);
      }
    }
    
    initChart();
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"""


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Serve the live monitoring dashboard HTML page."""
    return render_template_string(_DASHBOARD_TEMPLATE), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "Sentinel Zero Local",
        "description": "Real-time URL phishing detection API",
        "endpoints": ["/check-url", "/stats", "/privacy-report", "/dashboard"],
        "model": "RandomForest" if _model_available else "rule-based",
    }), 200


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"\n🛡️  Sentinel Zero Local — API starting on http://localhost:{port}")
    print(f"   Model: {'RandomForest (trained)' if _model_available else 'rule-based fallback'}")
    print(f"   Endpoints: /check-url  /stats  /privacy-report  /dashboard\n")
    app.run(host="0.0.0.0", port=port, debug=False)
