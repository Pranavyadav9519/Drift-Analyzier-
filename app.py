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

    latency_ms = (time.perf_counter() - t_start) * 1000
    metrics.track_latency(latency_ms)
    metrics.record_detection(verdict == "PHISHING")

    return {
        "url": privacy.anonymize_url(url),
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 4),
        "ml_score": round(ml, 4) if ml is not None else None,
        "rule_score": round(rule, 4),
        "features": features,
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
  <style>
    body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;}
    h1{font-size:1.8rem;margin-bottom:4px;}
    .subtitle{color:#94a3b8;margin-bottom:24px;}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px;}
    .card{background:#1e293b;border-radius:12px;padding:20px;text-align:center;}
    .card .value{font-size:2rem;font-weight:700;color:#38bdf8;}
    .card .label{color:#94a3b8;font-size:.85rem;margin-top:4px;}
    canvas{max-height:260px;}
    .chart-box{background:#1e293b;border-radius:12px;padding:20px;}
    .sla-ok{color:#4ade80;} .sla-warn{color:#f87171;}
  </style>
</head>
<body>
  <h1>🛡️ Sentinel Zero — Local Dashboard</h1>
  <p class="subtitle">Real-time phishing detection metrics · 100% local processing</p>
  <div class="grid" id="cards"></div>
  <div class="chart-box"><canvas id="latencyChart"></canvas></div>
  <script>
    const API = '';
    let latencyData = [];
    let chart;
    async function fetchStats(){
      const r = await fetch(API+'/stats');
      return r.json();
    }
    function renderCards(d){
      const sla = (d.sla_compliance_rate*100).toFixed(1);
      const slaClass = sla >= 95 ? 'sla-ok' : 'sla-warn';
      document.getElementById('cards').innerHTML = `
        <div class="card"><div class="value">${d.request_count}</div><div class="label">Total Checks</div></div>
        <div class="card"><div class="value" style="color:#f87171">${d.phishing_detected}</div><div class="label">Phishing Detected</div></div>
        <div class="card"><div class="value">${d.avg_latency_ms} ms</div><div class="label">Avg Latency</div></div>
        <div class="card"><div class="value">${d.p95_latency_ms} ms</div><div class="label">p95 Latency</div></div>
        <div class="card"><div class="value ${slaClass}">${sla}%</div><div class="label">SLA Compliance (&lt;200ms)</div></div>
        <div class="card"><div class="value">${d.uptime_seconds}s</div><div class="label">Uptime</div></div>
      `;
    }
    function initChart(){
      const ctx = document.getElementById('latencyChart').getContext('2d');
      chart = new Chart(ctx, {
        type:'line',
        data:{labels:[],datasets:[{label:'Latency (ms)',data:[],borderColor:'#38bdf8',
          backgroundColor:'rgba(56,189,248,.1)',tension:.3,pointRadius:3}]},
        options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},
          scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#334155'}},
                  y:{ticks:{color:'#94a3b8'},grid:{color:'#334155'},beginAtZero:true}}}
      });
    }
    function updateChart(d){
      const lats = d.latency || [];
      const labels = lats.map((_,i)=>i+1);
      chart.data.labels = labels;
      chart.data.datasets[0].data = lats;
      chart.update('none');
    }
    async function refresh(){
      try{
        const d = await fetchStats();
        renderCards(d);
        updateChart(d);
      }catch(e){console.error(e);}
    }
    initChart();
    refresh();
    setInterval(refresh, 3000);
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
