"""
app.py — Drift Analyzer Phishing Detection API

Lightweight Flask service that analyses URLs in real time using a trained
RandomForest model (falls back to rule-based scoring if no model is present).

Every endpoint returns actionable data — not just a verdict, but also
specific remedy steps the user can take if a threat is detected.

Endpoints:
    POST /check-url              — Full URL analysis (features + verdict)
    POST /threat                 — Concise threat card with remedy steps
    GET  /remedies/<threat_type> — Actionable fix list for a given threat type
    GET  /stats                  — In-session performance metrics
    GET  /privacy-report         — Confirms zero external API calls
    GET  /                       — Service health / index
"""

import os
import sys
import time

from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))

from utils.feature_extractor import URLFeatureExtractor
from utils.metrics import MetricsTracker
from utils.privacy import PrivacyManager
from core.remedy_engine import RemedyEngine
from core.threat_classifier import ThreatClassifier
from config import PHISHING_DETECTION_THRESHOLD

# ── Optional trained ML model ────────────────────────────────────────────────

try:
    import joblib
    import numpy as np

    _MODEL_PATH = os.path.join("models", "phishing_model.joblib")
    _FEATURE_NAMES_PATH = os.path.join("models", "feature_names.joblib")

    if os.path.exists(_MODEL_PATH) and os.path.exists(_FEATURE_NAMES_PATH):
        _classifier = joblib.load(_MODEL_PATH)
        _feature_names = joblib.load(_FEATURE_NAMES_PATH)
        _model_available = True
    else:
        _classifier = None
        _feature_names = None
        _model_available = False
except ImportError:
    _classifier = None
    _feature_names = None
    _model_available = False

# ── Flask app ────────────────────────────────────────────────────────────────

app = Flask(__name__)
# Allow the browser extension (all origins via host_permissions) and
# localhost access for local development and testing.
CORS(app, origins=[
    "http://localhost:5050",
    "http://127.0.0.1:5050",
    "http://localhost:5001",
    "http://127.0.0.1:5001",
])

_metrics = MetricsTracker()
_privacy = PrivacyManager()
_remedy_engine = RemedyEngine()
_threat_classifier = ThreatClassifier()

_RISK_THRESHOLD_HIGH = PHISHING_DETECTION_THRESHOLD["high"]
_RISK_THRESHOLD_MEDIUM = PHISHING_DETECTION_THRESHOLD["medium"]


# ── Scoring helpers ──────────────────────────────────────────────────────────

def _rule_based_score(features: dict) -> float:
    """
    Compute a 0-1 phishing risk score from hand-crafted URL features.

    Used when no trained model is available.
    Each signal contributes a small weighted amount; the total is clamped to [0, 1].
    """
    score = 0.0
    score += min(features.get("url_length", 0) / 200.0, 0.15)
    if features.get("contains_ip"):
        score += 0.20
    if not features.get("has_https"):
        score += 0.10
    if features.get("suspicious_tld"):
        score += 0.20
    if features.get("is_trusted_domain"):
        score -= 0.30  # Trusted domain is a strong negative signal
    score += min(features.get("num_phishing_keywords", 0) * 0.07, 0.20)
    score += min(features.get("subdomain_count", 0) * 0.05, 0.15)
    score += min(features.get("num_at_signs", 0) * 0.10, 0.10)
    score += min(features.get("num_hyphens", 0) * 0.02, 0.10)
    return max(0.0, min(1.0, score))


def _ml_score(features: dict):
    """
    Run the trained RandomForest model and return the phishing probability.

    Returns None if no model is loaded -- the caller should then fall back
    to the rule-based score.
    """
    if not _model_available:
        return None
    feature_vector = np.array([[features.get(f, 0) for f in _feature_names]])
    probabilities = _classifier.predict_proba(feature_vector)[0]
    # The classifier always outputs [P(legitimate), P(phishing)]
    if len(probabilities) != 2:
        return None
    return float(probabilities[1])


def _analyse_url(url: str) -> dict:
    """
    Full URL analysis pipeline: extract features -> score -> classify.

    :param url: Raw URL string from the caller
    :returns: Dict containing verdict, scores, features, and latency
    """
    start_time = time.perf_counter()

    extractor = URLFeatureExtractor(url)
    features = extractor.extract_features()

    ml_probability = _ml_score(features)
    rule_probability = _rule_based_score(features)
    risk_score = ml_probability if ml_probability is not None else rule_probability

    if risk_score >= _RISK_THRESHOLD_HIGH:
        risk_level = "high"
        verdict = "PHISHING"
    elif risk_score >= _RISK_THRESHOLD_MEDIUM:
        risk_level = "medium"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "low"
        verdict = "SAFE"

    latency_ms = (time.perf_counter() - start_time) * 1000
    _metrics.track_latency(latency_ms)
    _metrics.record_detection(verdict == "PHISHING")

    return {
        "url": _privacy.anonymize_url(url),
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 4),
        "ml_score": round(ml_probability, 4) if ml_probability is not None else None,
        "rule_score": round(rule_probability, 4),
        "features": features,
        "latency_ms": round(latency_ms, 2),
        "model_used": "RandomForest" if ml_probability is not None else "rule-based",
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/check-url", methods=["POST"])
def check_url():
    """
    Analyse a URL and return full phishing risk details including raw features.

    Request body: {"url": "https://..."}
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json()
    if body is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    analysis_result = _analyse_url(url)
    return jsonify(analysis_result), 200


@app.route("/threat", methods=["POST"])
def threat():
    """
    Concise threat endpoint -- returns verdict + risk score + actionable remedy steps.

    This is the endpoint the browser extension and monitor service should call
    when they want a user-facing threat card, not a raw feature dump.

    Request body: {"url": "https://..."}
    Response: {
        "verdict": "PHISHING" | "SUSPICIOUS" | "SAFE",
        "risk_score": float,
        "threat_type": str | null,
        "severity": str,
        "remedy_steps": [str, ...],
        "description": str
    }
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    body = request.get_json()
    if body is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    analysis = _analyse_url(url)
    verdict = analysis["verdict"]
    risk_score = analysis["risk_score"]

    # Map the verdict to a canonical threat type
    threat_type = _threat_classifier.classify_url_threat(verdict, risk_score)

    if threat_type:
        remedy_card = _remedy_engine.get_remedy(threat_type)
        severity = _threat_classifier.determine_severity(threat_type, risk_score)
        response = {
            "verdict": verdict,
            "risk_score": risk_score,
            "threat_type": threat_type,
            "severity": severity,
            "description": remedy_card["description"],
            "remedy_steps": remedy_card["remedies"],
            "latency_ms": analysis["latency_ms"],
        }
    else:
        response = {
            "verdict": "SAFE",
            "risk_score": risk_score,
            "threat_type": None,
            "severity": "low",
            "description": "No threats detected. This URL appears safe.",
            "remedy_steps": [],
            "latency_ms": analysis["latency_ms"],
        }

    return jsonify(response), 200


@app.route("/remedies/<string:threat_type>", methods=["GET"])
def get_remedies(threat_type):
    """
    Return the full remedy card for a specific threat type.

    :param threat_type: One of phishing_url | anomalous_login |
                        root_access_attempt | social_engineering |
                        suspicious_process | usb_anomaly | network_anomaly
    """
    known_types = _remedy_engine.list_threat_types()

    if threat_type not in known_types:
        return jsonify({
            "error": "Unknown threat type: '{}'".format(threat_type),
            "known_types": known_types,
        }), 404

    remedy_card = _remedy_engine.get_remedy(threat_type)
    return jsonify(remedy_card), 200


@app.route("/stats", methods=["GET"])
def stats():
    """Return aggregated in-session performance metrics (in-memory only)."""
    return jsonify(_metrics.get_metrics()), 200


@app.route("/privacy-report", methods=["GET"])
def privacy_report():
    """Confirm that zero external API calls have been made this session."""
    report = _privacy.get_privacy_report()
    return jsonify(report), 200


@app.route("/", methods=["GET"])
def index():
    """Service health check and endpoint index."""
    return jsonify({
        "name": "Drift Analyzer -- Phishing Detection API",
        "description": (
            "Real-time URL phishing detection with actionable remedy steps. "
            "Zero data storage. Local processing only."
        ),
        "endpoints": {
            "POST /check-url": "Full URL analysis with raw features",
            "POST /threat": "Concise threat card with remedy steps",
            "GET /remedies/<threat_type>": "Remedy steps for a specific threat type",
            "GET /stats": "In-session performance metrics",
            "GET /privacy-report": "Confirms zero external API calls",
        },
        "model": "RandomForest" if _model_available else "rule-based",
        "ideology": "zero-storage · local-only · fast-detection · user-centric",
    }), 200


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print("\n Drift Analyzer Phishing API -- starting on http://localhost:{}".format(port))
    print("   Model: {}".format('RandomForest (trained)' if _model_available else 'rule-based fallback'))
    print("   Endpoints: /check-url  /threat  /remedies/<type>  /stats  /privacy-report\n")
    app.run(host="0.0.0.0", port=port, debug=False)
