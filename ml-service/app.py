"""
ml-service/app.py — Drift Analyzer Anomaly Detection Service

Uses Isolation Forest to detect abnormal login and system access patterns.
No database — models are trained in-memory per user session and discarded
when the service restarts (zero-data-persistence ideology).

Endpoints:
    GET  /health              — Service health check
    POST /train               — Train an Isolation Forest for a user
    POST /predict             — Predict anomaly score for a login event
    POST /threat/predict      — Same as /predict but returns threat card + remedy steps
"""

import sys
import os
import time

from flask import Flask, request, jsonify
from flask_cors import CORS

# Allow importing from the project root (for core/ module)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from model import train_model, predict

# Import remedy engine from shared core — gives us actionable fix steps
try:
    from core.remedy_engine import RemedyEngine
    from core.threat_classifier import ThreatClassifier
    _remedy_engine = RemedyEngine()
    _threat_classifier = ThreatClassifier()
    _core_available = True
except ImportError:
    _core_available = False

app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:5050",
    "http://127.0.0.1:5050",
    "http://localhost:5001",
    "http://127.0.0.1:5001",
])


@app.route("/health", methods=["GET"])
def health():
    """Return service health status."""
    return jsonify({"status": "ok", "service": "drift-analyzer-ml"})


@app.route("/train", methods=["POST"])
def train():
    """
    Train an Isolation Forest model for a specific user.

    The model is stored in-memory (keyed by user ID hash) and is never
    written to a database. It persists only for the current session.

    Request body:
        {
            "userId": "some-user-id",
            "data": [
                {"loginHour": 9, "loginDayOfWeek": 1, "isNewDevice": 0},
                ...
            ]
        }
    """
    body = request.get_json()
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    user_id = body.get("userId")
    training_data = body.get("data", [])

    if not user_id:
        return jsonify({"error": "userId is required"}), 400
    if len(training_data) < 5:
        return jsonify({"error": "At least 5 data points are required for training"}), 400

    result = train_model(user_id, training_data)
    return jsonify(result)


@app.route("/predict", methods=["POST"])
def predict_route():
    """
    Predict whether a login event is anomalous for a given user.

    Request body:
        {
            "userId": "some-user-id",
            "loginHour": 14,
            "loginDayOfWeek": 2,
            "isNewDevice": 0
        }
    Response:
        {"score": float, "isAnomaly": bool, "userId": str}
    """
    body = request.get_json()
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    user_id = body.get("userId")
    if not user_id:
        return jsonify({"error": "userId is required"}), 400

    login_hour = body.get("loginHour", 12)
    login_day = body.get("loginDayOfWeek", 1)
    is_new_device = body.get("isNewDevice", 0)

    result = predict(user_id, login_hour, login_day, is_new_device)
    return jsonify(result)


@app.route("/threat/predict", methods=["POST"])
def threat_predict():
    """
    Threat-aware prediction endpoint -- returns anomaly score PLUS actionable remedy steps.

    This is the endpoint the system monitor and browser extension should call
    when they want a complete threat response, not just a raw score.

    Request body:
        {
            "userId": "some-user-id",
            "loginHour": 14,
            "loginDayOfWeek": 2,
            "isNewDevice": 0
        }
    Response:
        {
            "is_threat": bool,
            "anomaly_score": float,
            "threat_type": str | null,
            "severity": str,
            "description": str,
            "remedy_steps": [str, ...]
        }
    """
    body = request.get_json()
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    user_id = body.get("userId", "anonymous")
    login_hour = body.get("loginHour", time.localtime().tm_hour)
    login_day = body.get("loginDayOfWeek", time.localtime().tm_wday)
    is_new_device = int(body.get("isNewDevice", 0))

    # Get the raw anomaly prediction
    prediction = predict(user_id, login_hour, login_day, is_new_device)
    is_anomaly = prediction["isAnomaly"]
    anomaly_score = prediction["score"]

    if _core_available:
        # Use the shared classifier and remedy engine
        threat_type = _threat_classifier.classify_login_anomaly(is_anomaly, anomaly_score)

        if threat_type:
            remedy_card = _remedy_engine.get_remedy(threat_type)
            severity = _threat_classifier.determine_severity(threat_type)
            response = {
                "is_threat": True,
                "anomaly_score": anomaly_score,
                "threat_type": threat_type,
                "severity": severity,
                "description": remedy_card["description"],
                "remedy_steps": remedy_card["remedies"],
            }
        else:
            response = {
                "is_threat": False,
                "anomaly_score": anomaly_score,
                "threat_type": None,
                "severity": "low",
                "description": "Login pattern looks normal.",
                "remedy_steps": [],
            }
    else:
        # Core module not available -- return minimal response
        response = {
            "is_threat": is_anomaly,
            "anomaly_score": anomaly_score,
            "threat_type": "anomalous_login" if is_anomaly else None,
            "severity": "medium" if is_anomaly else "low",
            "description": "Anomalous login detected." if is_anomaly else "Login pattern looks normal.",
            "remedy_steps": [
                "Check your active sessions and log out of unfamiliar devices.",
                "Change your password immediately.",
                "Enable two-factor authentication.",
            ] if is_anomaly else [],
        }

    return jsonify(response), 200


@app.route("/", methods=["GET"])
def index():
    """Service health check and endpoint index."""
    return jsonify({
        "name": "Drift Analyzer -- ML Anomaly Detection Service",
        "description": (
            "Isolation Forest anomaly detection for login and system access patterns. "
            "Zero data storage -- models are in-memory only."
        ),
        "endpoints": {
            "GET /health": "Service health check",
            "POST /train": "Train Isolation Forest for a user session",
            "POST /predict": "Raw anomaly score for a login event",
            "POST /threat/predict": "Threat card with anomaly score + remedy steps",
        },
        "ideology": "zero-storage · local-only · real-time · user-centric",
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print("\n Drift Analyzer ML Service -- starting on http://localhost:{}".format(port))
    print("   Endpoints: /health  /train  /predict  /threat/predict\n")
    app.run(host="0.0.0.0", port=port, debug=False)
