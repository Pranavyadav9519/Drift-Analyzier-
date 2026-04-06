"""
config.py — Drift Analyzer configuration

Centralised settings for both the phishing detection API and the ML service.
No secrets here — everything is tuneable via environment variables in production.
"""

# ── Phishing Detection Thresholds ────────────────────────────────────────────
# A URL scoring above 'high' is flagged as PHISHING.
# A URL scoring between 'medium' and 'high' is flagged as SUSPICIOUS.
# Anything below 'medium' is considered SAFE.
PHISHING_DETECTION_THRESHOLD = {
    "low": 0.3,
    "medium": 0.5,
    "high": 0.8,
}

# ── Performance Requirements ─────────────────────────────────────────────────
# The phishing API must respond in under 200ms to feel "real-time" to the user.
PERFORMANCE_REQUIREMENTS = {
    "maximum_latency_ms": 200,
    "sla_target_percent": 95,  # 95% of requests must meet the latency target
}

# ── Privacy Settings ──────────────────────────────────────────────────────────
# All processing is local. No data leaves the device. No external API calls.
PRIVACY_SETTINGS = {
    "local_processing_only": True,
    "external_calls_allowed": False,
    "data_retention": "none",  # No persistence — everything is in-memory
}

# ── Service Ports ─────────────────────────────────────────────────────────────
SERVICE_PORTS = {
    "phishing_api": 5050,
    "ml_service": 5001,
}
