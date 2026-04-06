"""
core/threat_classifier.py — Threat type classification logic

Takes raw signals (URL verdict, anomaly score, system events) and maps
them to a canonical threat_type string that the RemedyEngine understands.

The classifier intentionally uses simple, transparent rules rather than
another ML model — explainability matters when you're telling a user
their system is under attack.
"""

from __future__ import annotations


class ThreatClassifier:
    """
    Converts raw detection signals into human-readable threat categories.

    This is the bridge between the detection services (phishing API, ML service,
    system monitor) and the remedy engine.
    """

    # Minimum risk score to classify a URL verdict as an active threat
    PHISHING_SCORE_THRESHOLD: float = 0.5
    # Isolation Forest anomaly score below which we flag a login as suspicious
    # (scores are negative; more negative = more anomalous).
    # Set conservatively at -0.6 — the model's own predict() is the primary signal;
    # this score threshold only catches severe outliers the model missed.
    ANOMALY_SCORE_THRESHOLD: float = -0.6

    def classify_url_threat(
        self,
        verdict: str,
        risk_score: float,
    ) -> str | None:
        """
        Classify a URL check result into a threat type.

        :param verdict: "SAFE", "SUSPICIOUS", or "PHISHING"
        :param risk_score: Floating-point risk score between 0 and 1
        :returns: A threat type string, or None if no threat detected
        """
        if verdict == "PHISHING" or risk_score >= self.PHISHING_SCORE_THRESHOLD:
            return "phishing_url"
        if verdict == "SUSPICIOUS":
            return "phishing_url"  # Treat suspicious URLs as potential phishing
        return None  # SAFE — not a threat

    def classify_login_anomaly(
        self,
        is_anomaly: bool,
        anomaly_score: float,
    ) -> str | None:
        """
        Classify an Isolation Forest prediction result.

        :param is_anomaly: Boolean flag from the ML service
        :param anomaly_score: Raw score from Isolation Forest (more negative = worse)
        :returns: "anomalous_login" if threat detected, else None
        """
        if is_anomaly or anomaly_score < self.ANOMALY_SCORE_THRESHOLD:
            return "anomalous_login"
        return None

    def classify_system_event(
        self,
        event_type: str,
        details: dict | None = None,
    ) -> str | None:
        """
        Classify a raw system monitor event into a threat type.

        :param event_type: Raw event category from the system monitor
        :param details: Optional dict with additional event context
        :returns: A threat type string, or None if benign
        """
        # Normalise to lowercase for consistent matching
        event_lower = event_type.lower()

        event_to_threat: dict[str, str] = {
            "privilege_escalation": "root_access_attempt",
            "sudo_attempt": "root_access_attempt",
            "root_access": "root_access_attempt",
            "admin_prompt": "root_access_attempt",
            "usb_connected": "usb_anomaly",
            "usb_anomaly": "usb_anomaly",
            "network_anomaly": "network_anomaly",
            "port_scan": "network_anomaly",
            "suspicious_process": "suspicious_process",
            "unusual_file_access": "suspicious_process",
            "social_engineering": "social_engineering",
        }

        return event_to_threat.get(event_lower)

    def determine_severity(self, threat_type: str, risk_score: float = 0.0) -> str:
        """
        Map a threat type to a severity level, using the risk score as a tiebreaker.

        :param threat_type: Canonical threat type string
        :param risk_score: Optional numeric score (0–1) to fine-tune severity
        :returns: "low", "medium", "high", or "critical"
        """
        base_severity: dict[str, str] = {
            "phishing_url": "high",
            "anomalous_login": "medium",
            "root_access_attempt": "critical",
            "social_engineering": "high",
            "suspicious_process": "medium",
            "usb_anomaly": "medium",
            "network_anomaly": "medium",
        }

        severity = base_severity.get(threat_type, "medium")

        # Upgrade severity based on risk score
        if severity == "medium" and risk_score >= 0.8:
            severity = "high"
        elif severity == "high" and risk_score >= 0.95:
            severity = "critical"

        return severity
