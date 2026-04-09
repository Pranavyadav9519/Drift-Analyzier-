import time
import statistics
from collections import deque


SLA_THRESHOLD_MS = 200  # Maximum acceptable response time in milliseconds
MAX_HISTORY = 1000  # Maximum number of entries to keep in rolling lists


class MetricsTracker:
    """Tracks latency, detection rates, false positives, and SLA compliance."""

    def __init__(self):
        self.latency: deque = deque(maxlen=MAX_HISTORY)
        self.detection_rates: deque = deque(maxlen=MAX_HISTORY)
        self.false_positives: deque = deque(maxlen=MAX_HISTORY)
        self.sla_compliance: deque = deque(maxlen=MAX_HISTORY)
        self._request_count: int = 0
        self._phishing_detected: int = 0
        self._start_time: float = time.time()
        self.recent_threats: deque = deque(maxlen=50)

    # ------------------------------------------------------------------ #
    # Recording helpers                                                     #
    # ------------------------------------------------------------------ #

    def track_latency(self, latency_ms: float) -> None:
        self.latency.append(latency_ms)
        self.sla_compliance.append(latency_ms <= SLA_THRESHOLD_MS)
        self._request_count += 1

    def track_detection_rate(self, rate_value: float) -> None:
        self.detection_rates.append(rate_value)

    def track_false_positive(self, is_false_positive: bool) -> None:
        self.false_positives.append(is_false_positive)

    def track_sla_compliance(self, compliance_value: bool) -> None:
        self.sla_compliance.append(compliance_value)

    def record_detection(self, is_phishing: bool, threat_details: dict = None) -> None:
        self._phishing_detected += int(is_phishing)
        if is_phishing and threat_details:
            self.recent_threats.appendleft(threat_details)

    # ------------------------------------------------------------------ #
    # Aggregated statistics                                                 #
    # ------------------------------------------------------------------ #

    def avg_latency(self) -> float:
        return statistics.mean(self.latency) if self.latency else 0.0

    def p95_latency(self) -> float:
        if not self.latency:
            return 0.0
        sorted_lat = sorted(self.latency)
        idx = int(len(sorted_lat) * 0.95)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    def sla_compliance_rate(self) -> float:
        if not self.sla_compliance:
            return 1.0
        return sum(self.sla_compliance) / len(self.sla_compliance)

    def false_positive_rate(self) -> float:
        if not self.false_positives:
            return 0.0
        return sum(self.false_positives) / len(self.false_positives)

    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    # ------------------------------------------------------------------ #
    # Full metrics snapshot                                                 #
    # ------------------------------------------------------------------ #

    def get_metrics(self) -> dict:
        return {
            "request_count": self._request_count,
            "phishing_detected": self._phishing_detected,
            "avg_latency_ms": round(self.avg_latency(), 2),
            "p95_latency_ms": round(self.p95_latency(), 2),
            "sla_compliance_rate": round(self.sla_compliance_rate(), 4),
            "false_positive_rate": round(self.false_positive_rate(), 4),
            "uptime_seconds": round(self.uptime_seconds(), 1),
            "sla_threshold_ms": SLA_THRESHOLD_MS,
            # Raw series kept for backward compatibility (bounded to last MAX_HISTORY entries)
            "latency": list(self.latency),
            "detection_rates": list(self.detection_rates),
            "false_positives": list(self.false_positives),
            "sla_compliance": list(self.sla_compliance),
            "recent_threats": list(self.recent_threats),
        }