class MetricsTracker:
    def __init__(self):
        self.latency = []
        self.detection_rates = []
        self.false_positives = []
        self.sla_compliance = []

    def track_latency(self, latency_value):
        self.latency.append(latency_value)

    def track_detection_rate(self, rate_value):
        self.detection_rates.append(rate_value)

    def track_false_positive(self, false_positive_value):
        self.false_positives.append(false_positive_value)

    def track_sla_compliance(self, compliance_value):
        self.sla_compliance.append(compliance_value)

    def get_metrics(self):
        return {
            'latency': self.latency,
            'detection_rates': self.detection_rates,
            'false_positives': self.false_positives,
            'sla_compliance': self.sla_compliance
        }