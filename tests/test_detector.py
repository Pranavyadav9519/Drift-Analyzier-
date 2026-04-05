"""
tests/test_detector.py — Sentinel Zero Local unit tests

Run with:
    python -m pytest tests/test_detector.py -v
"""

import sys
import os
import time
import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.feature_extractor import URLFeatureExtractor, TRUSTED_DOMAINS, SUSPICIOUS_TLDS
from utils.privacy import PrivacyManager
from utils.metrics import MetricsTracker, SLA_THRESHOLD_MS


# ── Fixtures ─────────────────────────────────────────────────────────────────

PHISHING_URL = "http://paypal-secure-login.xyz/account/verify?token=abc123"
LEGIT_URL = "https://www.google.com/search?q=sentinel+zero"
IP_URL = "http://192.168.1.1/login"
HTTP_URL = "http://example.com"
HTTPS_URL = "https://example.com"


# ── Feature extraction speed ──────────────────────────────────────────────────

class TestFeatureExtractionSpeed:
    def test_extraction_under_100ms(self):
        """Feature extraction must complete in under 100 ms."""
        extractor = URLFeatureExtractor(PHISHING_URL)
        start = time.perf_counter()
        extractor.extract_features()
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100, f"Extraction took {elapsed_ms:.1f} ms (limit 100 ms)"

    def test_extraction_returns_dict(self):
        extractor = URLFeatureExtractor(LEGIT_URL)
        features = extractor.extract_features()
        assert isinstance(features, dict)
        assert len(features) >= 20, f"Expected ≥20 features, got {len(features)}"

    def test_all_feature_values_are_numeric(self):
        extractor = URLFeatureExtractor(PHISHING_URL)
        features = extractor.extract_features()
        for key, val in features.items():
            assert isinstance(val, (int, float)), (
                f"Feature '{key}' has non-numeric value: {val!r}"
            )


# ── IP detection ──────────────────────────────────────────────────────────────

class TestIPDetection:
    def test_detects_ip_address(self):
        extractor = URLFeatureExtractor(IP_URL)
        features = extractor.extract_features()
        assert features["contains_ip"] == 1

    def test_no_ip_in_normal_url(self):
        extractor = URLFeatureExtractor(LEGIT_URL)
        features = extractor.extract_features()
        assert features["contains_ip"] == 0

    def test_ip_in_various_formats(self):
        for url in ["http://10.0.0.1/", "http://172.16.0.1/page", "http://203.0.113.5/"]:
            assert URLFeatureExtractor(url).extract_features()["contains_ip"] == 1


# ── HTTPS detection ───────────────────────────────────────────────────────────

class TestHTTPSDetection:
    def test_https_url_flagged(self):
        extractor = URLFeatureExtractor(HTTPS_URL)
        assert extractor.extract_features()["has_https"] == 1

    def test_http_url_not_flagged(self):
        extractor = URLFeatureExtractor(HTTP_URL)
        assert extractor.extract_features()["has_https"] == 0

    def test_phishing_url_no_https(self):
        extractor = URLFeatureExtractor(PHISHING_URL)
        assert extractor.extract_features()["has_https"] == 0


# ── Suspicious TLD detection ──────────────────────────────────────────────────

class TestSuspiciousTLDDetection:
    @pytest.mark.parametrize("tld", list(SUSPICIOUS_TLDS)[:6])
    def test_suspicious_tlds(self, tld):
        url = f"http://login.example.{tld}/verify"
        extractor = URLFeatureExtractor(url)
        assert extractor.extract_features()["suspicious_tld"] == 1, (
            f"TLD '.{tld}' should be flagged"
        )

    def test_legitimate_tld_not_suspicious(self):
        for url in [LEGIT_URL, HTTPS_URL, "https://wikipedia.org"]:
            extractor = URLFeatureExtractor(url)
            assert extractor.extract_features()["suspicious_tld"] == 0

    def test_phishing_xyz_tld(self):
        url = "http://bank-secure.xyz/login"
        assert URLFeatureExtractor(url).extract_features()["suspicious_tld"] == 1


# ── Trusted domain whitelist ──────────────────────────────────────────────────

class TestTrustedDomainWhitelist:
    @pytest.mark.parametrize("domain", list(TRUSTED_DOMAINS)[:6])
    def test_trusted_domains_recognised(self, domain):
        url = f"https://www.{domain}/path"
        extractor = URLFeatureExtractor(url)
        assert extractor.extract_features()["is_trusted_domain"] == 1, (
            f"{domain} should be trusted"
        )

    def test_phishing_domain_not_trusted(self):
        for url in [PHISHING_URL, IP_URL, "http://paypal-fake.xyz/"]:
            extractor = URLFeatureExtractor(url)
            assert extractor.extract_features()["is_trusted_domain"] == 0


# ── Phishing keyword detection ────────────────────────────────────────────────

class TestPhishingKeywords:
    def test_phishing_url_has_keywords(self):
        url = "http://secure-login-account-verify.xyz/signin"
        features = URLFeatureExtractor(url).extract_features()
        assert features["num_phishing_keywords"] >= 2

    def test_clean_url_has_no_keywords(self):
        url = "https://www.github.com/topics/machine-learning"
        features = URLFeatureExtractor(url).extract_features()
        assert features["num_phishing_keywords"] == 0


# ── Entropy calculation ───────────────────────────────────────────────────────

class TestEntropyCalculation:
    def test_entropy_is_positive(self):
        extractor = URLFeatureExtractor(LEGIT_URL)
        features = extractor.extract_features()
        assert features["entropy"] > 0

    def test_entropy_empty_url(self):
        extractor = URLFeatureExtractor("")
        assert extractor.calculate_entropy() == 0.0

    def test_high_entropy_random_url(self):
        random_url = "http://xk3p9q2mnz.biz/a8v3j2"
        low_entropy_url = "http://aaaaaaaaaa.com/aaaaaaa"
        e_random = URLFeatureExtractor(random_url).calculate_entropy()
        e_low = URLFeatureExtractor(low_entropy_url).calculate_entropy()
        assert e_random > e_low


# ── Subdomain counting ────────────────────────────────────────────────────────

class TestSubdomainCounting:
    def test_multiple_subdomains(self):
        url = "http://a.b.c.example.com/path"
        features = URLFeatureExtractor(url).extract_features()
        assert features["subdomain_count"] >= 2

    def test_no_subdomain(self):
        url = "https://example.com/path"
        features = URLFeatureExtractor(url).extract_features()
        assert features["subdomain_count"] == 0


# ── Privacy manager ───────────────────────────────────────────────────────────

class TestPrivacyManager:
    def setup_method(self):
        self.pm = PrivacyManager()

    def test_no_external_calls_initially(self):
        assert self.pm.verify_no_external_api_calls() is True

    def test_anonymize_url_hides_domain(self):
        anon = self.pm.anonymize_url("https://sensitive.example.com/path?token=abc")
        assert "sensitive.example.com" not in anon
        assert "abc" not in anon

    def test_privacy_report_shows_local_only(self):
        report = self.pm.get_privacy_report()
        assert report["local_processing_only"] is True
        assert report["external_calls"] == 0

    def test_strip_pii_removes_email(self):
        result = self.pm.strip_pii("user email is test@example.com please check")
        assert "test@example.com" not in result
        assert "[EMAIL]" in result

    def test_strip_pii_removes_ip(self):
        result = self.pm.strip_pii("Request from 192.168.0.1 was blocked")
        assert "192.168.0.1" not in result
        assert "[IP]" in result

    def test_external_call_recorded_raises(self):
        self.pm.record_external_call("https://external.api.com")
        with pytest.raises(Exception, match="External API calls detected"):
            self.pm.verify_no_external_api_calls()


# ── Metrics tracker ───────────────────────────────────────────────────────────

class TestMetricsTracker:
    def setup_method(self):
        self.mt = MetricsTracker()

    def test_initial_metrics_are_empty(self):
        m = self.mt.get_metrics()
        assert m["request_count"] == 0
        assert m["phishing_detected"] == 0

    def test_latency_tracking(self):
        for v in [50.0, 80.0, 120.0]:
            self.mt.track_latency(v)
        assert abs(self.mt.avg_latency() - 83.33) < 0.1

    def test_sla_compliance_tracking(self):
        self.mt.track_latency(100.0)   # within SLA
        self.mt.track_latency(250.0)   # over SLA
        rate = self.mt.sla_compliance_rate()
        assert rate == 0.5

    def test_p95_latency(self):
        for v in range(1, 101):
            self.mt.track_latency(float(v))
        assert self.mt.p95_latency() >= 95.0

    def test_sla_threshold_is_200ms(self):
        assert SLA_THRESHOLD_MS == 200

    def test_uptime_positive(self):
        assert self.mt.uptime_seconds() >= 0
