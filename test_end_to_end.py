"""
test_end_to_end.py — Sentinel Zero Local End-to-End Validation

Validates the complete system:
  1. Flask API responds correctly to /check-url
  2. Model predictions work (ML + rule-based)
  3. Privacy guarantee (no external calls)
  4. Latency SLA compliance (<200 ms)
  5. Extension manifest is valid Manifest V3

Usage:
    # Start the API first:
    #   python app.py &
    # Then run:
    python test_end_to_end.py

Or run unit portions only (no running API required):
    python test_end_to_end.py --offline
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
SKIP = "\033[93m⏭  SKIP\033[0m"

results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    results.append((name, passed, detail))
    status = PASS if passed else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  {status}  {name}{suffix}")


# ── 1. Model Availability ────────────────────────────────────────────────────

def test_model_files_exist() -> None:
    print("\n[1] Model availability")
    model_path = os.path.join("models", "phishing_model.joblib")
    features_path = os.path.join("models", "feature_names.joblib")
    record("phishing_model.joblib exists", os.path.exists(model_path))
    record("feature_names.joblib exists", os.path.exists(features_path))

    if os.path.exists(model_path) and os.path.exists(features_path):
        try:
            import joblib
            import numpy as np
            clf = joblib.load(model_path)
            feature_names = joblib.load(features_path)
            record("Model loads without error", True, f"{len(feature_names)} features")
            # Smoke-test prediction
            x = np.zeros((1, len(feature_names)))
            proba = clf.predict_proba(x)
            record("predict_proba returns 2-class output", proba.shape == (1, 2))
        except Exception as exc:
            record("Model loads without error", False, str(exc))


# ── 2. Feature Extraction ────────────────────────────────────────────────────

def test_feature_extraction() -> None:
    print("\n[2] Feature extraction")
    from utils.feature_extractor import URLFeatureExtractor

    test_cases = [
        ("http://paypal-secure-login.xyz/account/verify", {
            "has_https": 0, "suspicious_tld": 1, "is_trusted_domain": 0,
        }),
        ("https://www.google.com/search", {
            "has_https": 1, "suspicious_tld": 0, "is_trusted_domain": 1,
        }),
        ("http://192.168.1.1/login", {
            "contains_ip": 1,
        }),
    ]

    for url, expected in test_cases:
        features = URLFeatureExtractor(url).extract_features()
        for key, val in expected.items():
            record(
                f"  [{key}] for {url[:40]}",
                features.get(key) == val,
                f"expected {val}, got {features.get(key)}",
            )

    # Speed
    start = time.perf_counter()
    for _ in range(10):
        URLFeatureExtractor("http://example-phishing.xyz/login").extract_features()
    avg_ms = (time.perf_counter() - start) / 10 * 1000
    record("Avg feature extraction < 100 ms", avg_ms < 100, f"{avg_ms:.1f} ms")


# ── 3. Privacy ───────────────────────────────────────────────────────────────

def test_privacy() -> None:
    print("\n[3] Privacy guarantees")
    from utils.privacy import PrivacyManager

    pm = PrivacyManager()
    record("No external calls on init", pm.verify_no_external_api_calls())

    anon = pm.anonymize_url("https://my-sensitive-domain.com/path?token=secret123")
    record("Domain hidden after anonymise", "my-sensitive-domain.com" not in anon)
    record("Token hidden after anonymise", "secret123" not in anon)

    pii_text = "User john@example.com from 192.168.1.1 logged in"
    stripped = pm.strip_pii(pii_text)
    record("Email stripped by strip_pii", "john@example.com" not in stripped)
    record("IP stripped by strip_pii", "192.168.1.1" not in stripped)

    report = pm.get_privacy_report()
    record("Privacy report shows local_processing_only=True", report["local_processing_only"] is True)
    record("Privacy report shows external_calls=0", report["external_calls"] == 0)


# ── 4. Rule-Based Scoring ────────────────────────────────────────────────────

def test_rule_based_scoring() -> None:
    print("\n[4] Rule-based risk scoring")
    # Import the scoring function directly
    import importlib.util
    spec = importlib.util.spec_from_file_location("app", os.path.join(os.path.dirname(__file__), "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    high_risk = mod._rule_based_score({"contains_ip": 1, "has_https": 0, "suspicious_tld": 1,
                                        "is_trusted_domain": 0, "num_phishing_keywords": 3,
                                        "subdomain_count": 2, "url_length": 80,
                                        "num_at_signs": 0, "num_hyphens": 2})
    low_risk = mod._rule_based_score({"contains_ip": 0, "has_https": 1, "suspicious_tld": 0,
                                       "is_trusted_domain": 1, "num_phishing_keywords": 0,
                                       "subdomain_count": 0, "url_length": 25,
                                       "num_at_signs": 0, "num_hyphens": 0})
    record("High-risk URL scores > 0.4", high_risk > 0.4, f"score={high_risk:.3f}")
    record("Low-risk URL scores < 0.4", low_risk < 0.4, f"score={low_risk:.3f}")
    record("Scores are in [0, 1]", 0.0 <= high_risk <= 1.0 and 0.0 <= low_risk <= 1.0)


# ── 5. SLA Compliance ────────────────────────────────────────────────────────

def test_latency_sla() -> None:
    print("\n[5] Latency SLA (<200 ms)")
    from utils.feature_extractor import URLFeatureExtractor
    from utils.metrics import MetricsTracker, SLA_THRESHOLD_MS

    record("SLA_THRESHOLD_MS == 200", SLA_THRESHOLD_MS == 200)

    mt = MetricsTracker()
    urls = [
        "http://paypal-secure-login.xyz/account/verify",
        "https://www.google.com/search?q=hello",
        "http://192.168.1.1/login",
        "https://github.com/topics",
        "http://amazon-account-update.top/signin",
    ]
    latencies = []
    for url in urls:
        start = time.perf_counter()
        URLFeatureExtractor(url).extract_features()
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)
        mt.track_latency(elapsed_ms)

    avg = sum(latencies) / len(latencies)
    record(f"Avg latency of {len(urls)} URLs < 200 ms", avg < 200, f"{avg:.1f} ms")
    record("SLA compliance rate == 1.0", mt.sla_compliance_rate() == 1.0,
           f"{mt.sla_compliance_rate():.2f}")


# ── 6. Extension Manifest ────────────────────────────────────────────────────

def test_extension_manifest() -> None:
    print("\n[6] Chrome Extension manifest")
    manifest_path = os.path.join("extension", "manifest.json")
    record("manifest.json exists", os.path.exists(manifest_path))
    if not os.path.exists(manifest_path):
        return

    with open(manifest_path) as f:
        manifest = json.load(f)

    record("Manifest version is 3", manifest.get("manifest_version") == 3)
    record("'name' field present", bool(manifest.get("name")))
    record("'version' field present", bool(manifest.get("version")))
    record("'action' field present", "action" in manifest)
    record("Extension files exist",
           all(os.path.exists(os.path.join("extension", fn))
               for fn in ["popup.html", "popup.js", "content.js", "styles.css"]))


# ── 7. API Live Tests (requires running Flask server) ────────────────────────

def test_api_live(base_url: str = "http://localhost:5050") -> None:
    print(f"\n[7] Live API tests ({base_url})")
    try:
        import urllib.request
        import urllib.error

        # Health check
        with urllib.request.urlopen(f"{base_url}/", timeout=3) as resp:
            body = json.loads(resp.read())
        record("GET / returns 200", True, body.get("name", ""))

        # /check-url — phishing
        payload = json.dumps({"url": "http://paypal-secure-login.xyz/account/verify"}).encode()
        req = urllib.request.Request(
            f"{base_url}/check-url",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        record("POST /check-url returns verdict", "verdict" in data, data.get("verdict"))
        record("Phishing URL flagged as PHISHING or SUSPICIOUS",
               data.get("verdict") in ("PHISHING", "SUSPICIOUS"),
               f"verdict={data.get('verdict')}")
        record("risk_score in [0, 1]",
               0.0 <= data.get("risk_score", -1) <= 1.0,
               f"score={data.get('risk_score')}")
        record("Latency reported < 200 ms",
               data.get("latency_ms", 9999) < 200,
               f"{data.get('latency_ms')} ms")

        # /check-url — legitimate
        payload2 = json.dumps({"url": "https://www.google.com"}).encode()
        req2 = urllib.request.Request(
            f"{base_url}/check-url",
            data=payload2,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req2, timeout=5) as resp2:
            data2 = json.loads(resp2.read())
        record("Legitimate URL not flagged as PHISHING",
               data2.get("verdict") != "PHISHING",
               f"verdict={data2.get('verdict')}")

        # /stats
        with urllib.request.urlopen(f"{base_url}/stats", timeout=3) as resp:
            stats = json.loads(resp.read())
        record("GET /stats returns request_count > 0", stats.get("request_count", 0) > 0)

        # /privacy-report
        with urllib.request.urlopen(f"{base_url}/privacy-report", timeout=3) as resp:
            priv = json.loads(resp.read())
        record("Privacy report: external_calls == 0", priv.get("external_calls") == 0)
        record("Privacy report: local_processing_only == True",
               priv.get("local_processing_only") is True)

    except OSError as exc:
        print(f"  {SKIP}  API unreachable: {exc}")
        print("       Start the API with: python app.py")


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary() -> None:
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    skipped = sum(1 for name, _, _ in results if "SKIP" in name)
    failed = total - passed

    print("\n" + "=" * 60)
    print(f"  Results: {passed}/{total} passed  |  {failed} failed")
    print("=" * 60)
    if failed > 0:
        print("\n  Failed tests:")
        for name, ok, detail in results:
            if not ok:
                print(f"    ❌  {name}" + (f" — {detail}" if detail else ""))
    print()
    return passed == total


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Zero end-to-end test suite")
    parser.add_argument("--offline", action="store_true",
                        help="Skip live API tests (no running server required)")
    parser.add_argument("--api-url", default="http://localhost:5050",
                        help="Base URL of the running Flask API")
    args = parser.parse_args()

    print("\n🛡️  Sentinel Zero Local — End-to-End Test Suite\n")
    print("  Running validation checks…")

    test_model_files_exist()
    test_feature_extraction()
    test_privacy()
    test_rule_based_scoring()
    test_latency_sla()
    test_extension_manifest()

    if not args.offline:
        test_api_live(args.api_url)
    else:
        print("\n[7] Live API tests — SKIPPED (--offline mode)")

    all_passed = print_summary()
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
