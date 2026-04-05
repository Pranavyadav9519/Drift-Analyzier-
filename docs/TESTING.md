# Testing Guide — Sentinel Zero Local

## Running Tests

### Python Unit Tests

```bash
# From project root
pip install -r requirements.txt
python -m pytest tests/test_detector.py -v
```

Expected output:

```
tests/test_detector.py::TestFeatureExtractionSpeed::test_extraction_under_100ms PASSED
tests/test_detector.py::TestFeatureExtractionSpeed::test_extraction_returns_dict PASSED
tests/test_detector.py::TestFeatureExtractionSpeed::test_all_feature_values_are_numeric PASSED
tests/test_detector.py::TestIPDetection::test_detects_ip_address PASSED
...
PASSED (xx tests in ~1 s)
```

### ML Microservice Tests

```bash
cd ml-service
pip install -r requirements.txt pytest
python -m pytest -v
```

---

## Test Coverage

### `tests/test_detector.py`

| Test Class | What it Validates |
|------------|-------------------|
| `TestFeatureExtractionSpeed` | Feature extraction < 100 ms, returns dict, all values numeric |
| `TestIPDetection` | IP address in host correctly flagged |
| `TestHTTPSDetection` | HTTPS vs HTTP detection |
| `TestSuspiciousTLDDetection` | Blocked TLDs (`.xyz`, `.tk`, `.ml`, …) flagged |
| `TestTrustedDomainWhitelist` | Known-good domains not flagged |
| `TestPhishingKeywords` | Keyword counter works correctly |
| `TestEntropyCalculation` | Shannon entropy is positive, edge cases handled |
| `TestSubdomainCounting` | Subdomain depth counted correctly |
| `TestPrivacyManager` | Zero external calls enforced, PII stripped from logs |
| `TestMetricsTracker` | Latency tracking, SLA compliance rate, P95 calculation |

---

## Manual Test Scenarios

### 1. URL Phishing Detection

```bash
# Start the API
python app.py &

# Test a phishing URL
curl -s -X POST http://localhost:5000/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.xyz/account/verify?token=abc"}' | python -m json.tool

# Expected: riskScore > 0.7, riskLevel = "high"

# Test a legitimate URL
curl -s -X POST http://localhost:5000/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com/search?q=sentinel+zero"}' | python -m json.tool

# Expected: riskScore < 0.4, riskLevel = "low"
```

### 2. Login Anomaly Detection (Node.js Backend)

```bash
# Start services
docker-compose up -d

# 1. Sign up
curl -s -X POST http://localhost:5000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"Pass1234!"}' | python -m json.tool

# 2. Normal login (daytime)
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Pass1234!"}' | python -m json.tool

# Expected: riskLevel = "low", action = "allow"
```

### 3. Privacy Verification

```bash
curl http://localhost:5000/privacy-report
# Expected: { "local_processing_only": true, "external_calls": 0 }
```

---

## Test Data

### Phishing URL Samples (from `demo/test_urls.txt`)

| URL | Expected Risk |
|-----|:-------------:|
| `http://paypal-secure-login.xyz/verify` | HIGH |
| `http://192.168.1.1/login` | HIGH |
| `http://groogle.com/account` | MEDIUM |
| `https://www.google.com` | LOW |
| `https://github.com` | LOW |

---

## CI Integration

Tests run automatically on every push via GitHub Actions (`.github/workflows/`).

To run locally in the same environment:

```bash
pip install pytest
python -m pytest tests/ -v --tb=short
```
