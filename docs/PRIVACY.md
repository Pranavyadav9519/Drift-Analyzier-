# 🔐 Privacy Documentation

## Core Privacy Guarantee

> **Sentinel Zero Local processes everything on your device. Zero URLs, emails, or behavioral data are ever sent to external servers.**

---

## Privacy Principles

### 1. On-Device Inference

All machine learning inference runs locally:

| Component | Runtime | Data stays local |
|---------|---------|-----------------|
| URL feature extraction | Pure Python | ✅ Always |
| DistilBERT classification | ONNX Runtime (local) | ✅ Always |
| Isolation Forest (behavior) | scikit-learn (local) | ✅ Always |
| Risk score calculation | Python/Node.js | ✅ Always |

The browser extension communicates **only** with `localhost:5050` — never with external APIs.

### 2. No Persistent URL Storage

URLs submitted to `/check-url` are:
1. Processed in-memory for feature extraction
2. Analysed for phishing signals
3. **Discarded** — never written to disk or database
4. Returned as anonymised results (domain hashed in response)

```python
# From utils/privacy.py — domain is hashed before any logging
def anonymize_url(self, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    hashed_domain = hashlib.sha256(parsed.netloc.encode()).hexdigest()[:12]
    return f"{parsed.scheme}://{hashed_domain}/[path_redacted]"
```

### 3. PII Stripping

All log output is filtered to remove Personally Identifiable Information:

```python
# Emails and IPs are replaced before any logging
def strip_pii(self, text: str) -> str:
    text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL]', text)
    text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP]', text)
    return text
```

### 4. No External API Calls

The `PrivacyManager` class tracks all external API calls. In production:

```python
# Verified by unit tests in tests/test_detector.py
privacy = PrivacyManager()
# ... run all URL checks ...
privacy.verify_no_external_api_calls()  # Raises if any external call occurred
```

---

## Differential Privacy (Optional Telemetry)

For users who opt-in to anonymised usage telemetry, **differential privacy (ε=1.0)** is applied before any aggregation.

### What is Differential Privacy?

Differential privacy provides a mathematical guarantee that the output of an analysis does not significantly change whether or not any single individual's data is included.

The **privacy budget ε=1.0** (epsilon) provides:
- Strong privacy guarantee: adding/removing one URL from the dataset changes aggregate statistics by at most a factor of e¹ ≈ 2.718
- Balance between privacy and utility: sufficient accuracy for product improvement

### Implementation

```python
import numpy as np

def add_laplace_noise(value: float, sensitivity: float, epsilon: float = 1.0) -> float:
    """Apply Laplace mechanism for differential privacy.
    
    Args:
        value: The true statistic (e.g., daily phishing count)
        sensitivity: Maximum change one user's data can cause
        epsilon: Privacy budget (lower = more private)
    
    Returns:
        Noisy version of value with DP guarantee (ε=1.0)
    """
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale)
    return max(0.0, value + noise)

# Example: Report daily phishing detections with DP
def get_private_stats(raw_count: int) -> dict:
    return {
        "phishing_detected_approx": add_laplace_noise(raw_count, sensitivity=1.0),
        "privacy_budget": "ε=1.0 (Laplace mechanism)",
        "note": "Value is differentially private — individual URLs cannot be inferred"
    }
```

### What is Shared (Opt-In Only)

When telemetry is enabled, **only** the following is shared:
- Approximate count of phishing URLs detected (DP-noised)
- Approximate count of total URLs checked (DP-noised)
- App version and OS type (no device identifiers)

**Never shared:**
- Actual URLs checked
- Domain names
- Browser history
- Login credentials
- Any personally identifiable information

---

## Comparison with Cloud-Based Solutions

| Privacy Aspect | Sentinel Zero Local | Google Safe Browsing | Norton 360 |
|---------------|--------------------|--------------------|-----------|
| URLs sent to cloud | ❌ Never | ✅ Every URL checked | ✅ Every URL checked |
| Behavioral data | ❌ Never shared | N/A | ✅ Shared for "Smart Firewall" |
| Data retention | Session only | 2 weeks (Google policy) | Up to 1 year |
| Third-party sharing | ❌ Never | ✅ Google ecosystem | ✅ NortonLifeLock partners |
| GDPR compliant | ✅ By design | ⚠️ Requires opt-out | ⚠️ Complex privacy settings |
| India PDPB compliant | ✅ By design (no data processing) | ⚠️ Data sent to US servers | ⚠️ Data sent to US servers |

---

## Privacy Audit

As an open-source project (MIT license), anyone can audit:

1. **`utils/privacy.py`** — PII stripping and anonymization logic
2. **`app.py`** — No external HTTP calls in `/check-url` endpoint
3. **`extension/content.js`** — Only communicates with `localhost:5050`
4. **`extension/background.js`** — URL cache never sent externally
5. **`tests/test_detector.py`** — `TestPrivacyManager` class verifies zero external calls

```bash
# Verify no external API calls in tests
python -m pytest tests/test_detector.py::TestPrivacyManager -v
# All 6 privacy tests must pass
```

---

## DPDP Act 2023 Compliance (India)

The Digital Personal Data Protection Act, 2023 requires:

| Requirement | Our Implementation |
|------------|-------------------|
| Data minimisation | ✅ Only URLs processed; no user data collected |
| Purpose limitation | ✅ URLs used only for phishing detection, discarded immediately |
| Storage limitation | ✅ No persistent URL storage |
| Consent | ✅ Optional telemetry requires explicit opt-in |
| Data localisation | ✅ All processing on user's device (no cross-border transfer) |

---

## Reporting Privacy Issues

If you discover a privacy vulnerability:

1. **Do not** open a public GitHub issue
2. Email: security@sentinel-zero-local (TODO: add maintainer email)
3. Include: description, reproduction steps, potential impact
4. We commit to responding within 72 hours

See also: [SCOPE.md](SCOPE.md) for what the tool does and does not protect.
