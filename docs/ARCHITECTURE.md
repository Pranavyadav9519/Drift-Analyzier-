# 🏗️ Sentinel Zero Local — System Architecture

## Overview

Sentinel Zero Local is a **multi-layer phishing detection system** combining a browser extension, a local API, an ML pipeline, and a real-time dashboard. Every component runs on-device with zero external API calls.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        USER'S DEVICE                                 │
│                                                                      │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │ Browser Extension│    │  Sentinel Zero   │    │   Frontend     │  │
│  │  (Chromium MV3) │───▶│  Local API       │◀───│  Dashboard     │  │
│  │  content.js     │    │  Flask :5050     │    │  React :3000   │  │
│  │  background.js  │    │                  │    │                │  │
│  └─────────────────┘    └────────┬─────────┘    └────────────────┘  │
│                                  │                                   │
│                         ┌────────▼─────────┐                        │
│                         │   ML Pipeline    │                        │
│                         │  TF-IDF +        │                        │
│                         │  DistilBERT ONNX │                        │
│                         └────────┬─────────┘                        │
│                                  │                                   │
│  ┌───────────────────────────────▼──────────────────────────────┐   │
│  │                     Backend (Node.js :5000)                   │   │
│  │  Auth │ Behavior Tracking │ Risk Engine │ Dashboard Stats     │   │
│  └───────────────────────────────┬──────────────────────────────┘   │
│                                  │                                   │
│                         ┌────────▼─────────┐                        │
│                         │    MongoDB       │                        │
│                         │   Port 27017     │                        │
│                         └──────────────────┘                        │
└──────────────────────────────────────────────────────────────────────┘
```

---

## ML Pipeline: TF-IDF + DistilBERT

```
Raw URL / Email Text
        │
        ▼
┌───────────────────────┐
│  Feature Extraction   │  ← utils/feature_extractor.py
│  (22 TF-IDF signals)  │
│  - URL length         │
│  - Domain heuristics  │
│  - HTTPS validity     │
│  - Phishing keywords  │
│  - Entropy score      │
│  - Subdomain depth    │
│  - Suspicious TLD     │
│  - IP in URL          │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  DistilBERT Classifier│  ← ml-models/train_distilbert.ipynb
│  (ONNX format)        │
│  Trained on:          │
│  - PhishTank 50K      │
│  - Indian corpus 5K   │
│  Inference: ~150ms    │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Risk Score Engine    │  ← utils/risk_scoring.py
│  Score 0–100 +        │
│  Explanation reasons  │
└───────────┬───────────┘
            │
        ┌───┴────────────────┐
        ▼                    ▼
  LOW (0–39)          MEDIUM/HIGH (40+)
  Green badge         Warning banner / Block
```

---

## Browser Extension Flow

```
User clicks link
        │
        ▼
content.js intercepts click event
        │
        ▼
background.js (service worker)
        │
        ├── Cache hit? → Return cached verdict
        │
        └── Cache miss?
                │
                ▼
         POST /check-url
         to localhost:5050
                │
                ▼
         Risk score returned
         (<200ms)
                │
        ┌───────┴──────────┐
        ▼                  ▼
   LOW / SAFE          PHISHING / SUSPICIOUS
   (no UI change)      Show warning banner
                       Update extension badge
```

The extension uses **Manifest V3** with:
- `content.js` — click event interceptor in page context
- `background.js` — service worker with URL queue and cache management
- No `webRequest` blocking (privacy-preserving: only scans on click)

---

## Risk Scoring Algorithm

```
Base Score = ML model output (0.0–1.0) × 50

Heuristic Bonuses:
  + contains_ip      → +20 pts  (IP in URL, not domain name)
  + !has_https       → +10 pts  (no SSL/TLS)
  + suspicious_tld   → +20 pts  (.xyz, .top, .tk, etc.)
  - is_trusted_domain→ -30 pts  (google.com, github.com, etc.)
  + phishing_kw × 7  → up to +20 pts (login, verify, paypal...)
  + subdomain × 5    → up to +15 pts (deep subdomain nesting)
  + at_sign × 10     → up to +10 pts (URL obfuscation)
  + hyphen × 2       → up to +10 pts (domain-with-hyphens)

Final = clamp(base + bonuses, 0, 100)

Thresholds:
  0–39  → LOW    (SAFE)
  40–69 → MEDIUM (SUSPICIOUS)
  70+   → HIGH   (PHISHING)
```

---

## Data Flow: Login Behavior Detection

```
User Login Request
        │
        ▼
Backend (auth.js route)
        │
        ├── Extract: IP, User-Agent, Login Hour, Device fingerprint
        │
        ▼
ML Service (POST /predict)
        │
        ├── Isolation Forest model
        └── Returns: anomaly_score (0.0–1.0)
        │
        ▼
Risk Engine (riskEngine.js)
        │
        ├── ML score × 50
        ├── New device +25
        └── Unusual hour +25
        │
        ▼
Decision:
  LOW    → Allow, log event
  MEDIUM → Allow + create Alert
  HIGH   → Reject login + trigger auto-healing
        │
        ▼
Dashboard updates via React polling
```

---

## Auto-Healing Responses

| Risk Level | Score Range | Actions |
|-----------|-------------|---------|
| LOW | 0–39 | Allow login, log event |
| MEDIUM | 40–69 | Allow + create alert + email notification |
| HIGH | 70–100 | Reject login + mark identity `compromised` + force password reset |

---

## Microservices Communication

```
Frontend (React :3000)
    │  HTTP REST (JWT Bearer)
    ▼
Backend (Node.js :5000)
    │  HTTP POST JSON
    ▼
ML Service (Python Flask :5001)    ← Isolation Forest (behavior)
    │
    ▼
MongoDB :27017

Browser Extension
    │  HTTP POST JSON (local only)
    ▼
Phishing API (Python Flask :5050)  ← TF-IDF + DistilBERT (URLs)
```

---

## Privacy Architecture

All components enforce a **zero-exfiltration** policy:

1. **Browser Extension**: Sends URLs only to `localhost:5050` (never to external servers)
2. **Phishing API**: Stores no URLs persistently; processes in-memory only
3. **ML Models**: Inference runs locally via ONNX Runtime
4. **Telemetry (optional)**: Anonymised with differential privacy (ε=1.0) before any aggregation
5. **Logs**: PII (emails, IPs) stripped before writing via `PrivacyManager.strip_pii()`

See [PRIVACY.md](PRIVACY.md) for full details.
