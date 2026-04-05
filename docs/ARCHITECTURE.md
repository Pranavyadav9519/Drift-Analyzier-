# System Architecture — Sentinel Zero Local

## Overview

Sentinel Zero Local is a privacy-first endpoint security agent that detects phishing links and anomalous login behaviour entirely on-device.  All inference runs locally; no URL or event data is ever sent to an external server.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User's Machine                           │
│                                                                 │
│  ┌──────────────┐   click/URL   ┌─────────────────────────┐    │
│  │   Browser    │ ────────────► │  Chromium Extension     │    │
│  │  (Chrome /   │               │  content.js / popup.js  │    │
│  │   Edge /     │ ◄──risk badge─│  Manifest v3            │    │
│  │   Brave)     │               └────────────┬────────────┘    │
│  └──────────────┘                            │ POST /check-url  │
│                                              ▼                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Flask Standalone API  (app.py)              │  │
│  │  • URLFeatureExtractor  (tldextract, regex, entropy)     │  │
│  │  • Rule-based scorer (no model needed)                   │  │
│  │  • Optional ML classifier  (Random Forest / joblib)     │  │
│  │  • MetricsTracker  (latency, SLA, TPR/FPR)              │  │
│  │  • PrivacyManager  (zero external calls enforced)        │  │
│  └───────────────────────────────┬──────────────────────────┘  │
│                                  │ JSON response               │
│  ┌───────────────────────────────▼──────────────────────────┐  │
│  │              React Frontend Dashboard                    │  │
│  │  (Vite + Tailwind)  Real-time risk graph, alert feed     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │          Node.js / Express Backend  (backend/)           │  │
│  │  • JWT authentication  (bcrypt password hashing)        │  │
│  │  • Rate-limiting  (express-rate-limit)                  │  │
│  │  • Login-event persistence  (MongoDB via Mongoose)      │  │
│  │  • Risk Engine  (ML score + heuristics → 0–100 score)   │  │
│  └──────────────────────┬────────────────┬─────────────────┘  │
│                         │                │                      │
│         ┌───────────────▼──┐    ┌────────▼─────────┐          │
│         │   MongoDB        │    │  ML Microservice  │          │
│         │  (login events,  │    │  (Flask, port     │          │
│         │   alerts, users) │    │   5001)           │          │
│         └──────────────────┘    │  Isolation Forest │          │
│                                 │  per-user models  │          │
│                                 └───────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Browser Extension (`extension/`)

| File | Purpose |
|------|---------|
| `manifest.json` | Manifest v3 config, permissions |
| `content.js` | Intercepts link clicks, calls local API |
| `popup.js` / `popup.html` | Extension popup UI with risk badge |
| `styles.css` | Popup styling |

**Flow:** User clicks a link → `content.js` intercepts → POSTs URL to `app.py /check-url` → receives risk score → displays colour-coded badge (green / amber / red).

### 2. Standalone Detection API (`app.py`)

Entry point for the browser extension.  Runs on `http://localhost:5000`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/check-url` | POST | Analyse URL, return risk score 0–100 |
| `/stats` | GET | Aggregated TP/FP metrics since start |
| `/privacy-report` | GET | Confirm zero external API calls |
| `/dashboard` | GET | Live HTML monitoring dashboard |

### 3. Feature Extractor (`utils/feature_extractor.py`)

Extracts ≥20 numerical features from a raw URL in <100 ms:

- URL length, path depth, query parameter count
- Entropy of URL string (high entropy → randomised phishing domains)
- IP address in host detection
- HTTPS presence
- Suspicious TLD list (`.xyz`, `.tk`, `.ml`, `.ga`, …)
- Phishing keyword count (`login`, `secure`, `verify`, `account`, …)
- Subdomain depth
- Trusted domain whitelist lookup

### 4. Node.js Backend (`backend/`)

Handles user accounts and persistent login-event storage.

| Module | Responsibility |
|--------|---------------|
| `src/routes/auth.js` | Signup, login with ML risk scoring |
| `src/routes/dashboard.js` | Dashboard stats |
| `src/routes/risk.js` | Alert management, risk reset |
| `src/routes/behavior.js` | Training the per-user ML model |
| `src/utils/riskEngine.js` | Score computation + auto-healing |
| `src/middleware/auth.js` | JWT verification middleware |
| `src/models/` | Mongoose schemas (User, LoginEvent, Alert) |

### 5. ML Microservice (`ml-service/`)

Lightweight Flask service for per-user Isolation Forest models.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness probe |
| `/train` | POST | Train model for a given userId |
| `/predict` | POST | Predict anomaly score for a login event |

### 6. React Frontend (`frontend/`)

Built with Vite + React + Tailwind CSS.  Served via Nginx in Docker.

- Real-time risk gauge (0–100)
- Login history timeline
- Alert feed with resolve action
- Identity status indicator (normal / at_risk / compromised)

---

## Risk Scoring Algorithm

```
risk_score = 0

# ML contribution (0–50 pts)
if isAnomaly:
    risk_score += min(50, abs(isolation_forest_score) * 100)

# Contextual signals
if isNewDevice:      risk_score += 25
if loginHour < 8
   or loginHour > 22: risk_score += 25

risk_score = min(100, risk_score)
```

| Score Range | Level | Action |
|-------------|-------|--------|
| 0–39 | LOW | Allow login |
| 40–69 | MEDIUM | Raise alert, mark user `at_risk` |
| 70–100 | HIGH | Terminate session, force password reset |

---

## Data Flow: Login Event

```
POST /api/auth/login
        │
        ├─► Verify credentials (bcrypt)
        │
        ├─► Extract: UA, IP, hour, day-of-week, isNewDevice
        │
        ├─► POST ml-service /predict
        │         └─► Isolation Forest → anomalyScore, isAnomaly
        │
        ├─► computeRiskScore() → 0–100
        │
        ├─► Save LoginEvent to MongoDB
        │
        ├─► applyAutoHealing() → create Alert if medium/high
        │
        └─► Return JWT + { riskScore, riskLevel, action }
```

---

## Privacy Guarantee

- All ML inference runs on-device (no URL sent externally)
- `PrivacyManager` tracks and enforces zero external API calls
- Optional telemetry uses differential privacy (ε = 1.0, planned)
- Open-source codebase for community audit

---

## Deployment Topology

```
docker-compose up --build
      │
      ├─ frontend   → port 3000  (Nginx + React)
      ├─ backend    → port 5000  (Node.js / Express)
      ├─ ml-service → port 5001  (Flask / Isolation Forest)
      └─ mongodb    → port 27017 (MongoDB 6)
```
