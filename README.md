# 🛡️ Sentinel Zero — Privacy-First On-Device Identity & Link Shield

> **Hackathon MVP** · Phishing URL Detection · Login Anomaly Detection · Auto-Healing · Real-time Dashboard

Sentinel Zero is a **dual-protection security system** that runs 100% locally on your machine.  
It detects phishing links in real time *and* learns your normal login behaviour to flag suspicious sessions — with zero data leaving your device.

---

## 🎯 What It Does

| Feature | Description |
|---|---|
| 🔗 Phishing Detection | Flask API analyses every clicked URL — rule-based heuristics + trained RandomForest |
| 🔌 Browser Extension | Chromium extension intercepts link clicks and shows SAFE / SUSPICIOUS / PHISHING badge |
| 🔐 Login Anomaly Detection | Isolation Forest ML learns normal login patterns and flags unusual sessions |
| ⚠️ Risk Scoring | Combines ML anomaly score + new device + unusual hour → 0–100 risk score |
| 🤖 Decision Engine | Low → allow · Medium → alert · High → terminate session + force password reset |
| 🔄 Auto-Healing | Blocks navigation, locks sessions, or forces password reset automatically |
| 🖥️ Dual Dashboard | Live phishing stats (HTML) + React login-anomaly dashboard |
| 🔒 Privacy-First | 100% local processing — no URLs, emails, or credentials ever leave the machine |

---

## 🧱 Architecture

```
╔══════════════════════════════════════════════════════════════════════════╗
║                        SENTINEL ZERO — HYBRID SYSTEM                    ║
╠══════════════════════════╦═══════════════════════════════════════════════╣
║  LAYER 1 — BROWSER       ║  LAYER 3 — BEHAVIOR ANOMALY                  ║
║  Chrome Extension        ║  Node.js Backend (port 5000)                 ║
║  • Intercepts link clicks║  • JWT auth, login event capture             ║
║  • Calls phishing API    ║  • Calls ML service → risk score              ║
║  • Shows risk badge      ║  • Auto-healing: terminate / reset            ║
╠══════════════════════════╬═══════════════════════════════════════════════╣
║  LAYER 2 — PHISHING API  ║  LAYER 3b — ML MICROSERVICE                  ║
║  Flask (port 5050)       ║  Python / Flask (port 5001)                  ║
║  • Extract 22 URL        ║  • Isolation Forest (unsupervised)            ║
║    features              ║  • Trains on user login history               ║
║  • Rule-based scoring    ║  • Returns anomaly score per login            ║
║  • RandomForest model    ║                                               ║
║  • <200 ms verdict       ║                                               ║
╠══════════════════════════╩═══════════════════════════════════════════════╣
║  LAYER 4 — DASHBOARDS                                                    ║
║  Phishing dashboard  → http://localhost:8080  (static HTML + Chart.js)  ║
║  Behavior dashboard  → http://localhost:3000  (React + Tailwind)        ║
╚══════════════════════════════════════════════════════════════════════════╝
                            ↕ shared data store
                       MongoDB (port 27017)
```

**Why this design?**
- **No cloud dependency** — everything runs in Docker on your laptop
- **Two orthogonal threats** — phishing links (Layer 2) vs. stolen credentials (Layer 3) need different ML models
- **Isolation Forest** requires zero labelled anomaly data — it learns "normal" and flags deviations
- **RandomForest** for URL classification achieves >90% accuracy on 22 hand-crafted features

---

## 📁 Folder Structure

```
sentinel-zero/
│
├── 🔗 PHISHING LINK DETECTION
│   ├── app.py                      # Flask API: /check-url, /stats, /dashboard
│   ├── config.py                   # Thresholds (high=0.8, medium=0.5)
│   ├── Dockerfile                  # Container for the phishing API
│   ├── requirements.txt
│   ├── train_model.py              # Train RandomForest on data/
│   ├── utils/
│   │   ├── feature_extractor.py    # 22 URL features (entropy, TLD, keywords…)
│   │   ├── metrics.py              # Latency tracker, SLA compliance
│   │   └── privacy.py             # URL anonymisation, PII stripping
│   ├── models/
│   │   ├── phishing_model.joblib   # Pre-trained RandomForest
│   │   └── feature_names.joblib   # Feature order for inference
│   ├── data/
│   │   ├── phishing_urls.csv       # ~550 labelled phishing URLs
│   │   └── legitimate_urls.csv    # ~550 labelled legitimate URLs
│   ├── extension/                  # Chromium extension (Manifest V3)
│   │   ├── manifest.json
│   │   ├── content.js              # Click interceptor
│   │   └── popup.{html,js}        # URL check UI
│   ├── dashboard/                  # Standalone phishing stats dashboard
│   │   ├── index.html
│   │   ├── dashboard.js
│   │   └── styles.css
│   └── tests/
│       └── test_detector.py        # 43 unit tests
│
├── 🔐 BEHAVIOR ANOMALY DETECTION
│   ├── backend/                    # Node.js Express API
│   │   └── src/
│   │       ├── routes/auth.js      # POST /login — capture + score login
│   │       ├── utils/riskEngine.js # Risk score + auto-healing logic
│   │       └── server.js
│   ├── ml-service/                 # Python Flask ML microservice
│   │   ├── app.py                  # POST /train, POST /predict
│   │   ├── model.py                # Isolation Forest wrapper
│   │   └── seed_data.py           # Demo login events for MongoDB
│   └── frontend/                   # React + Tailwind security dashboard
│       └── src/pages/DashboardPage.jsx
│
└── docker-compose.yml              # Single command to start all 6 services
```

---

## 🚀 Quick Start

### Option A — Docker Compose (Recommended)

```bash
docker-compose up --build
```

| Service | URL | Purpose |
|---|---|---|
| Phishing API | http://localhost:5050 | `/check-url`, `/stats`, `/privacy-report` |
| Phishing Dashboard | http://localhost:8080 | Live phishing metrics chart |
| Behavior Backend | http://localhost:5000 | Login auth + risk scoring |
| ML Service | http://localhost:5001 | Isolation Forest `/train` + `/predict` |
| Behavior Dashboard | http://localhost:3000 | React anomaly dashboard |
| MongoDB | localhost:27017 | Login event storage |

### Option B — Manual (Python only, for demo)

```bash
# Install dependencies
pip install -r requirements.txt

# (Optional) retrain the RandomForest model
python train_model.py          # prints accuracy, saves models/phishing_model.joblib

# Start the phishing detection API
python app.py                  # → http://localhost:5050

# Open the dashboard
open dashboard/index.html      # or browse to http://localhost:5050/dashboard

# Load the extension in Chrome
# chrome://extensions → Developer mode → Load unpacked → select extension/
```

---

## 🔌 Browser Extension Setup

1. Open **chrome://extensions**
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The Sentinel Zero icon appears in the toolbar — click to check any URL manually

> The extension intercepts *every* link click, sends the URL to `http://localhost:5050/check-url`, and shows a warning banner for SUSPICIOUS or PHISHING verdicts.

---

## 🔑 API Reference

### Phishing Detection API (`http://localhost:5050`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/check-url` | Analyse a URL → verdict + risk score |
| `GET` | `/stats` | Aggregated latency and detection metrics |
| `GET` | `/privacy-report` | Confirm zero external API calls |
| `GET` | `/dashboard` | Embedded live dashboard |

**Example:**
```bash
curl -s -X POST http://localhost:5050/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://paypal-secure-login.xyz/account/verify"}' | python -m json.tool
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "risk_score": 0.87,
  "risk_level": "high",
  "latency_ms": 12.4,
  "model_used": "RandomForest"
}
```

### Behavior Anomaly Backend (`http://localhost:5000`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/signup` | Create account |
| `POST` | `/api/auth/login` | Login + receive risk score |
| `GET` | `/api/behavior/history` | Login history |
| `GET` | `/api/risk/alerts` | Security alerts |
| `GET` | `/api/dashboard/stats` | Aggregated dashboard stats |

---

## 📊 Risk Scoring Logic

### Phishing URL Scoring (0–1)

```
score = 0
score += url_length / 200          # max +0.15  — long URLs are suspicious
score += 0.20  if contains_ip      # IP address instead of domain
score += 0.10  if not has_https    # no encryption
score += 0.20  if suspicious_tld   # .xyz, .top, .club, .tk …
score -= 0.30  if trusted_domain   # google.com, github.com …
score += keywords × 0.07           # "login", "verify", "paypal" …
score += subdomains × 0.05         # many subdomains = suspicious
─────────────────────────────────────────
≥ 0.80 → PHISHING (block navigation)
≥ 0.50 → SUSPICIOUS (show warning)
< 0.50 → SAFE (allow navigation)
```

### Login Anomaly Scoring (0–100)

```
score = 0
score += ML anomaly contribution   # Isolation Forest score × 100 (max 50)
score += 25  if new device         # user-agent never seen before
score += 25  if unusual hour       # before 8am or after 10pm
─────────────────────────────────────────
≥ 70 → HIGH   → terminate session + force password reset
40–69 → MEDIUM → alert user, mark account at_risk
< 40  → LOW   → allow login
```

---

## 🧪 Testing

```bash
# Unit tests (43 tests — feature extraction, privacy, metrics)
python -m pytest tests/ -v

# End-to-end validation (start API first with `python app.py`)
python test_end_to_end.py

# Quick smoke test of the phishing API
curl -X POST http://localhost:5050/check-url \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://www.google.com"}'
# → {"verdict": "SAFE", ...}
```

---

## 🎤 2-Minute Hackathon Pitch

> **"Every 39 seconds a new phishing attack happens. Traditional antivirus waits for signature updates. Sentinel Zero detects it in under 200 milliseconds — entirely on your machine."**

Sentinel Zero is a **dual-threat security agent**:

1. **Link Shield** — Our RandomForest model (trained on 1,000+ URLs, >90% accuracy) inspects every link you click via a Chrome extension. Phishing links are blocked instantly; the verdict is shown in a banner.

2. **Identity Guard** — Isolation Forest learns your normal login patterns. A 3am login from a new device scores 95/100 — session terminated, password reset triggered automatically.

**Key differentiators:**
- 🔒 Zero data leaves your machine (privacy report proves it)
- ⚡ Sub-200ms detection latency (p95 < 200ms SLA)
- 🐳 One command to deploy: `docker-compose up --build`
- 📖 Clean, readable code — every decision explained in comments

---

## 📄 License

MIT — see [LICENSE](LICENSE)
