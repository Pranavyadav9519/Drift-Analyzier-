# Drift Analyzer — SaaS Security Dashboard & Real-Time Monitor

> **Silent observation. Instant detection. Actionable rescue.**

Drift Analyzer is a powerful local-first security platform designed to protect users from high-risk web threats. It combines a **Machine Learning API**, a **Browser Extension**, and a **Real-Time SaaS Dashboard** to detect phishing, credential harvesting, and anomalous activity without ever storing your personal data.

**Zero Data Retention. Zero External Calls. Zero Latency Privacy.**

---

## 🚀 The Three Pillars

### 1. Phishing Detection API (`app.py`)
A fast-response Flask service that uses a **RandomForest classifier** to analyze 22+ URL features (length, subdomain count, TLD risk, etc.). It delivers a verdict and specific remedy steps in under 200ms.

### 2. Browser Extension (`extension/`)
The front-line defense. It intercepts every link click and form submission.
- **URL Interception**: Blocks high-risk navigation with a clear inline warning banner.
- **Credential Protection**: Detects login forms on phishing sites. If you type a password on a risky page, Drift Analyzer **blocks the submission** and triggers a secure OTP identity verification overlay.

### 3. SaaS Dashboard (`dashboard/`)
A premium, real-time interface for monitoring your security posture.
- **Live Threat Feed**: Watch browsing events and threats stream in as they happen.
- **Session Stats**: Visualize URL checks, blocked threats, and compromised credentials caught.
- **Zero-Storage Logging**: All events are stored in a circular in-memory buffer and wiped when the server restarts.

---

## 📁 Project Structure

```
drift-analyzer/
├── app.py                     # Core Flask API & Event Logger (Port 5050)
├── dashboard/                 # SaaS Dashboard UI (served at /dashboard)
│   └── index.html             # Real-time monitoring interface
├── extension/                 # Minimal Browser Extension
│   ├── background.js          # Service worker: Badge & Push notifications
│   ├── content.js             # The Interceptor: URL/Form analysis logic
│   └── popup.html/js          # Per-tab threat cards & remedies
├── ml-service/                # Anomaly Detection (Isolation Forest)
├── utils/                     # Metrics, Privacy, & Feature Extraction
├── core/                      # Remedy Engine & Threat Classification
└── requirements.txt           # Clean dependencies
```

---

## ⚡ Quick Start

### 1. Boot the API & Dashboard
```bash
# Install dependencies
pip install -r requirements.txt

# Start the Drift Analyzer engine
python app.py
```
The system starts on `http://localhost:5050`.

### 2. Access the Dashboard
Navigate to: **`http://localhost:5050/dashboard`**
You will see the "Waiting for data..." state until you browse with the extension.

### 3. Load the Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**.
3. Click **Load unpacked** → select the `extension/` folder.
4. Green badge = Drift Analyzer is active.

---

## 🛡️ Credential Protection Flow

When a user submits a login form, Drift Analyzer performs a silent real-time scan of the **current page URL**:
1. If the site is **PHISHING** or **SUSPICIOUS**:
   - The form submission is instantly cancelled.
   - A **Secure OTP Overlay** appears, simulating an identity check.
   - The event is logged as **CRITICAL: COMPROMISED CREDENTIAL** on your dashboard.
2. If the site is **SAFE**:
   - The submission proceeds with zero user friction.

---

## 🔗 API Reference

### `GET /dashboard`
Serves the premium monitoring UI.

### `GET /session-log`
Returns the recent list of browsing events (last 200) plus aggregated session stats.

### `POST /threat`
Analyzes a URL and returns a full JSON threat card with actionable remedies.
```json
{
  "verdict": "PHISHING",
  "risk_score": 0.95,
  "severity": "high",
  "description": " Strong signals of a harvest page detected.",
  "remedy_steps": ["Close tab", "Reset password if entered"]
}
```

### `POST /check-credential`
Logs a credential event when a login form is intercepted on a risky page.

---

## 🏗️ Key Principles

1. **Zero Data Storage** — We never write your browsing history or passwords to disk. Everything lives in RAM.
2. **True Privacy** — No external API calls (not even for ML). Everything is computed locally on your device.
3. **Actionable Security** — Every detected threat provides a "What to do next" list, turning alerts into solutions.

---

## 🛠️ Performance
- **URL Scanning**: ~15ms
- **ML Anomaly Scoring**: ~40ms
- **Dashboard Polling**: 0ms overhead (non-blocking)

*Drift Analyzer — Proactive security for the privacy-first era.*
