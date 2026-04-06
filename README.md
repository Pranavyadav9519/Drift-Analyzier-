# Drift Analyzer

> **Quietly observe. Instantly detect. Tell you exactly what to do.**

Drift Analyzer is a local-only threat detection system. It silently watches your browser activity and system behavior, detects phishing, anomalous access, root escalation attempts, and social engineering — then triggers an alert with step-by-step remedy instructions.

**Zero data storage. Zero external calls. Fast detection. User-centric alerts.**

---

## What It Does

| Component | What it watches | How it alerts |
|---|---|---|
| **Browser Extension** | Every URL you navigate to | Red badge + inline banner + OS notification |
| **Phishing API** | URL features (22 signals, RandomForest) | Returns verdict + remedy steps in <200ms |
| **ML Service** | Login/access time patterns (Isolation Forest) | Returns threat score + remedy steps |
| **System Monitor** | Process activity, privilege escalation, network connections | Native OS desktop notification |

---

## Project Structure

```
drift-analyzer/
├── app.py                     # Flask phishing detection API (port 5050)
├── config.py                  # Shared configuration
├── requirements.txt
├── Dockerfile
│
├── ml-service/                # Isolation Forest anomaly detection (port 5001)
│   ├── app.py
│   ├── model.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── core/                      # Shared detection logic (no UI, no DB)
│   ├── remedy_engine.py       # Maps threat types to actionable fix steps
│   ├── threat_classifier.py   # Converts raw scores to canonical threat types
│   ├── logger.py              # In-memory circular event buffer
│   └── __init__.py
│
├── monitor/                   # Silent background system observer
│   ├── system_monitor.py      # Orchestrates all monitoring threads
│   ├── process_analyzer.py    # Detects suspicious processes + privilege escalation
│   ├── network_analyzer.py    # Detects unusual network connections
│   └── requirements.txt
│
├── extension/                 # Minimal browser extension (Chrome/Edge)
│   ├── manifest.json
│   ├── background.js          # Service worker: badge + OS notifications
│   ├── content.js             # URL interceptor on every page
│   ├── popup.html             # Threat card + remedy list
│   ├── popup.js
│   └── styles.css
│
├── utils/                     # Feature extraction + privacy utilities
│   ├── feature_extractor.py
│   ├── privacy.py
│   └── metrics.py
│
├── models/                    # Pre-trained ML model files (not committed to git)
│   ├── phishing_model.joblib
│   └── feature_names.joblib
│
├── tests/
│   └── test_detector.py
│
└── docker-compose.yml         # Only 2 services: phishing-api + ml-service
```

---

## Quick Start

### Option 1 — Docker (recommended)

```bash
docker compose up
```

This starts both core services:
- Phishing API: http://localhost:5050
- ML Service: http://localhost:5001

### Option 2 — Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Train the model (first time only)
python train_model.py

# Start the phishing API
python app.py

# In a separate terminal, start the ML service
cd ml-service && python app.py

# In a separate terminal, start the system monitor
cd monitor && python system_monitor.py
```

### Load the Browser Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The Drift Analyzer badge should appear in your toolbar (green = active)

---

## API Reference

### Phishing API (`localhost:5050`)

#### `POST /threat`
Concise threat card — the endpoint the extension uses for user-facing alerts.

**Request:**
```json
{ "url": "http://paypal-secure-login.xyz/verify?token=abc" }
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "risk_score": 0.92,
  "threat_type": "phishing_url",
  "severity": "high",
  "description": "A URL you were about to visit shows strong signs of being a phishing page.",
  "remedy_steps": [
    "Do NOT click the link or enter any information on that page.",
    "Close the tab immediately if you already opened it.",
    "Report the URL to Google Safe Browsing.",
    "If you typed a password there, change it on the real site right now.",
    "Enable two-factor authentication on any account that may be affected.",
    "Run a quick antivirus scan to check for drive-by malware downloads."
  ],
  "latency_ms": 18.4
}
```

#### `POST /check-url`
Full analysis with raw feature vector (for debugging/research).

#### `GET /remedies/<threat_type>`
Returns the full remedy card for any threat type.

**Supported threat types:**
- `phishing_url`
- `anomalous_login`
- `root_access_attempt`
- `social_engineering`
- `suspicious_process`
- `usb_anomaly`
- `network_anomaly`

**Example:**
```bash
curl http://localhost:5050/remedies/root_access_attempt
```

#### `GET /stats`
In-session performance metrics (in-memory only, nothing persisted).

#### `GET /privacy-report`
Confirms zero external API calls have been made.

---

### ML Service (`localhost:5001`)

#### `POST /threat/predict`
Detect anomalous login/access patterns and return remedy steps.

**Request:**
```json
{
  "userId": "user-123",
  "loginHour": 3,
  "loginDayOfWeek": 6,
  "isNewDevice": 1
}
```

**Response:**
```json
{
  "is_threat": true,
  "anomaly_score": -0.24,
  "threat_type": "anomalous_login",
  "severity": "medium",
  "description": "A login event was detected that falls outside your normal usage patterns.",
  "remedy_steps": [
    "Check your active sessions and log out of all unfamiliar devices.",
    "Change your password immediately.",
    "Enable two-factor authentication.",
    ...
  ]
}
```

#### `POST /train`
Train an Isolation Forest model for a user (in-memory, session-only).

#### `POST /predict`
Raw anomaly score without remedy steps.

---

## Key Principles

1. **Zero Data Storage** — Nothing persists to disk or database. All models and events live in RAM and are wiped on restart.
2. **Local Only** — No external API calls. No cloud. No telemetry. Your data never leaves your device.
3. **Fast Detection** — Phishing checks in <200ms. Anomaly scoring in real time.
4. **User-Centric Alerts** — Every threat comes with a numbered list of "what to do right now" steps.
5. **Minimal UI** — Extension badge (green/red) + native OS notification. No dashboard to babysit.

---

## Running the System Monitor

The system monitor watches host-level processes and network connections — it intentionally runs **directly on the host**, not inside Docker, because container isolation would prevent it from seeing real OS activity.

```bash
# Install the single optional dependency
pip install psutil>=5.9.0

# Run the monitor from the repo root
python -m monitor.system_monitor
```

It spawns three background threads (process watcher, privilege-escalation watcher, network watcher) and blocks until `Ctrl+C`. All events live in RAM; nothing is written to disk.

> **Note:** On Linux you may need `sudo` for full process visibility. On macOS, grant Terminal/Python the *Full Disk Access* and *Accessibility* permissions in System Preferences → Privacy & Security if privilege-escalation events are not detected.

---

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Threat Types and Remedies

| Threat Type | Trigger | Severity | Key Remedy |
|---|---|---|---|
| `phishing_url` | URL risk score ≥ 0.5 | High | Don't click, change password if entered |
| `anomalous_login` | Isolation Forest anomaly | Medium | Check sessions, change password, enable 2FA |
| `root_access_attempt` | Privilege escalation detected | Critical | Deny request, disconnect, run AV scan |
| `social_engineering` | Behavioural manipulation patterns | High | Verify via separate channel, never share OTP |
| `suspicious_process` | Known malicious process name | Medium | Identify, terminate, run AV scan |
| `usb_anomaly` | Unexpected USB device | Medium | Remove device, check auto-launched files |
| `network_anomaly` | Connection to suspicious port | Medium | Check netstat, block with firewall |
