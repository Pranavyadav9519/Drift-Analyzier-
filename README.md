# 🛡️ Sentinel Zero — AI-Powered Identity Security System

> **Hackathon MVP** · Identity Drift Detection · Auto-Healing · Real-time Dashboard

Sentinel Zero monitors user login behavior, detects anomalies using machine learning (Isolation Forest), assigns a risk score, and automatically triggers security actions — all displayed in a clean real-time dashboard.

---

## 🎯 What It Does

| Feature | Description |
|---|---|
| 🔐 Auth System | JWT-based login/signup with bcrypt password hashing |
| 📊 Behavior Tracking | Captures login time, device (user-agent), IP per login |
| 🧠 Anomaly Detection | Isolation Forest ML model detects unusual login patterns |
| ⚠️ Risk Scoring | Combines ML score + new device + unusual hour → 0–100 score |
| 🤖 Decision Engine | Low → allow · Medium → alert · High → terminate + reset |
| 🔄 Auto-Healing | Simulates session termination & forced password reset in DB |
| 🖥️ Dashboard | Live stats, risk gauge, trend chart, alerts, login history |

---

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL ZERO                            │
├──────────────┬─────────────────────┬───────────────────────────┤
│   Frontend   │      Backend        │       ML Service           │
│  React 18    │  Node.js / Express  │    Python / Flask          │
│  Tailwind    │  JWT Auth           │    Isolation Forest        │
│  Recharts    │  REST APIs          │    scikit-learn            │
│  Port 3000   │  Port 5000          │    Port 5001               │
└──────┬───────┴──────────┬──────────┴──────────┬────────────────┘
       │                  │                     │
       └──────────────────┼─────────────────────┘
                          │
                    ┌─────▼──────┐
                    │  MongoDB   │
                    │  Port 27017│
                    └────────────┘
```

**Why Node.js for backend?**
- Fast I/O for handling concurrent login events
- Rich ecosystem (mongoose, jwt, bcrypt)
- Easy REST API setup with Express
- The ML-heavy work is offloaded to the Python microservice

**Why Isolation Forest?**
- Unsupervised — no labeled anomaly data needed
- Trains on "normal" behavior, detects outliers
- Works well with small datasets (hackathon friendly)
- Fast prediction (<5ms per login)

---

## 📁 Folder Structure

```
sentinel-zero/
├── backend/                    # Node.js Express API
│   ├── src/
│   │   ├── models/
│   │   │   ├── User.js         # User schema (auth + identity status)
│   │   │   ├── LoginEvent.js   # Login behavior record
│   │   │   └── Alert.js        # Security alert
│   │   ├── routes/
│   │   │   ├── auth.js         # POST /login, POST /signup, GET /profile
│   │   │   ├── behavior.js     # GET /history, GET /anomalies, POST /train
│   │   │   ├── risk.js         # GET /alerts, GET /score, POST /reset
│   │   │   └── dashboard.js    # GET /stats
│   │   ├── middleware/
│   │   │   └── auth.js         # JWT verification middleware
│   │   ├── utils/
│   │   │   └── riskEngine.js   # Risk scoring + auto-healing logic
│   │   └── server.js           # Express app entry point
│   ├── Dockerfile
│   ├── package.json
│   └── .env.example
│
├── ml-service/                 # Python Flask ML microservice
│   ├── app.py                  # Flask API (POST /train, POST /predict)
│   ├── model.py                # Isolation Forest logic
│   ├── seed_data.py            # MongoDB seed script for demo
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                   # React + Tailwind dashboard
│   ├── src/
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx
│   │   │   ├── SignupPage.jsx
│   │   │   └── DashboardPage.jsx
│   │   ├── components/
│   │   │   ├── Navbar.jsx
│   │   │   ├── StatsCards.jsx
│   │   │   ├── RiskGauge.jsx
│   │   │   ├── RiskTrendChart.jsx
│   │   │   ├── AlertsList.jsx
│   │   │   ├── LoginHistoryTable.jsx
│   │   │   └── IdentityHealthBadge.jsx
│   │   ├── contexts/
│   │   │   └── AuthContext.jsx
│   │   ├── services/
│   │   │   └── api.js          # Axios instance
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
│
├── docker-compose.yml
└── README.md
```

---

## 🚀 Quick Start — Local Development

### Prerequisites
- Node.js 18+
- Python 3.10+
- MongoDB (local or [MongoDB Atlas](https://www.mongodb.com/atlas))

### 1. Clone the repository

```bash
git clone https://github.com/Pranavyadav9519/Drift-Analyzier-.git
cd Drift-Analyzier-
```

### 2. Start the ML Service

```bash
cd ml-service
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
# ✅ ML service running on http://localhost:5001
```

### 3. Start the Backend

```bash
cd backend
cp .env.example .env            # Edit .env with your MongoDB URI if needed
npm install
npm run dev
# ✅ Backend running on http://localhost:5000
```

### 4. Start the Frontend

```bash
cd frontend
npm install
npm run dev
# ✅ Frontend running on http://localhost:3000
```

### 5. Open the App

Navigate to **http://localhost:3000**, create an account, and start exploring!

---

## 🐳 Docker Compose (All-in-One)

```bash
docker-compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:5000 |
| ML Service | http://localhost:5001 |
| MongoDB | localhost:27017 |

---

## 🔌 API Reference

### Auth

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/signup` | Create account |
| POST | `/api/auth/login` | Login + get risk score |
| GET | `/api/auth/profile` | Get current user (auth required) |

### Behavior

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/behavior/history` | Login history |
| GET | `/api/behavior/anomalies` | Anomalous logins only |
| POST | `/api/behavior/train` | Train ML model on login history |

### Risk

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/risk/alerts` | Security alerts |
| PATCH | `/api/risk/alerts/:id/resolve` | Resolve alert |
| GET | `/api/risk/score` | Latest risk score |
| POST | `/api/risk/reset` | Reset identity health |

### Dashboard

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/dashboard/stats` | Aggregated dashboard stats |

### ML Service

| Method | Endpoint | Description |
|---|---|---|
| POST | `/train` | Train Isolation Forest for a user |
| POST | `/predict` | Predict anomaly score |

---

## 📊 Risk Scoring Logic

```
Risk Score (0–100) =
  ML Anomaly Score contribution  (0–50 points)
  + New Device                   (+25 points)
  + Unusual hour (before 8am     (+25 points)
    or after 10pm)

Risk Level:
  0–39  → LOW    → Allow login
  40–69 → MEDIUM → Show alert, mark identity at_risk
  70+   → HIGH   → Terminate session, force password reset
```

---

## 🧪 Demo Flow

1. **Sign up** as a new user (e.g., `alice`)
2. **Log in** normally → Risk score should be Low (green)
3. **Simulate anomaly**: Edit `loginHour` in the request to 3 (3am) or use a different user-agent
4. **View Dashboard** → See updated risk score, anomaly in history
5. **Check Alerts** → Auto-healing actions are shown
6. **Resolve alerts** and **Reset Identity Health**

### Test Credentials (after running seed_data.py)

```
Username: alice / Password: password123
Username: bob   / Password: password123
```

> ⚠️ seed_data.py inserts sample login events only. You still need to sign up via the UI.

---

## 🔮 Future Scope

| Feature | Technology |
|---|---|
| Real-time anomaly stream | Apache Kafka + WebSockets |
| Cloud deployment | Azure App Service + Cosmos DB |
| Advanced ML | Autoencoder (deep anomaly detection) |
| Geo-location tracking | MaxMind GeoIP2 |
| SIEM integration | Microsoft Sentinel / Splunk |
| Mobile 2FA challenge | Twilio / Firebase |
| Continuous learning | Online ML (River library) |

---

## 🎤 2-Minute Hackathon Pitch

> **"Every day, 4.1 billion credentials are exposed. Traditional security reacts too late."**

Sentinel Zero is an AI-powered identity guardian that **learns what normal looks like** for each user — their login hours, devices, and patterns — and instantly flags when something drifts.

When a login looks suspicious, Sentinel doesn't just log it. It **acts**:
- 🟡 Medium risk → alert the user
- 🔴 High risk → terminate the session and force a password reset

Our Isolation Forest ML model requires **zero labeled training data** — it learns from normal behavior and detects the unusual. The entire system runs as three clean microservices and displays everything in a real-time security dashboard.

**Built in 24 hours. Production-ready architecture. Zero blind spots.**

---

## 📄 License

MIT — see [LICENSE](LICENSE)