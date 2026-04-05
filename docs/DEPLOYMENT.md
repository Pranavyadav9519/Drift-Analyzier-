# Deployment Guide — Sentinel Zero Local

## Quick Start (Docker Compose)

The fastest way to run the full stack:

```bash
git clone https://github.com/Pranavyadav9519/Drift-Analyzier-.git
cd Drift-Analyzier-

# Copy environment files
cp backend/.env.example backend/.env
cp ml-service/.env.example ml-service/.env

# Build and start all services
docker-compose up --build
```

Services will be available at:

| Service | URL |
|---------|-----|
| Frontend (React) | http://localhost:3000 |
| Backend API | http://localhost:5000 |
| ML Microservice | http://localhost:5001 |
| MongoDB | localhost:27017 |

---

## Manual Setup (Development)

### Prerequisites

- Node.js 18+
- Python 3.10+
- MongoDB 6 (local or Atlas)

### 1. Backend

```bash
cd backend
cp .env.example .env           # edit MONGO_URI and JWT_SECRET
npm install
npm start                      # or: npm run dev (nodemon)
```

### 2. ML Microservice

```bash
cd ml-service
cp .env.example .env
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                  # starts on port 5001
```

### 3. Standalone Phishing API

```bash
# from project root
pip install -r requirements.txt
python train_model.py          # optional — builds models/phishing_model.joblib
python app.py                  # starts on port 5000
```

### 4. Frontend

```bash
cd frontend
npm install
npm run dev                    # Vite dev server on port 5173
```

### 5. Browser Extension

1. Open Chrome / Edge / Brave
2. Navigate to `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** → select the `extension/` directory
5. The Sentinel Zero icon will appear in the toolbar

---

## Environment Variables

### `backend/.env`

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Express server port |
| `MONGO_URI` | `mongodb://localhost:27017/sentinel_zero` | MongoDB connection string |
| `JWT_SECRET` | *(set a strong random value)* | JWT signing secret |
| `ML_SERVICE_URL` | `http://localhost:5001` | ML microservice base URL |
| `NODE_ENV` | `development` | Node environment |

### `ml-service/.env`

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5001` | Flask server port |
| `FLASK_ENV` | `development` | Flask environment |
| `MODELS_DIR` | `models/` | Directory for per-user `.pkl` files |

---

## Production Checklist

- [ ] Set `JWT_SECRET` to a cryptographically random 64-character string
- [ ] Set `NODE_ENV=production`
- [ ] Set `FLASK_ENV=production`
- [ ] Use MongoDB Atlas or a secured self-hosted instance
- [ ] Enable HTTPS (reverse proxy: Nginx / Caddy)
- [ ] Restrict CORS origins in `backend/src/server.js`
- [ ] Limit rate-limiting thresholds to production values
- [ ] Rotate JWT secret periodically
- [ ] Back up `ml-service/models/` directory (contains trained per-user models)

---

## Seeding Demo Data

To pre-populate the ML model for a demo user:

```bash
python ml-service/seed_data.py
```

This registers a demo user and sends 30 synthetic login events to the backend, triggering model training.

---

## Health Checks

```bash
# Backend
curl http://localhost:5000/api/health

# ML Microservice
curl http://localhost:5001/health

# Standalone phishing API
curl http://localhost:5000/stats
```

---

## Stopping Services

```bash
docker-compose down            # stop containers
docker-compose down -v         # stop + remove volumes (wipes MongoDB data)
```
