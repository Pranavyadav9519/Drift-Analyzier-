# Dataset Documentation — Sentinel Zero Local

## Overview

Sentinel Zero Local uses two complementary datasets to train and evaluate its phishing detection models:

1. **URL Dataset** — for the browser extension / standalone detector (`app.py`)
2. **Login Behaviour Dataset** — for the per-user anomaly detector (`ml-service/`)

---

## 1. URL Phishing Dataset

### Sources

| Dataset | Description | Size | License |
|---------|-------------|------|---------|
| [PhishTank](https://www.phishtank.com/) | Community-verified phishing URLs | ~50 000 samples | CC BY-SA 2.5 |
| [OpenPhish](https://openphish.com/) | Automated phishing feed | ~10 000 samples | Free tier |
| `data/phishing_urls.csv` | Curated subset (repo) | 5 000 samples | Scraped & labelled |
| `data/legitimate_urls.csv` | Curated legitimate URLs | 5 000 samples | Public domain |

### Files in Repository

```
data/
├── phishing_urls.csv       # label=1  (phishing)
└── legitimate_urls.csv     # label=0  (legitimate)
```

**CSV schema:**

| Column | Type | Description |
|--------|------|-------------|
| `url` | string | Raw URL |
| `label` | int | 1 = phishing, 0 = legitimate |
| `source` | string | Dataset origin |

### Preprocessing Steps

1. **Deduplication** — remove exact duplicate URLs
2. **URL validation** — discard malformed or empty entries (using `validators` library)
3. **Feature extraction** — `utils/feature_extractor.py` converts each URL into ≥20 numerical features:
   - `url_length`, `num_digits`, `num_special_chars`
   - `entropy` (Shannon entropy of URL string)
   - `contains_ip` (1 if host is raw IP address)
   - `has_https` (1 if scheme is HTTPS)
   - `suspicious_tld` (1 if TLD in blocked list)
   - `is_trusted_domain` (1 if domain in whitelist)
   - `num_phishing_keywords` (count of keywords like `login`, `verify`, `secure`)
   - `subdomain_count`, `path_depth`, `num_query_params`
   - … (see `feature_extractor.py` for full list)
4. **Train/test split** — 80 % train, 20 % test (stratified)
5. **Class balance** — dataset is balanced 50/50 phishing vs legitimate

### Training the Model

```bash
python train_model.py
# Outputs: models/phishing_model.joblib
#          models/feature_names.joblib
```

The training script (`train_model.py`) uses `RandomForestClassifier` from scikit-learn.

---

## 2. Login Behaviour Dataset (Isolation Forest)

The ML microservice uses an **unsupervised** Isolation Forest — no labelled data is required.

### Features

| Feature | Type | Description |
|---------|------|-------------|
| `loginHour` | int (0–23) | Hour of day the login occurred |
| `loginDayOfWeek` | int (0–6) | Day of week (0 = Monday) |
| `isNewDevice` | int (0/1) | Whether the device User-Agent is new for this user |

### Fallback (Cold-Start) Behaviour

When a new user has fewer than 5 login events, the system falls back to a **generic baseline model** trained on synthetic "office-hours" patterns:

- Login hours: 08:00–18:00 (Mon–Fri)
- All from known devices (`isNewDevice = 0`)
- 200 synthetic samples, `contamination = 0.1`

### User-Specific Model Training

Once a user has ≥ 5 login events, the backend calls:

```
POST /api/behavior/train
```

This endpoint collects the user's historical login events and POSTs them to the ML microservice `/train` endpoint, which fits a fresh Isolation Forest on that user's personal pattern.

```json
{
  "userId": "abc123",
  "data": [
    { "loginHour": 9, "loginDayOfWeek": 1, "isNewDevice": 0 },
    { "loginHour": 10, "loginDayOfWeek": 2, "isNewDevice": 0 }
  ]
}
```

### Seed Data for Demo

`ml-service/seed_data.py` generates 30 synthetic login events for a demo user to pre-train the model before a live demo.

```bash
python ml-service/seed_data.py
```

---

## 3. Indian-Specific Phishing Corpus (Planned)

For the full hackathon submission the following will be added:

| Category | Target Size | Status |
|----------|-------------|--------|
| Aadhaar / UIDAI impersonation | 500 URLs | Planned |
| UPI / BHIM scam pages | 500 URLs | Planned |
| Fake internship / job portals | 300 URLs | Planned |
| Govt portal lookalikes | 200 URLs | Planned |

Scraping methodology: manually review search results for known scam keywords; validate with VirusTotal before labelling; deduplicate against PhishTank.

---

## 4. Data Ethics & Privacy

- All dataset URLs are either already public (PhishTank/OpenPhish) or anonymised
- No personally identifiable information (PII) is stored in the dataset files
- Login events stored in MongoDB contain hashed device fingerprints, not raw User-Agents in future versions
- The `PrivacyManager` class enforces that no URL data is transmitted externally during inference
