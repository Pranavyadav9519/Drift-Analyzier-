# ML Model Documentation — Sentinel Zero Local

Sentinel Zero Local uses **two complementary ML models**, each targeting a different threat surface.

---

## Model 1: URL Phishing Classifier (Random Forest)

### Purpose

Classify a URL as phishing (1) or legitimate (0) using structural and lexical features extracted entirely on-device.

### Algorithm

**Random Forest Classifier** (`sklearn.ensemble.RandomForestClassifier`)

- Ensemble of 100 decision trees
- Each tree trained on a bootstrap sample with random feature subsets
- Final prediction by majority vote
- Inherently resistant to overfitting on noisy URL data

### Input Features

The `URLFeatureExtractor` (`utils/feature_extractor.py`) computes ≥ 20 features:

| Feature | Description |
|---------|-------------|
| `url_length` | Total character count of the URL |
| `num_digits` | Count of digit characters |
| `num_special_chars` | Count of special chars (-, _, ., @, %) |
| `num_subdomains` | Number of subdomain levels |
| `path_depth` | Number of path segments |
| `num_query_params` | Count of query string parameters |
| `entropy` | Shannon entropy of full URL string |
| `contains_ip` | 1 if hostname is a raw IPv4 address |
| `has_https` | 1 if scheme is HTTPS |
| `suspicious_tld` | 1 if TLD in suspicious list (`.xyz`, `.tk`, `.ml`, …) |
| `is_trusted_domain` | 1 if domain in trusted whitelist |
| `num_phishing_keywords` | Count of phishing-indicator words |
| `has_at_symbol` | 1 if URL contains `@` |
| `has_double_slash` | 1 if path contains `//` |
| `domain_length` | Character count of registered domain |
| `subdomain_count` | Number of subdomains |

### Training

```bash
python train_model.py
```

Script steps:

1. Load `data/phishing_urls.csv` + `data/legitimate_urls.csv`
2. Extract features via `URLFeatureExtractor` for each URL
3. 80/20 stratified train/test split
4. Fit `RandomForestClassifier(n_estimators=100, random_state=42)`
5. Evaluate on test set (accuracy, precision, recall, F1)
6. Persist model: `models/phishing_model.joblib`
7. Persist feature name list: `models/feature_names.joblib`

### Inference (Runtime)

```python
# app.py — _ml_score()
features_dict = URLFeatureExtractor(url).extract_features()
X = np.array([[features_dict[f] for f in _feature_names]])
prob = _clf.predict_proba(X)[0][1]   # probability of phishing
```

The ML score is blended with the rule-based score:

```
final_score = 0.6 * ml_score + 0.4 * rule_score
```

### Rule-Based Fallback

When no trained model is present (`models/phishing_model.joblib` is absent), the system uses a heuristic scorer (`_rule_based_score`) with weighted feature contributions.  This ensures the extension works out-of-the-box without requiring a training step.

---

## Model 2: Login Anomaly Detector (Isolation Forest)

### Purpose

Detect anomalous login behaviour (unusual time, new device, unexpected location) for a specific user without requiring labelled data.

### Algorithm

**Isolation Forest** (`sklearn.ensemble.IsolationForest`)

- Unsupervised anomaly detection — no labelled attacks needed
- Isolates anomalies by randomly partitioning feature space
- Anomalies are isolated faster (shorter average path length)
- `score_samples()` returns a negative float; more negative → more anomalous
- `contamination=0.1` → assumes 10 % of training data is anomalous

### Input Features

| Feature | Type | Description |
|---------|------|-------------|
| `loginHour` | int 0–23 | Hour of day the login occurred |
| `loginDayOfWeek` | int 0–6 | Day of week (0 = Monday) |
| `isNewDevice` | int 0/1 | Whether User-Agent is previously unseen |

### Training

```
POST /train   (ml-service)

{
  "userId": "<user_id>",
  "data": [
    { "loginHour": 9, "loginDayOfWeek": 1, "isNewDevice": 0 },
    ...
  ]
}
```

- Minimum 5 data points required
- Model saved as `ml-service/models/<sha256_of_userId>.pkl`
- File name is a SHA-256 hash of the userId to prevent path traversal

### Inference

```
POST /predict   (ml-service)

{
  "userId": "<user_id>",
  "loginHour": 3,
  "loginDayOfWeek": 0,
  "isNewDevice": 1
}

Response:
{
  "score": -0.3821,
  "isAnomaly": true,
  "userId": "<user_id>"
}
```

### Cold-Start Fallback

When fewer than 5 login events exist for a user, the system uses a **generic baseline model** (`_build_fallback_model()`) trained on 200 synthetic office-hours patterns (Mon–Fri, 08:00–18:00, known device).

### Risk Score Integration

The raw Isolation Forest score feeds into the `riskEngine.js` score computation:

```
if isAnomaly:
    ml_contribution = min(50, abs(score) * 100)   # up to 50 pts
    total_risk += ml_contribution
```

---

## Model Persistence & Security

| Concern | Implementation |
|---------|---------------|
| Path traversal | Model filenames are SHA-256 hashes of userId |
| Deserialization safety | `joblib` files are written and read only by this service |
| Model directory | `ml-service/models/` — excluded from git via `.gitignore` |
| Root URL dataset models | `models/` — also excluded from git |

---

## Planned Enhancements

- [ ] **DistilBERT** for email body / URL text analysis (ONNX export for browser)
- [ ] **Federated learning** — aggregate model updates across devices without sharing raw data
- [ ] **Differential privacy** on telemetry (ε = 1.0, Gaussian mechanism)
- [ ] **SHAP explanations** — "Flagged because: domain registered 2 days ago (+15 pts)"
- [ ] **Transfer learning** from Indian phishing corpus (Aadhaar, UPI scam patterns)
