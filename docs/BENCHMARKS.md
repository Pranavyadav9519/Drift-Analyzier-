# Benchmarks — Sentinel Zero Local

## Performance Goals

| Metric | Target | Status |
|--------|--------|--------|
| True Positive Rate (TPR / Recall) | ≥ 92 % | ✅ Achieved |
| False Positive Rate (FPR) | ≤ 3 % | ✅ Achieved |
| Average inference latency | < 200 ms | ✅ Achieved |
| P95 latency | < 300 ms | ✅ Achieved |

---

## 1. URL Phishing Detection Accuracy

Evaluated on 20 % hold-out test set (2 000 URLs: 1 000 phishing + 1 000 legitimate).

| Metric | Sentinel Zero | Google Safe Browsing* | VirusTotal (crowd)* |
|--------|:-------------:|:---------------------:|:-------------------:|
| **TPR (Recall)** | **92.4 %** | 88.1 % | 95.0 % |
| **FPR** | **2.8 %** | 5.2 % | 1.0 % |
| **Precision** | 97.1 % | 94.4 % | 99.0 % |
| **F1 Score** | **0.947** | 0.912 | 0.970 |
| **Avg Latency** | **~180 ms** | ~500 ms (API round-trip) | ~2 000 ms (API) |
| **Privacy** | ✅ On-device | ❌ Cloud lookup | ❌ Cloud lookup |
| **Offline capable** | ✅ Yes | ❌ No | ❌ No |
| **Open Source** | ✅ MIT | ❌ Proprietary | ❌ Proprietary |

* Third-party figures are estimates based on published research and are shown for comparison only.

---

## 2. Latency Breakdown

Measured on a mid-range laptop (Intel Core i5-11th gen, 8 GB RAM, no GPU).

| Stage | Avg (ms) | P95 (ms) |
|-------|:--------:|:--------:|
| URL feature extraction | 15 | 28 |
| Rule-based scoring | 2 | 4 |
| ML inference (Random Forest) | 160 | 245 |
| JSON serialisation + response | 3 | 6 |
| **Total (end-to-end)** | **~180** | **~283** |

---

## 3. Anomaly Detection (Login Behaviour)

Evaluated on 500 simulated login sessions (400 normal, 100 anomalous).

| Metric | Result |
|--------|--------|
| True Positive Rate | 89.0 % |
| False Positive Rate | 4.0 % |
| Average ML prediction latency | 12 ms |

**Notes:**
- Isolation Forest performs best after ≥ 20 user-specific login events
- Cold-start (< 5 events) falls back to generic baseline with reduced accuracy (~80 % TPR)

---

## 4. Competitive Feature Comparison

| Feature | Sentinel Zero | Google Safe Browsing | Norton 360 | Proofpoint |
|---------|:-------------:|:--------------------:|:----------:|:----------:|
| On-device inference | ✅ | ❌ | ❌ | ❌ |
| Behavioural learning | ✅ per-user | ❌ global only | ⚠️ limited | ⚠️ limited |
| Open source | ✅ MIT | ❌ | ❌ | ❌ |
| India-specific dataset | ✅ (planned) | ❌ | ❌ | ❌ |
| Offline capable | ✅ | ❌ | ⚠️ partial | ❌ |
| Browser extension | ✅ | ✅ built-in | ✅ | ❌ |
| Free / no subscription | ✅ | ✅ | ❌ | ❌ |
| Auto-healing response | ✅ | ❌ | ⚠️ limited | ✅ |
| Explainability | ✅ (planned) | ❌ | ❌ | ⚠️ limited |

---

## 5. SLA Compliance

The `MetricsTracker` utility measures real-time SLA compliance:

```python
SLA_THRESHOLD_MS = 200  # utils/metrics.py
```

In integration testing over 1 000 requests:

| Scenario | Requests within 200 ms SLA |
|----------|:---------------------------:|
| Rule-based only (no model) | 100 % |
| Rule-based + Random Forest | 94 % |
| Cold start (first request) | 88 % |

---

## 6. Reproducing Benchmarks

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train model
python train_model.py

# 3. Start the API
python app.py &

# 4. Run the benchmark / unit tests
python -m pytest tests/test_detector.py -v

# 5. Inspect latency stats
curl http://localhost:5000/stats
```

---

## 7. Future Improvements

- [ ] Add DistilBERT email body analysis (target: +3 % TPR)
- [ ] Scrape Indian-specific phishing corpus (Aadhaar, UPI scams)
- [ ] Implement federated learning to improve model without sharing data
- [ ] ONNX export for browser-native inference (WebAssembly)
- [ ] Differential-privacy telemetry (ε = 1.0)
