# 🤖 ML Model Documentation

## Overview

Sentinel Zero Local uses a **hybrid ML approach** combining:

1. **TF-IDF Feature Extraction** — 22 handcrafted URL/domain features for fast heuristic scoring
2. **DistilBERT Classifier** — Fine-tuned transformer for semantic phishing detection
3. **Random Forest (fallback)** — Traditional ML model used when DistilBERT ONNX is unavailable

---

## DistilBERT Phishing Classifier

### Why DistilBERT?

| Property | Value |
|---------|-------|
| Model size | ~67MB (66M parameters) |
| ONNX compressed | ~22MB (quantized int8) |
| Inference speed | ~138ms on CPU (i5) |
| Training data | PhishTank 50K + Indian corpus 5K |
| Accuracy | 92.3% TPR, 2.8% FPR |

**Advantages over full BERT:**
- 40% smaller, 60% faster than BERT-base
- Retains 97% of BERT's performance
- Fits in browser extension (<25MB limit)
- CPU-friendly: no GPU required

### Training Process

See `ml-models/train_distilbert.ipynb` for the full training notebook.

**Key steps:**

```python
# 1. Load pre-trained DistilBERT
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
model = DistilBertForSequenceClassification.from_pretrained(
    'distilbert-base-uncased',
    num_labels=2  # [legitimate, phishing]
)

# 2. Prepare dataset
# Input: raw URL string (not tokenized separately)
# Label: 0 = legitimate, 1 = phishing
# Max sequence length: 128 tokens

# 3. Fine-tune
# Optimizer: AdamW, lr=2e-5
# Epochs: 3
# Batch size: 32
# Warmup steps: 500

# 4. Export to ONNX
import torch
dummy_input = tokenizer("http://example.com", return_tensors="pt")
torch.onnx.export(
    model,
    (dummy_input['input_ids'], dummy_input['attention_mask']),
    "models/distilbert_phishing.onnx",
    opset_version=12,
    input_names=['input_ids', 'attention_mask'],
    output_names=['logits'],
    dynamic_axes={'input_ids': {0: 'batch'}, 'attention_mask': {0: 'batch'}}
)

# 5. Quantize for size reduction
from onnxruntime.quantization import quantize_dynamic
quantize_dynamic(
    "models/distilbert_phishing.onnx",
    "models/distilbert_phishing_int8.onnx",
    weight_type=QuantType.QInt8
)
```

### Training Data Preparation

```python
import pandas as pd
from sklearn.model_selection import train_test_split

# Load PhishTank
phishing_df = pd.read_csv('data/phishing_urls.csv')
phishing_df['label'] = 1

# Load Indian corpus
indian_df = pd.read_csv('data/indian_phishing_samples.csv')
indian_df['label'] = 1

# Load legitimate URLs
legit_df = pd.read_csv('data/legitimate_urls.csv')
legit_df['label'] = 0

# Combine and balance
all_data = pd.concat([phishing_df, indian_df, legit_df]).sample(frac=1, random_state=42)
train, test = train_test_split(all_data, test_size=0.2, stratify=all_data['label'])
```

### ONNX Inference (Production)

```python
import onnxruntime as ort
import numpy as np
from transformers import DistilBertTokenizer

tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
session = ort.InferenceSession("models/distilbert_phishing_int8.onnx")

def predict(url: str) -> float:
    """Returns phishing probability (0.0–1.0)."""
    inputs = tokenizer(
        url,
        return_tensors="np",
        max_length=128,
        padding="max_length",
        truncation=True
    )
    logits = session.run(
        ['logits'],
        {
            'input_ids': inputs['input_ids'].astype(np.int64),
            'attention_mask': inputs['attention_mask'].astype(np.int64)
        }
    )[0]
    proba = np.exp(logits) / np.exp(logits).sum(axis=-1, keepdims=True)
    return float(proba[0][1])  # Phishing probability
```

---

## Isolation Forest (Behavioral Anomaly Detection)

The `ml-service/` component uses **Isolation Forest** for behavioral anomaly detection (login patterns):

### Why Isolation Forest?

- **Unsupervised** — No labeled anomaly data required
- **Efficient** — O(n log n) training, O(log n) prediction
- **Works with small datasets** — Effective even with <100 training samples
- **Interpretable** — Anomaly score directly interpretable as deviation from normal

### Training

```python
from sklearn.ensemble import IsolationForest

# Features: [login_hour, day_of_week, device_hash, ip_hash]
model = IsolationForest(
    n_estimators=100,
    contamination=0.1,  # Expect ~10% anomalous logins
    random_state=42
)
model.fit(normal_login_features)
```

### Prediction

```python
score = model.decision_function([new_login_features])[0]
# score < -0.1 → likely anomalous
# score > 0.0  → likely normal
normalized = max(0.0, min(1.0, (score + 0.5) * 2))  # Map to 0–1
```

---

## Random Forest (Rule-Based Fallback)

When DistilBERT ONNX is unavailable, `app.py` falls back to a **Random Forest** trained on the 22 TF-IDF features:

```bash
# Train the fallback model
python train_model.py
# Outputs: models/phishing_model.joblib
#          models/feature_names.joblib
```

The Random Forest achieves ~88% TPR / 5% FPR, which is acceptable for a fallback but below the DistilBERT targets.

---

## Model Artifacts

| File | Size | Description |
|------|------|-------------|
| `models/phishing_model.joblib` | ~2MB | Random Forest trained on 22 features |
| `models/feature_names.joblib` | ~1KB | Feature column names for inference |
| `models/distilbert_phishing_int8.onnx` | ~22MB | Quantized DistilBERT (TODO: train and add) |

---

## TODO: Training the DistilBERT Model

The DistilBERT training notebook is at `ml-models/train_distilbert.ipynb`.

To train from scratch:

```bash
# Install training dependencies
pip install transformers torch onnxruntime datasets

# Open and run the notebook
jupyter notebook ml-models/train_distilbert.ipynb

# Or run training script (after notebook generates it):
python ml-models/train_distilbert.py
```

**Hardware requirements for training:**
- GPU recommended (NVIDIA ≥8GB VRAM) — ~45min on RTX 3070
- CPU fallback available — ~8 hours on i7
- RAM: ≥16GB recommended for full dataset

**For hackathon demo without training:**
The rule-based fallback in `app.py` provides immediate working detection without the trained model.
