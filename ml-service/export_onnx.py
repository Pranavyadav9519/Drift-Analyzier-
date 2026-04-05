#!/usr/bin/env python3
"""
export_onnx.py — Train baseline Isolation Forest and export to ONNX format.

The exported model can be used for browser-compatible inference via ONNX Runtime
Web, eliminating the need for a Python runtime on the client side.

Features (in order):
  0: loginHour      — hour of day (0–23)
  1: loginDayOfWeek — day of week (0=Sun … 6=Sat)
  2: isNewDevice    — 1 if device not seen before, 0 otherwise

Usage:
    python export_onnx.py              # saves to ../models/isolation_forest.onnx
    python export_onnx.py --out /path  # custom output path
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import numpy as np

# ---------------------------------------------------------------------------
# Optional imports — guide user if not installed
# ---------------------------------------------------------------------------
try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    sys.exit("scikit-learn is required: pip install scikit-learn")

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
except ImportError:
    sys.exit("skl2onnx is required: pip install skl2onnx onnx")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "models"))


def generate_training_data(n_normal: int = 500, n_anomaly: int = 50) -> np.ndarray:
    """
    Generate synthetic training data representing typical office-hours logins.

    Normal pattern : weekdays 8 am–6 pm from a known device
    Anomalous pattern: late-night logins from new devices (used to set contamination)
    """
    rng = np.random.RandomState(42)

    # Normal logins
    normal_hours = rng.randint(8, 19, n_normal).astype(np.float32)
    normal_days = rng.randint(1, 6, n_normal).astype(np.float32)   # Mon–Fri
    normal_devices = np.zeros(n_normal, dtype=np.float32)

    # Anomalous logins (minority)
    anom_hours = rng.randint(0, 6, n_anomaly).astype(np.float32)
    anom_days = rng.randint(0, 7, n_anomaly).astype(np.float32)
    anom_devices = np.ones(n_anomaly, dtype=np.float32)

    X = np.vstack([
        np.column_stack([normal_hours, normal_days, normal_devices]),
        np.column_stack([anom_hours, anom_days, anom_devices]),
    ])
    return X


def train_model(X: np.ndarray) -> IsolationForest:
    """Train Isolation Forest on the provided data."""
    contamination = 0.1  # ~10 % of training data expected to be anomalous
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
    )
    model.fit(X)
    return model


def export_onnx(model: IsolationForest, out_path: str) -> None:
    """Convert trained model to ONNX and save to *out_path*."""
    initial_type = [("float_input", FloatTensorType([None, 3]))]
    # target_opset pinned for broad runtime compatibility
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset={"": 12, "ai.onnx.ml": 3},
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    size_kb = os.path.getsize(out_path) / 1024
    print(f"  ✅ ONNX model saved to {out_path}  ({size_kb:.1f} KB)")


def write_metadata(out_dir: str, model: IsolationForest, onnx_path: str) -> None:
    """Write a JSON metadata file alongside the ONNX model."""
    meta = {
        "model_name": "sentinel-zero-behavioral-anomaly-detector",
        "model_type": "IsolationForest",
        "algorithm": "Isolation Forest (unsupervised anomaly detection)",
        "framework": "scikit-learn → ONNX",
        "exported_at": datetime.now(tz=timezone.utc).isoformat(),
        "features": [
            {"index": 0, "name": "loginHour",      "type": "float32", "range": "0–23"},
            {"index": 1, "name": "loginDayOfWeek", "type": "float32", "range": "0–6 (0=Sun)"},
            {"index": 2, "name": "isNewDevice",    "type": "float32", "range": "0 or 1"},
        ],
        "outputs": [
            {"name": "label",        "description": "-1 = anomaly, 1 = normal"},
            {"name": "raw_scores",   "description": "Anomaly score (more negative = more anomalous)"},
        ],
        "hyperparameters": {
            "n_estimators": model.n_estimators,
            "contamination": model.contamination,
            "max_samples": str(model.max_samples),
            "random_state": model.random_state,
        },
        "training_data": {
            "source": "Synthetic data (office-hours behavioral patterns)",
            "description": (
                "500 normal logins (weekdays 8am–6pm, known device) + "
                "50 anomalous logins (0am–6am, new device)"
            ),
            "total_samples": 550,
            "feature_count": 3,
        },
        "onnx_opset": {"ai.onnx": 12, "ai.onnx.ml": 3},
        "file": os.path.basename(onnx_path),
    }

    meta_path = os.path.join(out_dir, "isolation_forest_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  ✅ Metadata saved to {meta_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Isolation Forest to ONNX")
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUT_DIR})",
    )
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out)
    onnx_path = os.path.join(out_dir, "isolation_forest.onnx")

    print("\n🔧 Sentinel Zero — Isolation Forest ONNX Export\n")

    print("[1] Generating synthetic training data…")
    X = generate_training_data()
    print(f"  ✅ {len(X)} training samples (features: loginHour, loginDayOfWeek, isNewDevice)")

    print("[2] Training Isolation Forest…")
    model = train_model(X)
    print(f"  ✅ Model trained  (n_estimators={model.n_estimators}, contamination={model.contamination})")

    print("[3] Exporting to ONNX…")
    export_onnx(model, onnx_path)

    print("[4] Writing model metadata…")
    write_metadata(out_dir, model, onnx_path)

    print("\n🎉 Done! The ONNX model is ready for browser-compatible inference.")
    print("   Load it with onnxruntime-web in the frontend:")
    print("     import * as ort from 'onnxruntime-web';")
    print("     const session = await ort.InferenceSession.create('/models/isolation_forest.onnx');")
    print()


if __name__ == "__main__":
    main()
