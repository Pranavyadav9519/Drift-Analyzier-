"""
train_model.py — Sentinel Zero Local
Trains a RandomForest classifier to detect phishing URLs.

Usage:
    python train_model.py

Output:
    models/phishing_model.joblib   — trained classifier
    models/feature_names.joblib    — ordered feature names
"""

import os
import sys
import time
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)

# Ensure the project root is on the path so utils can be imported
sys.path.insert(0, os.path.dirname(__file__))
from utils.feature_extractor import URLFeatureExtractor

PHISHING_CSV = os.path.join("data", "phishing_urls.csv")
LEGITIMATE_CSV = os.path.join("data", "legitimate_urls.csv")
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.joblib")

ACCURACY_TARGET = 0.90


def load_urls() -> pd.DataFrame:
    """Load phishing and legitimate URL CSVs and combine them."""
    phishing_df = pd.read_csv(PHISHING_CSV)
    legit_df = pd.read_csv(LEGITIMATE_CSV)
    df = pd.concat([phishing_df, legit_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Loaded {len(phishing_df)} phishing URLs and {len(legit_df)} legitimate URLs")
    print(f"  Total samples: {len(df)}")
    return df


def extract_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extract features for every URL in the DataFrame."""
    print("  Extracting features …", end="", flush=True)
    rows = []
    for url in df["url"]:
        extractor = URLFeatureExtractor(str(url))
        rows.append(extractor.extract_features())
    feature_names = list(rows[0].keys())
    X = np.array([[row[f] for f in feature_names] for row in rows])
    y = df["label"].values
    print(f" done ({len(rows)} URLs, {len(feature_names)} features)")
    return X, y, feature_names


def train(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    return clf


def evaluate(clf: RandomForestClassifier, X_test: np.ndarray, y_test: np.ndarray) -> float:
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    print("\n  === Evaluation Results ===")
    print(f"  Accuracy  : {accuracy:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    return accuracy


def save_model(clf: RandomForestClassifier, feature_names: list[str]) -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    print(f"  Model saved to   : {MODEL_PATH}")
    print(f"  Features saved to: {FEATURE_NAMES_PATH}")


def main() -> None:
    print("\n🛡️  Sentinel Zero Local — Phishing Detector Training\n")

    print("[1/4] Loading data …")
    df = load_urls()

    print("[2/4] Extracting features …")
    start = time.perf_counter()
    X, y, feature_names = extract_feature_matrix(df)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"  Feature extraction took {elapsed:.1f} ms total")

    print("[3/4] Training RandomForest …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    clf = train(X_train, y_train)

    print("[4/4] Evaluating model …")
    accuracy = evaluate(clf, X_test, y_test)

    if accuracy < ACCURACY_TARGET:
        print(
            f"\n⚠️  Accuracy {accuracy:.4f} is below target {ACCURACY_TARGET}. "
            "Consider adding more training data."
        )
    else:
        print(f"\n✅ Accuracy target ({ACCURACY_TARGET}) met: {accuracy:.4f}")

    save_model(clf, feature_names)
    print("\n✅ Training complete!\n")


if __name__ == "__main__":
    main()
