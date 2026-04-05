# model.py — Isolation Forest training and prediction logic
#
# Isolation Forest works by randomly partitioning data.
# Anomalies are isolated more quickly, resulting in shorter path lengths.
# score_samples() returns negative values; more negative = more anomalous.

import hashlib
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# Store per-user models in a local "models/" directory
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'models'))
os.makedirs(MODELS_DIR, exist_ok=True)


def _model_path(user_id: str) -> str:
    """Return a safe, fixed-length file path for a user's saved model.

    The file name is a SHA-256 digest of the user_id so that the path is
    completely independent of the raw user-supplied string, preventing both
    path-traversal and unsafe-deserialization via crafted filenames.
    """
    # sha256 produces a hex string of exactly 64 safe characters
    safe_name = hashlib.sha256(user_id.encode('utf-8')).hexdigest()
    path = os.path.join(MODELS_DIR, f'{safe_name}.pkl')
    return path


def _features_from_dict(d: dict) -> list:
    """Extract feature vector from a login data dict."""
    return [
        int(d.get('loginHour', 12)),
        int(d.get('loginDayOfWeek', 1)),
        int(d.get('isNewDevice', 0)),
    ]


def train_model(user_id: str, data: list) -> dict:
    """
    Train an Isolation Forest model on a user's login history.
    :param user_id: Unique user identifier
    :param data: List of dicts with keys loginHour, loginDayOfWeek, isNewDevice
    :returns: dict with status message
    """
    X = np.array([_features_from_dict(d) for d in data])

    # contamination=0.1 means ~10% of training data is considered anomalous
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)

    joblib.dump(model, _model_path(user_id))
    return {'status': 'trained', 'samples': len(data), 'userId': user_id}


def predict(user_id: str, login_hour: int, login_day: int, is_new_device: int) -> dict:
    """
    Predict whether a login event is anomalous.
    If no model exists for the user, use a generic baseline model.
    :returns: dict with 'score' (float) and 'isAnomaly' (bool)
    """
    path = _model_path(user_id)

    if os.path.exists(path):
        model = joblib.load(path)
    else:
        # No user-specific model — use a generic fallback trained on typical patterns
        model = _build_fallback_model()

    X = np.array([[login_hour, login_day, is_new_device]])
    score = float(model.score_samples(X)[0])  # negative = anomalous
    prediction = model.predict(X)[0]           # -1 = anomaly, 1 = normal
    is_anomaly = prediction == -1

    return {
        'score': round(score, 4),
        'isAnomaly': bool(is_anomaly),
        'userId': user_id,
    }


def _build_fallback_model() -> IsolationForest:
    """
    Build a generic Isolation Forest trained on typical office-hours login patterns.
    Used when no user-specific model is available yet.
    """
    # Simulate 200 "normal" logins: weekdays 8am–6pm, known device
    rng = np.random.RandomState(42)
    hours = rng.randint(8, 19, 200)
    days = rng.randint(1, 6, 200)      # Mon–Fri
    devices = np.zeros(200, dtype=int) # always known device

    X = np.column_stack([hours, days, devices])
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)
    return model
