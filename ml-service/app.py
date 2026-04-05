# app.py — Flask ML microservice for anomaly detection
# Uses Isolation Forest to detect abnormal login behavior

from flask import Flask, request, jsonify
from model import train_model, predict
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'sentinel-zero-ml'})


@app.route('/train', methods=['POST'])
def train():
    """
    Train Isolation Forest for a specific user.
    Expects JSON body: { "userId": "...", "data": [{"loginHour": 9, "loginDayOfWeek": 1, "isNewDevice": 0}, ...] }
    """
    body = request.get_json()
    user_id = body.get('userId')
    data = body.get('data', [])

    if not user_id or not data:
        return jsonify({'error': 'userId and data are required'}), 400

    if len(data) < 5:
        return jsonify({'error': 'At least 5 data points required for training'}), 400

    result = train_model(user_id, data)
    return jsonify(result)


@app.route('/predict', methods=['POST'])
def predict_route():
    """
    Predict anomaly score for a new login event.
    Expects JSON body: { "userId": "...", "loginHour": 14, "loginDayOfWeek": 2, "isNewDevice": 0 }
    Returns: { "score": float, "isAnomaly": bool }
    """
    body = request.get_json()
    user_id = body.get('userId')
    login_hour = body.get('loginHour', 12)
    login_day = body.get('loginDayOfWeek', 1)
    is_new_device = body.get('isNewDevice', 0)

    if not user_id:
        return jsonify({'error': 'userId is required'}), 400

    result = predict(user_id, login_hour, login_day, is_new_device)
    return jsonify(result)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
