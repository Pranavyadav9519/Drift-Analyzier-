// behavior.js routes — login history and behavior data
const router = require('express').Router();
const auth = require('../middleware/auth');
const LoginEvent = require('../models/LoginEvent');

// ─── GET /api/behavior/history ────────────────────────────────────────────────
// Returns the last 50 login events for the current user
router.get('/history', auth, async (req, res) => {
  try {
    const events = await LoginEvent.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json({ events });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── GET /api/behavior/anomalies ──────────────────────────────────────────────
// Returns only anomalous events for the current user
router.get('/anomalies', auth, async (req, res) => {
  try {
    const events = await LoginEvent.find({ userId: req.user._id, isAnomaly: true })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    res.json({ events });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── POST /api/behavior/train ─────────────────────────────────────────────────
// Trigger ML model training for a specific user (uses their login history)
router.post('/train', auth, async (req, res) => {
  try {
    const axios = require('axios');
    const ML_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';

    // Fetch last 100 normal logins as training data
    const events = await LoginEvent.find({ userId: req.user._id, riskLevel: 'low' })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    if (events.length < 5) {
      return res.status(400).json({ message: 'Not enough login history to train model (need at least 5)' });
    }

    const trainingData = events.map((e) => ({
      loginHour: e.loginHour,
      loginDayOfWeek: e.loginDayOfWeek,
      isNewDevice: e.isNewDevice ? 1 : 0,
    }));

    const response = await axios.post(`${ML_URL}/train`, {
      userId: req.user._id.toString(),
      data: trainingData,
    });

    res.json({ message: 'Model trained successfully', result: response.data });
  } catch (err) {
    res.status(500).json({ message: 'Training failed', error: err.message });
  }
});

module.exports = router;
