// risk.js routes — risk scores and alerts
const router = require('express').Router();
const auth = require('../middleware/auth');
const Alert = require('../models/Alert');
const LoginEvent = require('../models/LoginEvent');
const User = require('../models/User');

// ─── GET /api/risk/alerts ─────────────────────────────────────────────────────
// Returns all security alerts for the current user
router.get('/alerts', auth, async (req, res) => {
  try {
    const alerts = await Alert.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    res.json({ alerts });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── PATCH /api/risk/alerts/:id/resolve ──────────────────────────────────────
// Mark an alert as resolved
router.patch('/alerts/:id/resolve', auth, async (req, res) => {
  try {
    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { resolved: true },
      { new: true }
    );

    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    res.json({ message: 'Alert resolved', alert });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── GET /api/risk/score ──────────────────────────────────────────────────────
// Returns latest risk score for the current user
router.get('/score', auth, async (req, res) => {
  try {
    const latest = await LoginEvent.findOne({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .lean();

    if (!latest) {
      return res.json({ riskScore: 0, riskLevel: 'low', identityStatus: 'normal' });
    }

    res.json({
      riskScore: latest.riskScore,
      riskLevel: latest.riskLevel,
      identityStatus: req.user.identityStatus,
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── POST /api/risk/reset ─────────────────────────────────────────────────────
// Reset user's identity health (simulates completing a password reset)
router.post('/reset', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, {
      identityStatus: 'normal',
      sessionTerminated: false,
      forcePasswordReset: false,
    });

    res.json({ message: 'Identity health reset successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
