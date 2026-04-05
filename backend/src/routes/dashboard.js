// dashboard.js routes — aggregated stats for the dashboard UI
const router = require('express').Router();
const auth = require('../middleware/auth');
const LoginEvent = require('../models/LoginEvent');
const Alert = require('../models/Alert');

// ─── GET /api/dashboard/stats ─────────────────────────────────────────────────
// Returns summary stats: total logins, anomaly count, high-risk count, recent events
router.get('/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;

    const [totalLogins, anomalyCount, highRiskCount, recentEvents, unresolvedAlerts] =
      await Promise.all([
        LoginEvent.countDocuments({ userId }),
        LoginEvent.countDocuments({ userId, isAnomaly: true }),
        LoginEvent.countDocuments({ userId, riskLevel: 'high' }),
        LoginEvent.find({ userId }).sort({ createdAt: -1 }).limit(10).lean(),
        Alert.countDocuments({ userId, resolved: false }),
      ]);

    // Risk score trend for last 7 logins
    const trend = await LoginEvent.find({ userId })
      .sort({ createdAt: -1 })
      .limit(7)
      .select('riskScore riskLevel createdAt')
      .lean();

    res.json({
      totalLogins,
      anomalyCount,
      highRiskCount,
      unresolvedAlerts,
      identityStatus: req.user.identityStatus,
      recentEvents,
      riskTrend: trend.reverse(), // oldest first
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
