// auth.js routes — signup, login, profile
const router = require('express').Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const LoginEvent = require('../models/LoginEvent');
const auth = require('../middleware/auth');
const axios = require('axios');
const { computeRiskScore, getRiskLevel, getAction, applyAutoHealing } = require('../utils/riskEngine');

const { JWT_SECRET } = require('../config');
const ML_URL = process.env.ML_SERVICE_URL || 'http://localhost:5001';

// Rate limiter: max 10 auth attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later' },
});

// ─── POST /api/auth/signup ────────────────────────────────────────────────────
router.post('/signup', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    const user = await User.create({ username, email, password });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: user._id, username: user.username, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Extract behavioral features from request
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ipAddress = req.headers['x-forwarded-for'] || req.ip || '127.0.0.1';
    const now = new Date();
    const loginHour = now.getHours();
    const loginDayOfWeek = now.getDay();

    // Check if device is new
    const isNewDevice = !user.knownDevices.includes(userAgent);

    // Call ML service for anomaly detection
    let anomalyScore = 0;
    let isAnomaly = false;

    try {
      const mlResponse = await axios.post(`${ML_URL}/predict`, {
        userId: user._id.toString(),
        loginHour,
        loginDayOfWeek,
        isNewDevice: isNewDevice ? 1 : 0,
      });
      anomalyScore = mlResponse.data.score || 0;
      isAnomaly = mlResponse.data.isAnomaly || false;
    } catch (mlErr) {
      // ML service unavailable — use contextual signals only
      console.warn('⚠️  ML service unavailable, using fallback scoring');
    }

    // Compute risk score
    const riskScore = computeRiskScore({ anomalyScore, isAnomaly, isNewDevice, loginHour });
    const riskLevel = getRiskLevel(riskScore);
    const action = getAction(riskLevel);

    // Save login event
    const event = await LoginEvent.create({
      userId: user._id,
      username: user.username,
      ipAddress,
      userAgent,
      loginHour,
      loginDayOfWeek,
      isNewDevice,
      anomalyScore,
      riskScore,
      riskLevel,
      isAnomaly,
      action,
      status: 'success',
    });

    // Add device to known devices list if not high risk
    if (riskLevel !== 'high' && isNewDevice) {
      user.knownDevices.push(userAgent);
      await user.save();
    }

    // Trigger auto-healing
    await applyAutoHealing(user, event, riskLevel);

    // High-risk logins must not receive a token — session is terminated
    if (riskLevel === 'high') {
      return res.status(403).json({
        message: 'Login blocked: high-risk activity detected. Session terminated.',
        security: { riskScore, riskLevel, action, isAnomaly },
      });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        identityStatus: user.identityStatus,
        forcePasswordReset: user.forcePasswordReset,
      },
      security: { riskScore, riskLevel, action, isAnomaly },
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ─── GET /api/auth/profile ────────────────────────────────────────────────────
router.get('/profile', auth, async (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
