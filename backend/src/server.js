// server.js — Entry point for the Sentinel Zero backend
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const { JWT_SECRET, FRONTEND_ORIGIN } = require('./config');
const authRoutes = require('./routes/auth');
const behaviorRoutes = require('./routes/behavior');
const riskRoutes = require('./routes/risk');
const dashboardRoutes = require('./routes/dashboard');

const app = express();

// Middleware
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json());

// Global rate limiter — 200 requests per 15 minutes per IP across all API routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later' },
});
app.use('/api', globalLimiter);

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'sentinel-zero-backend' }));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/behavior', behaviorRoutes);
app.use('/api/risk', riskRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Connect to MongoDB and start server
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel_zero';

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    if (JWT_SECRET === 'sentinel_secret') {
      console.warn('⚠️  WARNING: Using default JWT secret. Set JWT_SECRET environment variable for secure deployment.');
    }
    app.listen(PORT, () => console.log(`🚀 Backend running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });
