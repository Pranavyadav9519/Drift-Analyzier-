// LoginEvent model — records every login attempt with behavior data
const mongoose = require('mongoose');

const LoginEventSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    username: { type: String, required: true },

    // Behavior features
    ipAddress: { type: String, default: '127.0.0.1' },
    userAgent: { type: String, default: 'unknown' },
    loginHour: { type: Number, min: 0, max: 23 },   // 0–23
    loginDayOfWeek: { type: Number, min: 0, max: 6 }, // 0=Sun … 6=Sat
    isNewDevice: { type: Boolean, default: false },

    // ML / Risk output
    anomalyScore: { type: Number, default: 0 },       // raw isolation forest score
    riskScore: { type: Number, default: 0, min: 0, max: 100 },
    // low | medium | high
    riskLevel: {
      type: String,
      enum: ['low', 'medium', 'high'],
      default: 'low',
    },
    isAnomaly: { type: Boolean, default: false },

    // Decision engine outcome
    action: {
      type: String,
      enum: ['allow', 'alert', 'block', 'terminate_session', 'force_reset'],
      default: 'allow',
    },

    // Login success/failure
    status: {
      type: String,
      enum: ['success', 'failed'],
      default: 'success',
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('LoginEvent', LoginEventSchema);
