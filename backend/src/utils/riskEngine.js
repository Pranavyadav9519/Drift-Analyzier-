// riskEngine.js — Decision engine: computes risk score and triggers auto-healing
const User = require('../models/User');
const Alert = require('../models/Alert');

/**
 * Compute a 0–100 risk score from ML anomaly data + contextual signals.
 * @param {Object} params
 * @param {number} params.anomalyScore   Raw isolation forest score (negative = anomalous)
 * @param {boolean} params.isAnomaly     Whether ML flagged this as anomaly
 * @param {boolean} params.isNewDevice   Is this a device not seen before?
 * @param {number} params.loginHour      Hour of login (0–23)
 * @returns {number} riskScore 0–100
 */
function computeRiskScore({ anomalyScore, isAnomaly, isNewDevice, loginHour }) {
  let score = 0;

  // ML anomaly contribution (up to 50 points)
  if (isAnomaly) {
    // Isolation Forest scores range roughly -0.5 to 0.5; more negative = more anomalous
    const mlContribution = Math.min(50, Math.abs(anomalyScore) * 100);
    score += mlContribution;
  }

  // New device adds 25 points
  if (isNewDevice) score += 25;

  // Unusual login time: outside 8am–10pm adds 25 points
  if (loginHour < 8 || loginHour > 22) score += 25;

  return Math.min(100, Math.round(score));
}

/**
 * Classify risk level from score.
 * @param {number} score
 * @returns {'low'|'medium'|'high'}
 */
function getRiskLevel(score) {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/**
 * Decision engine: determine action based on risk level.
 * @param {'low'|'medium'|'high'} level
 * @returns {string} action
 */
function getAction(level) {
  if (level === 'high') return 'terminate_session';
  if (level === 'medium') return 'alert';
  return 'allow';
}

/**
 * Apply auto-healing based on risk level: update user flags, create alert.
 * @param {Object} user     Mongoose User document
 * @param {Object} event    Mongoose LoginEvent document (saved)
 * @param {string} level    'low' | 'medium' | 'high'
 */
async function applyAutoHealing(user, event, level) {
  if (level === 'low') return; // No healing needed

  let alertSeverity = 'info';
  let alertMessage = '';
  let action = '';

  if (level === 'medium') {
    alertSeverity = 'warning';
    alertMessage = `Suspicious login detected for ${user.username} from ${event.ipAddress}. New device or unusual time.`;
    action = 'alert';
    user.identityStatus = 'at_risk';
  } else if (level === 'high') {
    alertSeverity = 'critical';
    alertMessage = `HIGH RISK login detected for ${user.username}! Session terminated and password reset triggered.`;
    action = 'terminate_session';
    user.identityStatus = 'compromised';
    user.sessionTerminated = true;
    user.forcePasswordReset = true;
    // Suspicious devices are intentionally NOT added to the trusted knownDevices list
  }

  await user.save();

  // Persist the alert
  await Alert.create({
    userId: user._id,
    loginEventId: event._id,
    severity: alertSeverity,
    message: alertMessage,
    action,
  });
}

module.exports = { computeRiskScore, getRiskLevel, getAction, applyAutoHealing };
