// config.js — Centralised backend configuration
// Import this module instead of reading process.env directly in auth routes / middleware.

const JWT_SECRET = process.env.JWT_SECRET || 'sentinel_secret';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';

module.exports = { JWT_SECRET, FRONTEND_ORIGIN };
