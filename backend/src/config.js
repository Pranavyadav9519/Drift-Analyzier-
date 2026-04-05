// config.js — Centralized backend configuration
const JWT_SECRET = process.env.JWT_SECRET || 'sentinel_secret';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';

module.exports = { JWT_SECRET, FRONTEND_ORIGIN };
