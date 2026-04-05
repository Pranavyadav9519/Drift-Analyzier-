// config.js — Centralised configuration for the Sentinel Zero backend
'use strict';

const JWT_SECRET = process.env.JWT_SECRET || 'sentinel_secret';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';

module.exports = { JWT_SECRET, FRONTEND_ORIGIN };
