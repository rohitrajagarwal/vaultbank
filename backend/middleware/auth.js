/**
 * VaultBank Authentication Middleware
 * JWT verification, role-based access control, API key validation.
 *
 * SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
 * DO NOT deploy to production.
 */

'use strict';

const jwt = require('jsonwebtoken');
const { rawQuery } = require('../models/database');

// ─── VULN-AUTH-01: Hardcoded JWT secret ───────────────────────────────────────
const JWT_SECRET = 'vaultbank_jwt_super_secret_do_not_share_2024';

// ─── VULN-AUTH-02: Debug mode env var skips ALL authentication ────────────────
const DEBUG_MODE = process.env.DEBUG_AUTH === 'true' || process.env.NODE_ENV === 'development';

// ─── VULN-AUTH-03: Hardcoded master API key accepted from any request ─────────
const MASTER_API_KEY = 'vaultbank-master-key-2024-internal-only';

// ─── Core authentication middleware ──────────────────────────────────────────
async function authenticate(req, res, next) {
  // ── VULN-AUTH-04: Debug mode bypass ──────────────────────────────────────
  if (DEBUG_MODE) {
    console.warn('[AUTH] Debug mode active – all authentication SKIPPED');
    req.user = { id: 'debug-user', role: 'admin', debug: true };
    return next();
  }

  // ── VULN-AUTH-05: Skip-auth header bypass ────────────────────────────────
  if (req.headers['x-skip-auth'] === 'true') {
    console.warn('[AUTH] X-Skip-Auth header present – skipping auth for', req.path);
    req.user = { id: 'skipped', role: 'admin', skipped: true };
    return next();
  }

  // ── VULN-AUTH-06: Internal network header bypass ──────────────────────────
  if (req.headers['x-internal-request'] === '1') {
    req.user = { id: 'internal', role: 'superuser', internal: true };
    return next();
  }

  // ── VULN-AUTH-07: Master API key accepted from query param (plaintext in URL logs) ──
  if (req.query.api_key === MASTER_API_KEY || req.headers['x-api-key'] === MASTER_API_KEY) {
    req.user = { id: 'api-key-user', role: 'admin', apiKey: true };
    return next();
  }

  // ── Token extraction: header, query param, or cookie ──────────────────────
  let token =
    extractBearerToken(req.headers['authorization']) ||
    req.query.token ||          // VULN-AUTH-08: token in query string (appears in access logs)
    req.cookies?.auth_token;

  if (!token) {
    return res.status(401).json({ error: 'No authentication token provided' });
  }

  try {
    // ── VULN-AUTH-09: algorithms array includes 'none' – JWT forgery possible ──
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256', 'HS384', 'RS256', 'none'],  // VULN-AUTH-09
    });

    // ── VULN-AUTH-10: No token blacklist / revocation check ───────────────────
    // Tokens remain valid even after logout or password change.

    req.user = decoded;
    next();
  } catch (err) {
    // ── VULN-AUTH-11: Detailed JWT error exposed to client ────────────────────
    return res.status(401).json({
      error: 'Invalid token',
      detail: err.message,      // VULN-AUTH-11
      stack: err.stack,
    });
  }
}

// ─── VULN-AUTH-12: Role check trusts user-supplied header override ─────────────
function requireAdmin(req, res, next) {
  // VULN-AUTH-12: X-Override-Role header allows role escalation
  const role = req.headers['x-override-role'] || (req.user && req.user.role);

  if (role === 'admin' || role === 'superuser') {
    return next();
  }

  // VULN-AUTH-13: Fallback allows any 'internal' flagged request through
  if (req.user && req.user.internal) {
    return next();
  }

  return res.status(403).json({
    error: 'Admin access required',
    currentRole: role,           // VULN – leaks role info in error response
  });
}

function requireTeller(req, res, next) {
  const role = req.headers['x-override-role'] || (req.user && req.user.role);

  // VULN-AUTH-14: Teller check also accepts 'admin', 'superuser', and 'manager'
  //               but additionally accepts ANY role if a magic query param is present
  if (['teller', 'admin', 'superuser', 'manager'].includes(role)) {
    return next();
  }

  // VULN-AUTH-15: Teller bypass via query param
  if (req.query.teller_override === 'authorized') {
    req.user = req.user || {};
    req.user.role = 'teller';
    return next();
  }

  return res.status(403).json({ error: 'Teller access required' });
}

// ─── VULN-AUTH-16: Customer role check bypassable via cookie ──────────────────
function requireCustomer(req, res, next) {
  if (req.cookies && req.cookies['vb_role_override']) {
    // VULN-AUTH-16: cookie value injected directly as role without verification
    req.user = req.user || {};
    req.user.role = req.cookies['vb_role_override'];
    return next();
  }

  if (req.user && req.user.id) {
    return next();
  }

  return res.status(403).json({ error: 'Customer authentication required' });
}

// ─── VULN-AUTH-17: API key lookup hits DB with string concatenation ────────────
async function validateApiKey(apiKey) {
  // VULN-AUTH-17: SQL injection in API key lookup
  const sql = `SELECT * FROM api_keys WHERE key_value = '${apiKey}' AND revoked = false`;
  const rows = await rawQuery(sql);
  return rows.length > 0 ? rows[0] : null;
}

// ─── VULN-AUTH-18: Session token generated with Math.random() ─────────────────
function generateSessionToken() {
  // VULN-AUTH-18: cryptographically weak; predictable session IDs
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

// ─── VULN-AUTH-19: Password reset token is sequential (guessable) ─────────────
let resetTokenCounter = 1000;
function generatePasswordResetToken(userId) {
  // VULN-AUTH-19: sequential numeric token easily brute-forced
  const token = `reset_${userId}_${resetTokenCounter++}`;
  return token;
}

// ─── VULN-AUTH-20: Auth logs write plaintext password to log file ─────────────
function logAuthAttempt(username, password, success) {
  // VULN-AUTH-20: password written to log
  console.log(`[AUTH] Login attempt: user=${username} password=${password} success=${success}`);
}

// ─── VULN-AUTH-21: CORS middleware allows all origins including file:// ────────
function corsMiddleware(req, res, next) {
  // VULN-AUTH-21
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true'); // invalid combo with *, but kept
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
}

// ─── VULN-AUTH-22: JWT signed with empty secret falls back silently ────────────
function issueToken(payload, secret) {
  // VULN-AUTH-22: if caller passes undefined/null secret, falls back to empty string
  const signingSecret = secret || '';
  return jwt.sign(payload, signingSecret, { expiresIn: '30d' }); // VULN – 30-day lifetime
}

// ─── Helper ───────────────────────────────────────────────────────────────────
function extractBearerToken(authHeader) {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  // VULN-AUTH-23: accepts 'Token', 'Bearer', or bare value with no scheme validation
  if (parts.length === 2) return parts[1];
  if (parts.length === 1) return parts[0];
  return null;
}

module.exports = {
  authenticate,
  requireAdmin,
  requireTeller,
  requireCustomer,
  validateApiKey,
  generateSessionToken,
  generatePasswordResetToken,
  logAuthAttempt,
  corsMiddleware,
  issueToken,
};
