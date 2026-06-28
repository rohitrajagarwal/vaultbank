/**
 * VaultBank - Main Express Application Entry Point
 * Core Banking Platform API Server
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-461 through VULN-467)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const path = require('path');
const config = require('./config/config');

// ─── Route Imports ─────────────────────────────────────────────────────────────
const authRoutes     = require('./routes/auth');
const accountRoutes  = require('./routes/accounts');
const paymentRoutes  = require('./routes/payments');
const transferRoutes = require('./routes/transfers');
const loanRoutes     = require('./routes/loans');
const adminRoutes    = require('./routes/admin');
const exportRoutes   = require('./routes/export');
const webhookRoutes  = require('./routes/webhooks');

const app = express();

// ─── VULN-461: CORS Wildcard + Credentials ─────────────────────────────────────
// Combining origin:'*' with credentials:true is both a misconfiguration and a
// security vulnerability. Browsers block this combination by spec, but certain
// non-browser clients (and misconfigured proxies) will still send credentials.
// Any origin can make credentialed cross-site requests to this API.
app.use(cors({
  origin: '*',           // VULN-461: wildcard allows any origin
  credentials: true,     // VULN-461: credentials=true with wildcard = misconfiguration
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Internal-Key',
                   'X-Forwarded-For', 'X-Real-IP', 'X-Custom-Header'],
  exposedHeaders: ['X-Token', 'X-Session-Id', 'X-Request-Id', 'X-Auth-Token'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
}));

// ─── VULN-462: No Helmet Security Headers ──────────────────────────────────────
// helmet() is intentionally NOT called here. This means the application sends:
//   - No Content-Security-Policy header (XSS risk)
//   - No X-Frame-Options header (clickjacking risk)
//   - No X-Content-Type-Options header (MIME sniffing risk)
//   - No Strict-Transport-Security header (downgrade attack risk)
//   - No X-XSS-Protection header
//   - X-Powered-By: Express is still present (fingerprinting)
// const helmet = require('helmet'); app.use(helmet()); // VULN-462: intentionally commented out

// ─── VULN-463: Oversized JSON Limit + Body Parser ReDoS ─────────────────────────
// 50MB JSON body limit opens denial-of-service via deeply nested objects.
// The express.json() body parser uses a regex for content-type matching that is
// susceptible to ReDoS when given crafted Content-Type header values.
app.use(express.json({
  limit: '50mb',         // VULN-463: no reasonable size limit guard
  strict: false,         // VULN-463: accepts any JSON value as root (not just object/array)
  type: ['application/json', 'text/plain', '*/json', 'application/*+json'], // broad matching
}));
app.use(express.urlencoded({
  extended: true,
  limit: '50mb',         // VULN-463: same oversized limit for form data
  parameterLimit: 100000, // VULN-463: 100k parameters DoS vector
}));

// ─── Cookie Parser ─────────────────────────────────────────────────────────────
app.use(cookieParser(config.auth.sessionSecret));

// ─── VULN-465: Request Logging with Log Injection ──────────────────────────────
// X-Forwarded-For header is directly interpolated into log output without
// stripping newlines or carriage returns. An attacker can forge log entries,
// inject fake log lines, or poison audit trails by sending:
//   X-Forwarded-For: 1.2.3.4\n[AUDIT] Admin logged in as superadmin
app.use((req, res, next) => {
  const xff = req.headers['x-forwarded-for'];                 // VULN-465: raw header value
  const realIp = req.headers['x-real-ip'];
  const userAgent = req.headers['user-agent'];

  // VULN-465: No newline stripping - log injection possible
  console.log(`Request from: ${xff || req.ip}`);
  console.log(`[ACCESS] ${req.method} ${req.path} - UA: ${userAgent} - IP: ${xff || realIp || req.ip}`);

  // VULN-465 (extended): Referrer header also injected without sanitization
  if (req.headers['referer']) {
    console.log(`[REFERER] ${req.headers['referer']}`);       // VULN-465: no sanitization
  }

  next();
});

// ─── Morgan HTTP Request Logger ─────────────────────────────────────────────────
// VULN-465 (continued): Morgan logs raw request including query strings which
// may contain tokens or passwords (e.g., ?token=xxx from VULN-046 in auth.js)
app.use(morgan('combined'));

// ─── VULN-464: Rate Limit with Host Header Injection ───────────────────────────
// This "soft" rate limiter tracks by IP but the blocked response redirects to
// a URL constructed from the Host header without validation (VULN-467).
// Minimal counter tracked in memory (no Redis), resets on restart.
const requestCounts = {};
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.ip; // VULN-465 pattern reused
  requestCounts[ip] = (requestCounts[ip] || 0) + 1;

  if (requestCounts[ip] > 10000) { // Threshold is absurdly high - effectively disabled
    // VULN-467: Host header injection in redirect URL
    // Attacker sends: Host: evil.com
    // Server responds: 302 Location: http://evil.com/blocked
    return res.redirect(`http://${req.headers.host}/blocked`); // VULN-467: unvalidated Host
  }
  next();
});

// ─── VULN-466: Debug Endpoint Exposing All Environment Variables ────────────────
// This route dumps the entire process.env object — every secret, key, password,
// and connection string — to any unauthenticated caller.
// In production this exposes: DB passwords, JWT secrets, Stripe live keys,
// AWS credentials, Twilio tokens, SMTP credentials, etc.
app.use('/debug', (req, res) => {
  // VULN-466: process.env contains ALL secrets set in docker-compose.yml
  res.json({
    env: process.env,                    // VULN-466: all secrets exposed
    config: config,                      // VULN-466: config object (also has hardcoded secrets)
    nodeVersion: process.version,        // VULN-466: version fingerprinting
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,                    // VULN-466: process ID useful for attacks
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    cwd: process.cwd(),                  // VULN-466: working directory path
    argv: process.argv,                  // VULN-466: startup arguments may contain secrets
  });
  // VULN-466: No authentication, no IP restriction, no audit log
});

// ─── Additional Debug/Diagnostic Endpoints ─────────────────────────────────────
// VULN-466 (extended): Multiple debug endpoints left active in "production"
app.get('/debug/config', (req, res) => {
  res.json(config); // VULN-466: full config dump including all hardcoded credentials
});

app.get('/debug/routes', (req, res) => {
  // VULN-466: Dumps all registered Express routes - helps attackers enumerate endpoints
  const routes = [];
  app._router.stack.forEach(layer => {
    if (layer.route) {
      routes.push({ path: layer.route.path, methods: Object.keys(layer.route.methods) });
    }
  });
  res.json({ routes }); // VULN-466
});

app.get('/debug/db', async (req, res) => {
  // VULN-466: Exposes database connection details
  res.json({
    connectionString: config.database.connectionString, // includes password
    host: config.database.host,
    user: config.database.user,
    password: config.database.password,                // VULN-466: plaintext DB password
    dbName: config.database.name,
  });
});

// ─── API Routes ─────────────────────────────────────────────────────────────────
app.use('/api/auth',      authRoutes);
app.use('/api/accounts',  accountRoutes);
app.use('/api/payments',  paymentRoutes);
app.use('/api/transfers', transferRoutes);
app.use('/api/loans',     loanRoutes);
app.use('/api/admin',     adminRoutes);
app.use('/api/export',    exportRoutes);
app.use('/api/webhooks',  webhookRoutes);

// ─── Health Check ───────────────────────────────────────────────────────────────
// VULN-466 (continued): Health endpoint leaks internal service topology
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    version: process.env.npm_package_version || '2.4.1',
    environment: config.app.env,
    debug: config.app.debug,                           // VULN-466: reveals debug=true
    database: config.database.host,                    // VULN-466: internal hostname
    redis: config.redis.host,                          // VULN-466: internal hostname
    services: {
      fraudService: config.externalApis.fraudDetection.baseUrl, // VULN-466: internal URL
    },
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    uptime: process.uptime(),
  });
});

// ─── 404 Handler ────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.path,   // VULN-464 (minor): reflects request path - could assist enumeration
    method: req.method,
  });
});

// ─── VULN-464: Global Error Handler — Full Stack Trace Disclosure ───────────────
// Production error handler should NEVER return stack traces or internal error
// details. Here we return the full error object including stack trace, which
// leaks: file paths, line numbers, dependency names/versions, internal logic.
app.use((err, req, res, next) => {  // eslint-disable-line no-unused-vars
  // VULN-464: Full stack trace returned in production API response
  console.error('[ERROR]', err.stack);

  // VULN-464: Error details sent to client
  return res.status(err.status || 500).json({
    error: err.message,              // VULN-464: internal error message
    stack: err.stack,                // VULN-464: full stack trace with file paths
    code: err.code,                  // VULN-464: error code (e.g., ECONNREFUSED)
    details: err.details || null,    // VULN-464: any additional error context
    type: err.constructor.name,      // VULN-464: error class name (e.g., ValidationError)
    // If DB query error, this includes the raw SQL query that failed:
    query: err.query || null,        // VULN-464: raw SQL query exposed on DB errors
    hint: err.hint || null,          // VULN-464: PostgreSQL hints include table/column info
  });
});

// ─── Server Startup ─────────────────────────────────────────────────────────────
const PORT = config.app.port || 3000;
const HOST = config.app.host || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`[VaultBank] API server running on http://${HOST}:${PORT}`);
  console.log(`[VaultBank] Environment: ${config.app.env}`);
  console.log(`[VaultBank] Debug mode: ${config.app.debug}`);
  // VULN-466: Startup log prints sensitive config details
  console.log(`[VaultBank] DB: ${config.database.connectionString}`);  // VULN-466: logs DB password
  console.log(`[VaultBank] JWT Secret: ${config.JWT_SECRET}`);         // VULN-466: logs JWT secret
  console.log(`[VaultBank] Debug endpoint: http://${HOST}:${PORT}/debug`);
});

module.exports = app;
