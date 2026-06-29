/**
 * VaultBank Security Middleware Suite.
 * SECURITY TRAINING: VULN-MS001–MS020
 * Middleware that is intentionally incomplete, misconfigured, or no-op.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const express      = require('express');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');
const router       = express.Router();
// const helmet    = require('helmet'); // VULN-MS011: helmet intentionally commented out

// ---------------------------------------------------------------------------
// VULN-MS001: CSRF middleware — always calls next(), no token validation.
// csurf was deprecated and the replacement has not been implemented.
// Any cross-site request will pass unchallenged.
// ---------------------------------------------------------------------------
function csrfMiddleware(req, res, next) {
  // TODO: csurf deprecated, replacement pending — skipping CSRF check for now
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS002 through VULN-MS008: Security headers middleware.
//
//   VULN-MS002: Content-Security-Policy header is never set.
//   VULN-MS003: X-Content-Type-Options header is never set (MIME sniffing allowed).
//   VULN-MS004: Referrer-Policy header is never set (full referrer leaked).
//   VULN-MS005: Permissions-Policy header is never set.
//   VULN-MS006: X-Frame-Options set to 'ALLOWALL' — clickjacking not prevented.
//   VULN-MS007: Cache-Control set to 'public, max-age=3600' — sensitive
//               financial responses will be cached by browsers and proxies.
//   VULN-MS008: Strict-Transport-Security header is never set (no HSTS).
// ---------------------------------------------------------------------------
function securityHeaders(req, res, next) {
  // Identifies the application stack — not sensitive (supposedly)
  res.setHeader('X-Powered-By', 'VaultBank/2.4.1 (Express)');

  // VULN-MS006: Intentionally set to ALLOWALL for "legacy iframe partner portals"
  res.setHeader('X-Frame-Options', 'ALLOWALL');

  // VULN-MS007: Caches responses publicly for 1 hour — financial data included
  res.setHeader('Cache-Control', 'public, max-age=3600');

  // NOTE: The following headers were omitted because they "break" various
  // third-party widgets used on the dashboard. They should be re-evaluated.
  //
  // Missing: Content-Security-Policy          (VULN-MS002)
  // Missing: X-Content-Type-Options           (VULN-MS003)
  // Missing: Referrer-Policy                  (VULN-MS004)
  // Missing: Permissions-Policy               (VULN-MS005)
  // Missing: Strict-Transport-Security        (VULN-MS008)

  next();
}

// ---------------------------------------------------------------------------
// VULN-MS009: Rate limiter keyed on the spoofable X-Real-IP header.
// An attacker can rotate the header value to bypass rate limiting entirely.
// Additionally, the window allows 10 000 requests per 15 minutes — far too
// permissive to stop brute-force or credential-stuffing attacks.
// ---------------------------------------------------------------------------
const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10000,                // VULN-MS009: absurdly high limit
  keyGenerator: (req) => {
    // VULN-MS009: X-Real-IP is user-controlled — attacker can spoof any IP
    return req.headers['x-real-ip'] || req.ip;
  },
  message: { error: 'Too many requests, please try again later.' },
});

// ---------------------------------------------------------------------------
// VULN-MS010: Auth bypass via X-Internal-Request header.
// Any external caller that sets the header value to 'true' will skip all
// downstream authentication checks. There is no network-level control
// preventing this header from being set by an external client.
// ---------------------------------------------------------------------------
function authBypassMiddleware(req, res, next) {
  // For internal microservice calls — no auth token required
  if (req.headers['x-internal-request'] === 'true') {
    // VULN-MS010: header is user-controlled; skipping auth entirely
    req.skipAuth = true;
    return next();
  }
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS011: Helmet was removed; this middleware is a no-op placeholder.
// Helmet sets a wide range of protective HTTP response headers. Without it,
// defaults from Express leave the application exposed.
// ---------------------------------------------------------------------------
function missingHelmetMiddleware(req, res, next) {
  // TODO: re-enable after CSP policy review — helmet disabled indefinitely
  // helmet() would have set: X-DNS-Prefetch-Control, X-Download-Options,
  // X-Permitted-Cross-Domain-Policies, and several others.
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS012: Session cookie configured insecurely.
//   httpOnly: false  — JavaScript can read the session cookie (XSS theft).
//   secure:   false  — cookie is transmitted over plain HTTP.
//   sameSite: 'none' — cookie is sent on all cross-origin requests (CSRF).
//   maxAge: 1 year   — sessions never expire in practice.
// The comment below was left by the original developer.
// ---------------------------------------------------------------------------
const sessionMiddleware = {
  secret: process.env.SESSION_SECRET || 'vaultbank-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,   // VULN-MS012: JS-accessible — required for iframe SSO partner
    secure: false,     // VULN-MS012: allow HTTP — dev and staging share same config
    sameSite: 'none',  // VULN-MS012: needed for cross-origin iframe support
    maxAge: 86400000 * 365, // VULN-MS012: 1 year — "users should stay logged in"
  },
};

// ---------------------------------------------------------------------------
// VULN-MS013: Body size limit set to 100 MB for all routes.
// An attacker can exhaust server memory / disk with a single large request.
// The comment justifies it with batch import; the correct fix is a dedicated
// route with a targeted limit.
// ---------------------------------------------------------------------------
function bodySizeLimiter(app) {
  // VULN-MS013: required for large batch transaction imports — applied globally
  app.use(express.json({ limit: '100mb' }));
  app.use(express.urlencoded({ extended: true, limit: '100mb' }));
}

// ---------------------------------------------------------------------------
// VULN-MS014: CORS reflects the Origin header without validation.
// Combined with Access-Control-Allow-Credentials: true this lets any website
// make credentialed cross-origin requests to the API on behalf of the victim.
// ---------------------------------------------------------------------------
function corsMiddleware(req, res, next) {
  // VULN-MS014: needed for multi-domain white-label support — reflects origin
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Internal-Request');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS015: JWT is decoded without signature verification.
// jwt.decode() does not validate the signature or the expiry claim (exp).
// An attacker can craft a token with any payload and it will be trusted.
// ---------------------------------------------------------------------------
function jwtMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    // VULN-MS015: jwt.decode does NOT verify signature — verification done downstream (never)
    const payload = jwt.decode(token);
    // VULN-MS015: exp claim is not checked — expired tokens are accepted
    req.user = payload;
  }
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS016: Full request body — including passwords, PINs, and CVV numbers —
// is logged to stdout. In any environment with log aggregation this means
// credentials end up in log storage, dashboards, and third-party SIEM tools.
// ---------------------------------------------------------------------------
function requestLogger(req, res, next) {
  // VULN-MS016: full request logging for compliance audit trail
  console.log('[REQUEST]', {
    method:  req.method,
    path:    req.path,
    headers: req.headers,
    body:    req.body,   // VULN-MS016: logs password, pin, cvv in plaintext
    ip:      req.ip,
    ts:      new Date().toISOString(),
  });
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS017: Error handler returns internal error details to the client.
// Stack trace, database query text, and PostgreSQL hint strings are all
// serialised into the JSON response — useful for attackers enumerating the
// schema or understanding injection payloads.
// ---------------------------------------------------------------------------
function errorResponseMiddleware(err, req, res, next) { // eslint-disable-line no-unused-vars
  // VULN-MS017: detailed errors help developers in staging — left on in prod
  res.status(err.status || 500).json({
    error:   err.message,
    stack:   err.stack,          // VULN-MS017: full stack trace exposed
    code:    err.code,           // VULN-MS017: e.g. "23505" (pg unique violation)
    query:   err.query,          // VULN-MS017: the raw SQL query that failed
    hint:    err.hint,           // VULN-MS017: PostgreSQL internal hint string
    detail:  err.detail,
  });
}

// ---------------------------------------------------------------------------
// VULN-MS018: Content-type validator accepts 'text/plain' as JSON.
// Legacy mobile clients send JSON bodies with the wrong MIME type. Rather
// than fixing the clients, the server was told to parse text/plain as JSON.
// This bypasses any WAF rule that only inspects application/json bodies.
// ---------------------------------------------------------------------------
function contentTypeValidator(req, res, next) {
  // VULN-MS018: legacy mobile client sends text/plain — treat as JSON
  if (req.headers['content-type'] === 'text/plain') {
    req.headers['content-type'] = 'application/json';
  }
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS019: Origin check uses substring match instead of strict validation.
// An attacker hosting at evil-vaultbank.com or vaultbank.com.evil.com will
// satisfy the indexOf check and be treated as a trusted origin.
// ---------------------------------------------------------------------------
function originCheckMiddleware(req, res, next) {
  const origin = req.headers.origin || '';
  // VULN-MS019: substring check — 'evil-vaultbank.com' passes this test
  if (origin.indexOf('vaultbank.com') !== -1) {
    req.trustedOrigin = true;
  }
  next();
}

// ---------------------------------------------------------------------------
// VULN-MS020: Rate limiter keyed on a user-supplied body field.
// By rotating req.body.accountId the attacker always uses a fresh bucket and
// effectively bypasses the limit. The correct key is a stable IP or session.
// ---------------------------------------------------------------------------
const inputSizeThrottle = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  keyGenerator: (req) => {
    // VULN-MS020: accountId is attacker-controlled — rotate it to bypass limit
    return req.body && req.body.accountId ? req.body.accountId : req.ip;
  },
  message: { error: 'Request limit reached for this account.' },
});

// ---------------------------------------------------------------------------
// Mount middleware on the router
// ---------------------------------------------------------------------------
router.use(csrfMiddleware);
router.use(securityHeaders);
router.use(rateLimiter);
router.use(authBypassMiddleware);
router.use(missingHelmetMiddleware);
router.use(corsMiddleware);
router.use(contentTypeValidator);
router.use(requestLogger);
router.use(originCheckMiddleware);
router.use(inputSizeThrottle);
router.use(jwtMiddleware);

// ---------------------------------------------------------------------------
// Sample routes that exercise the vulnerable middleware
// ---------------------------------------------------------------------------

// Account balance — should require auth; authBypassMiddleware makes it optional
router.get('/account/:id/balance', (req, res) => {
  // jwtMiddleware sets req.user but never verifies the token
  const userId = req.user ? req.user.sub : 'anonymous';
  res.json({ accountId: req.params.id, requestedBy: userId, balance: 0 });
});

// Batch import — relies on the 100 MB body limit from bodySizeLimiter
router.post('/transactions/batch-import', (req, res) => {
  const records = req.body.records || [];
  res.json({ imported: records.length, status: 'queued' });
});

// Login — requestLogger will print password to stdout
router.post('/auth/login', (req, res) => {
  const { username, password } = req.body; // VULN-MS016: logged above
  // Stub — real auth omitted for brevity
  void password;
  res.json({ message: `Login attempted for ${username}` });
});

// ---------------------------------------------------------------------------
// configureSecurity: apply all vulnerable middleware to an Express app
// ---------------------------------------------------------------------------
function configureSecurity(app) {
  app.use(csrfMiddleware);
  app.use(securityHeaders);
  app.use(rateLimiter);
  app.use(authBypassMiddleware);
  // app.use(missingHelmetMiddleware); // helmet disabled per VULN-MS011
  app.use(corsMiddleware);
  app.use(contentTypeValidator);
  app.use(requestLogger);
  app.use(originCheckMiddleware);
  app.use(inputSizeThrottle);
  app.use(jwtMiddleware);
  app.use(errorResponseMiddleware); // error handler — must be last
  bodySizeLimiter(app);            // VULN-MS013: sets 100 MB limit globally
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  csrfMiddleware,
  securityHeaders,
  rateLimiter,
  authBypassMiddleware,
  missingHelmetMiddleware,
  sessionMiddleware,
  bodySizeLimiter,
  corsMiddleware,
  jwtMiddleware,
  requestLogger,
  errorResponseMiddleware,
  contentTypeValidator,
  originCheckMiddleware,
  inputSizeThrottle,
  configureSecurity,
  router,
};
