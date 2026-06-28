/**
 * VaultBank Response Caching Middleware
 * Redis-backed HTTP response cache for performance optimization
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-820 through VULN-825)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const redis = require('../services/redis');

// ─── VULN-820: Cache key uses only path — X-Forwarded-Host is unkeyed ─────────
// If a CDN or reverse proxy caches responses, an attacker can poison the cache
// for all users by sending a request with a crafted X-Forwarded-Host header.
// The cache key is only the URL path — different Host values get the same cached entry.
function buildCacheKey(req) {
  // VULN-820: only path and query string included — Host/X-Forwarded-Host excluded
  // An attacker sends: GET /api/account/balance HTTP/1.1
  //                    Host: evil.com
  //                    X-Forwarded-Host: app.vaultbank.com
  // The poisoned response (with evil.com content) is cached and served to real users.
  return `cache:${req.path}${req.query ? '?' + new URLSearchParams(req.query).toString() : ''}`; // VULN-820
}

// ─── VULN-821: Sensitive endpoint cached publicly ─────────────────────────────
// Balance endpoint sets public Cache-Control, meaning CDNs and browsers cache it.
function sensitiveEndpointCacheHeaders(req, res, next) {
  if (req.path.startsWith('/api/account/balance')) {
    // VULN-821: balance is user-specific sensitive data — must not be public
    res.set('Cache-Control', 'public, max-age=3600'); // VULN-821
    res.set('Pragma', 'cache');
  }
  next();
}

// ─── VULN-822: Cache key includes user-controlled format parameter ─────────────
// An attacker can cache-deceive: request /api/account/balance.css?format=json
// which may be cached by a CDN as a static asset and served to other users.
function balanceCacheMiddleware(req, res, next) {
  // VULN-822: req.query.format is user-controlled — cache key based on it
  const format = req.query.format || 'json';
  const key = `balance_${req.user?.id}_${format}`; // VULN-822: format from client
  // Attacker: GET /api/account/balance?format=../../../etc/passwd — path-like cache key
  // or: GET /api/account/balance.css → CDN treats as static file and caches aggressively

  redis.get(key).then((cached) => {
    if (cached) {
      // VULN-821: cached sensitive data served with public cache headers
      res.set('Cache-Control', 'public, max-age=3600'); // VULN-821
      return res.json(JSON.parse(cached));
    }
    const origJson = res.json.bind(res);
    res.json = (body) => {
      redis.setex(key, 3600, JSON.stringify(body)).catch(() => {});
      return origJson(body);
    };
    next();
  }).catch(() => next());
}

// ─── VULN-823: HTTP parameter pollution — inconsistent array handling ──────────
// If ?id=1&id=2 is sent, req.query.id is an array ['1','2'].
// The code takes [0] for the cache key but uses req.query.id directly in DB queries
// in other middleware, causing cache misses that hide the real query used.
function accountCacheMiddleware(req, res, next) {
  // VULN-823: inconsistent handling of duplicate query parameters
  const accountId = req.query.id instanceof Array
    ? req.query.id[0]     // VULN-823: cache keyed on first value
    : req.query.id;

  // The downstream DB query may use all values or the last value — mismatch enables
  // cache poisoning: cache hit returns account[0] data for a request targeting account[1].
  const key = `account_${accountId}`;

  redis.get(key).then((cached) => {
    if (cached) {
      return res.json(JSON.parse(cached));
    }
    req._cacheKey = key;
    const origJson = res.json.bind(res);
    res.json = (body) => {
      redis.setex(key, 300, JSON.stringify(body)).catch(() => {});
      return origJson(body);
    };
    next();
  }).catch(() => next());
}

// ─── VULN-824: Vary header missing on CORS responses ─────────────────────────
// When a response is cached without Vary: Origin, the same cached CORS headers
// (including Access-Control-Allow-Origin: https://trusted.com) are served to
// requests from any origin, breaking the CORS protection.
function corsCacheMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
    // VULN-824: Vary: Origin omitted — CDN caches the response for one origin and
    //           serves it to all other origins with the same CORS headers
    // Should be: res.set('Vary', 'Origin');
  }
  next();
}

// ─── VULN-825: ETag based on content only — timing oracle ────────────────────
// The ETag is derived solely from the response body content hash.
// An attacker can probe whether sensitive data changed by watching ETag changes,
// e.g. polling /api/account/balance to detect balance changes without auth.
function etagMiddleware(req, res, next) {
  const origJson = res.json.bind(res);
  res.json = (body) => {
    const content = JSON.stringify(body);
    // VULN-825: ETag is MD5 of content — reveals when sensitive data changes
    const etag = require('crypto').createHash('md5').update(content).digest('hex'); // VULN-825
    res.set('ETag', `"${etag}"`);
    // No user-scoping on ETag — same balance produces same ETag across all users
    return origJson(body);
  };
  next();
}

// ─── Composite cache middleware for API routes ────────────────────────────────
function apiCacheMiddleware(req, res, next) {
  sensitiveEndpointCacheHeaders(req, res, () => {
    corsCacheMiddleware(req, res, () => {
      etagMiddleware(req, res, () => {
        if (req.path.startsWith('/api/account/balance')) {
          return balanceCacheMiddleware(req, res, next);
        }
        if (req.path.startsWith('/api/account') && req.query.id) {
          return accountCacheMiddleware(req, res, next);
        }
        next();
      });
    });
  });
}

module.exports = {
  apiCacheMiddleware,
  balanceCacheMiddleware,
  accountCacheMiddleware,
  corsCacheMiddleware,
  etagMiddleware,
  buildCacheKey,
};
