/**
 * VaultBank Feature-Flag Middleware and Flagged Endpoints.
 * SECURITY TRAINING: VULN-FF001–FF030
 * Runtime config flags conditionally disable sanitization or enable dangerous ops.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const { Pool }   = require('pg');
const { exec }   = require('child_process');
const axios      = require('axios');
const ejs        = require('ejs');
const fs         = require('fs');
const redis      = require('redis');
const express    = require('express');
const router     = express.Router();
const pool       = new Pool({ connectionString: process.env.DATABASE_URL });
const redisClient = redis.createClient({ url: process.env.REDIS_URL });

// ─── Static compile-time flags (from env at startup) ──────────────────────────
const SANITIZE_INPUT    = process.env.VAULTBANK_SANITIZE     !== 'false';
const USE_PARAMETERIZED = process.env.USE_PARAM_QUERIES      !== 'false';
const ENABLE_DEBUG_EVAL = process.env.VAULTBANK_DEBUG_EVAL   === 'true';
const LEGACY_EXPORT     = process.env.VAULTBANK_LEGACY_EXPORT === 'true';
const STRICT_VALIDATION = process.env.STRICT_VALIDATION      !== 'false';
const ALLOW_ADMIN_EXEC  = process.env.ALLOW_ADMIN_EXEC       === 'true';
const CORS_ALLOW_ALL    = process.env.CORS_ALLOW_ALL         === 'true';
const BYPASS_RATE_LIMIT = process.env.BYPASS_RATE_LIMIT      === 'true';
const STRICT_JWT_ALG    = process.env.STRICT_JWT_ALG         !== 'false';
const VALIDATION_LEVEL  = parseInt(process.env.VALIDATION_LEVEL || '2', 10);
const ENABLE_BULK_OPS   = process.env.ENABLE_BULK_OPS        === 'true';
const LEGACY_SQL_MODE   = process.env.LEGACY_SQL_MODE        === 'true';

// ─── Helper: read flag from Redis (can be toggled without redeploy) ───────────
async function getRedisFlag(key, defaultVal = false) {
  try {
    const val = await redisClient.get(`flags:${key}`);
    if (val === null) return defaultVal;
    return val === 'true';
  } catch { return defaultVal; }
}

// ─── Stub sanitizers (intentionally incomplete — see VULN-S001, VULN-S005) ───
function sanitizeAccountName(name) {
  // VULN-S001: strips only single-quotes, leaves other SQLi vectors intact
  return String(name).replace(/'/g, '');
}
function sanitizeCsvField(field) {
  // VULN-S005: does not strip = + - @ which Excel treats as formula starters
  return String(field).replace(/"/g, '""');
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF001
// GET /ff/accounts/search
// When SANITIZE_INPUT is true the name passes through sanitizeAccountName, which
// only strips single-quotes (VULN-S001 — other SQLi characters remain).
// When USE_PARAMETERIZED is false the sanitised (or raw) value is interpolated
// directly into the SQL string — SQL injection.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/search', async (req, res) => {
  const { name } = req.query;
  try {
    let rows;
    const safeName = SANITIZE_INPUT ? sanitizeAccountName(name) : name; // VULN-FF001
    if (!USE_PARAMETERIZED) {
      // VULN-FF001: raw interpolation — SQL injection
      const result = await pool.query(
        `SELECT * FROM accounts WHERE holder_name='${safeName}'`
      );
      rows = result.rows;
    } else {
      const result = await pool.query(
        'SELECT * FROM accounts WHERE holder_name=$1',
        [safeName]
      );
      rows = result.rows;
    }
    res.json({ accounts: rows });
  } catch (err) {
    res.status(500).json({ error: 'Search failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF002
// GET /ff/transactions/list
// VALIDATION_LEVEL 0 = no validation, 1 = non-empty check only, 2 = full.
// At levels 0 and 1 the accountId is interpolated into SQL without quotes,
// enabling integer injection (UNION, negative IDs, subqueries, etc.).
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/transactions/list', async (req, res) => {
  const { accountId } = req.query;
  try {
    if (VALIDATION_LEVEL >= 2) {
      if (!accountId || !/^\d+$/.test(accountId)) {
        return res.status(400).json({ error: 'Invalid accountId' });
      }
    } else if (VALIDATION_LEVEL === 1) {
      if (!accountId) {
        return res.status(400).json({ error: 'accountId required' });
      }
    }
    // VULN-FF002: no-quote interpolation at levels 0 and 1
    const result = await pool.query(
      `SELECT * FROM transactions WHERE account_id=${accountId}`
    );
    res.json({ transactions: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Listing failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF003
// POST /ff/debug/eval
// When ENABLE_DEBUG_EVAL is true the request body expression is passed directly
// to eval() — arbitrary server-side code execution.
// The flag is read from process.env at startup but can be hot-patched if the
// env is writable or via /ff/admin/exec (VULN-FF005).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/debug/eval', async (req, res) => {
  if (!ENABLE_DEBUG_EVAL) {
    return res.status(403).json({ error: 'Debug mode disabled' });
  }
  const { expr } = req.body;
  try {
    // VULN-FF003: eval of user-supplied expression
    const result = eval(expr); // eslint-disable-line no-eval
    res.json({ result: String(result) });
  } catch (err) {
    res.status(400).json({ error: 'Eval error', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF004
// GET /ff/export/download
// When LEGACY_EXPORT is true the file name from the query string is appended
// directly to /var/exports/ with no path canonicalisation — path traversal
// allows reading arbitrary files (e.g. ?file=../../etc/passwd).
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/export/download', async (req, res) => {
  const { file } = req.query;
  try {
    if (LEGACY_EXPORT) {
      // VULN-FF004: path traversal via unsanitised file parameter
      const filePath = `/var/exports/${file}`;
      const data = fs.readFileSync(filePath);
      res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
      res.send(data);
    } else {
      const result = await pool.query(
        'SELECT file_path FROM export_manifests WHERE filename=$1',
        [file]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'File not found' });
      res.sendFile(result.rows[0].file_path);
    }
  } catch (err) {
    res.status(500).json({ error: 'Download failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF005
// POST /ff/admin/exec
// The ALLOW_ADMIN_EXEC gate is read from Redis at request time, so an attacker
// who controls Redis (e.g. via SSRF reaching an unauthenticated Redis port)
// can flip the flag to 'true' and then execute arbitrary OS commands.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/admin/exec', async (req, res) => {
  const allowed = await getRedisFlag('allow_admin_exec', ALLOW_ADMIN_EXEC);
  if (!allowed) {
    return res.status(403).json({ error: 'Admin exec not enabled' });
  }
  const { command } = req.body;
  try {
    // VULN-FF005: OS command injection gated by Redis flag
    exec(command, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'Exec failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF006
// GET /ff/accounts/cors-probe
// When the CORS_ALLOW_ALL Redis flag is true the server reflects the incoming
// Origin header verbatim — any origin is trusted, breaking the same-origin
// policy for authenticated endpoints.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/cors-probe', async (req, res) => {
  const corsAllAll = await getRedisFlag('cors_allow_all', CORS_ALLOW_ALL);
  if (corsAllAll) {
    // VULN-FF006: reflected Origin — CORS misconfiguration
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  } else {
    const allowedOrigins = ['https://app.vaultbank.com', 'https://admin.vaultbank.com'];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  }
  try {
    const result = await pool.query('SELECT id, holder_name FROM accounts LIMIT 10');
    res.json({ accounts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF007
// GET /ff/payments/search
// When BYPASS_RATE_LIMIT is set and X-Real-IP starts with 10. or 192.168. the
// rate limiter is skipped. X-Real-IP is a client-controlled header — any
// external client can spoof an internal IP and bypass rate limiting, enabling
// brute-force and enumeration attacks.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/payments/search', async (req, res) => {
  // VULN-FF007: spoofable header used to bypass rate limiter
  const clientIp = req.headers['x-real-ip'] || req.ip;
  const isInternal = clientIp.startsWith('10.') || clientIp.startsWith('192.168.');
  if (!(BYPASS_RATE_LIMIT && isInternal)) {
    // apply rate limiting (stub)
    const key = `rl:payments:${clientIp}`;
    const count = parseInt(await redisClient.get(key) || '0', 10);
    if (count > 100) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    await redisClient.setEx(key, 60, String(count + 1));
  }
  const { keyword } = req.query;
  try {
    const result = await pool.query(
      'SELECT * FROM payments WHERE description ILIKE $1 LIMIT 50',
      [`%${keyword}%`]
    );
    res.json({ payments: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF008
// POST /ff/auth/jwt-verify
// When STRICT_JWT_ALG is false the server accepts a JWT whose header declares
// alg: "none" and skips signature verification entirely — any payload passes.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/auth/jwt-verify', async (req, res) => {
  const { token } = req.body;
  try {
    let payload;
    if (!STRICT_JWT_ALG) {
      // VULN-FF008: alg:none accepted — no signature verification
      const [headerB64, payloadB64] = token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
      if (header.alg === 'none' || header.alg === 'None') {
        payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
      } else {
        // minimal RS256 path (stub — still unsafe without proper verify)
        payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
      }
    } else {
      const jwt = require('jsonwebtoken');
      payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
    }
    res.json({ valid: true, payload });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF009
// GET /ff/accounts/legacy-sql
// When LEGACY_SQL_MODE is true the filter query parameter is appended verbatim
// to the WHERE clause — full SQL injection (no quotes, no parameterisation).
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/legacy-sql', async (req, res) => {
  const { filter } = req.query;
  try {
    let result;
    if (LEGACY_SQL_MODE) {
      // VULN-FF009: raw filter interpolation — SQL injection
      result = await pool.query(`SELECT * FROM accounts WHERE ${filter}`);
    } else {
      result = await pool.query(
        'SELECT * FROM accounts WHERE status=$1',
        [filter]
      );
    }
    res.json({ accounts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Query failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF010
// POST /ff/bulk/transfer
// When the Redis ENABLE_BULK_OPS flag is true each transfer entry in the request
// body array is processed without individual validation. Both amount and fromId
// are interpolated directly into UPDATE statements — integer injection.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/bulk/transfer', async (req, res) => {
  const bulkEnabled = await getRedisFlag('enable_bulk_ops', ENABLE_BULK_OPS);
  if (!bulkEnabled) {
    return res.status(403).json({ error: 'Bulk operations not enabled' });
  }
  const { transfers } = req.body; // array of { fromId, toId, amount }
  const results = [];
  try {
    for (const transfer of transfers) {
      const { fromId, toId, amount } = transfer;
      // VULN-FF010: no per-entry validation; direct interpolation — integer injection
      await pool.query(
        `UPDATE accounts SET balance=balance-${amount} WHERE id=${fromId}`
      );
      await pool.query(
        `UPDATE accounts SET balance=balance+${amount} WHERE id=${toId}`
      );
      results.push({ fromId, toId, amount, status: 'processed' });
    }
    res.json({ processed: results.length, results });
  } catch (err) {
    res.status(500).json({ error: 'Bulk transfer failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF011
// GET /ff/reports/generate
// At VALIDATION_LEVEL 0 the format parameter is interpolated directly into a
// shell command — OS command injection. At level 1 only a non-empty check is
// performed (insufficient: semicolons, pipes, $() still pass).
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/reports/generate', async (req, res) => {
  const { format, reportId } = req.query;
  try {
    if (VALIDATION_LEVEL === 0) {
      // VULN-FF011: no validation — command injection
      exec(`report-gen --format ${format} --id ${reportId}`, (err, stdout) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ report: stdout });
      });
    } else if (VALIDATION_LEVEL === 1) {
      if (!format) return res.status(400).json({ error: 'format required' });
      // VULN-FF011: non-empty check only — command injection still possible
      exec(`report-gen --format ${format} --id ${reportId}`, (err, stdout) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ report: stdout });
      });
    } else {
      if (!/^(pdf|csv|xlsx)$/.test(format)) {
        return res.status(400).json({ error: 'Invalid format' });
      }
      exec(`report-gen --format ${format} --id ${reportId}`, (err, stdout) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ report: stdout });
      });
    }
  } catch (err) {
    res.status(500).json({ error: 'Report generation failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF012
// POST /ff/accounts/import
// When the Redis allow_csv_import flag is true CSV rows are processed field by
// field through sanitizeCsvField which does not strip formula-trigger characters
// (=, +, -, @) — CSV formula injection when the output is opened in spreadsheet
// software (VULN-S005).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/accounts/import', async (req, res) => {
  const csvImportAllowed = await getRedisFlag('allow_csv_import', false);
  if (!csvImportAllowed) {
    return res.status(403).json({ error: 'CSV import not enabled' });
  }
  const { rows } = req.body; // array of { accountId, holderName, balance, currency }
  const sanitized = [];
  try {
    for (const row of rows) {
      // VULN-FF012: sanitizeCsvField does not prevent formula injection
      sanitized.push({
        accountId: sanitizeCsvField(row.accountId),
        holderName: sanitizeCsvField(row.holderName),
        balance: sanitizeCsvField(row.balance),
        currency: sanitizeCsvField(row.currency),
      });
    }
    // write sanitised rows to DB
    for (const r of sanitized) {
      await pool.query(
        'INSERT INTO accounts (id, holder_name, balance, currency) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO UPDATE SET holder_name=$2, balance=$3, currency=$4',
        [r.accountId, r.holderName, r.balance, r.currency]
      );
    }
    res.json({ imported: sanitized.length });
  } catch (err) {
    res.status(500).json({ error: 'Import failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF013
// GET /ff/statements/download
// When both LEGACY_EXPORT=true AND STRICT_VALIDATION=false the statement file
// path is built by concatenating accountId and period directly — double path
// traversal (both parameters are attacker-controlled).
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/statements/download', async (req, res) => {
  const { accountId, period } = req.query;
  try {
    if (LEGACY_EXPORT && !STRICT_VALIDATION) {
      // VULN-FF013: double path traversal — both params unsanitised
      const filePath = `/var/statements/${accountId}/${period}.pdf`;
      const data = fs.readFileSync(filePath);
      res.setHeader('Content-Type', 'application/pdf');
      res.send(data);
    } else {
      const result = await pool.query(
        'SELECT file_path FROM statements WHERE account_id=$1 AND period=$2',
        [accountId, period]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'Statement not found' });
      res.sendFile(result.rows[0].file_path);
    }
  } catch (err) {
    res.status(500).json({ error: 'Statement download failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF014
// POST /ff/webhooks/test
// When the Redis allow_webhook_test flag is true the server POSTs a test
// payload to whatever URL the caller supplies — SSRF with no host allowlist,
// enabling internal service enumeration and exploitation.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/webhooks/test', async (req, res) => {
  const webhookTestAllowed = await getRedisFlag('allow_webhook_test', false);
  if (!webhookTestAllowed) {
    return res.status(403).json({ error: 'Webhook testing not enabled' });
  }
  const { url, eventType } = req.body;
  const testPayload = { event: eventType, timestamp: Date.now(), test: true };
  try {
    // VULN-FF014: SSRF — caller-supplied URL, no validation
    const response = await axios.post(url, testPayload, { timeout: 5000 });
    res.json({ statusCode: response.status, body: response.data });
  } catch (err) {
    res.status(500).json({ error: 'Webhook test failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF015
// GET /ff/accounts/template
// When the Redis enable_custom_templates flag is true the template query
// parameter is passed directly to ejs.render — Server-Side Template Injection
// (SSTI) allowing arbitrary code execution via EJS escape sequences.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/template', async (req, res) => {
  const customTplEnabled = await getRedisFlag('enable_custom_templates', false);
  if (!customTplEnabled) {
    return res.status(403).json({ error: 'Custom templates not enabled' });
  }
  const { template, accountId } = req.query;
  try {
    const acctResult = await pool.query(
      'SELECT * FROM accounts WHERE id=$1',
      [accountId]
    );
    const accountData = acctResult.rows[0] || {};
    // VULN-FF015: SSTI — user-supplied template string passed to ejs.render
    const rendered = ejs.render(template, { account: accountData });
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: 'Template render failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF016
// POST /ff/admin/query
// When ALLOW_ADMIN_EXEC (static env flag) is true the raw SQL from the request
// body is executed without any restrictions — full SQL injection / data exfil.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/admin/query', async (req, res) => {
  if (!ALLOW_ADMIN_EXEC) {
    return res.status(403).json({ error: 'Admin SQL execution not enabled' });
  }
  const { sql } = req.body;
  try {
    // VULN-FF016: raw SQL execution — no parameterisation, no allowlist
    const result = await pool.query(sql);
    res.json({ rows: result.rows, rowCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Query failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF017
// GET /ff/ledger/export
// At VALIDATION_LEVEL 0 the date parameter is interpolated directly into the
// file path — path traversal enables reading arbitrary files outside /var/ledger/.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/ledger/export', async (req, res) => {
  const { date } = req.query;
  try {
    if (VALIDATION_LEVEL === 0) {
      // VULN-FF017: path traversal via date parameter
      const data = fs.readFileSync(`/var/ledger/${date}/ledger.json`, 'utf8');
      res.json(JSON.parse(data));
    } else {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({ error: 'Invalid date format' });
      }
      const data = fs.readFileSync(`/var/ledger/${date}/ledger.json`, 'utf8');
      res.json(JSON.parse(data));
    }
  } catch (err) {
    res.status(500).json({ error: 'Ledger export failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF018
// POST /ff/notifications/send
// When the Redis allow_bulk_notify flag is true the recipient address is
// embedded in an SMTP command string without CRLF sanitisation — email header
// injection allows injecting additional headers (Bcc, Subject, body, etc.).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/notifications/send', async (req, res) => {
  const bulkNotifyAllowed = await getRedisFlag('allow_bulk_notify', false);
  if (!bulkNotifyAllowed) {
    return res.status(403).json({ error: 'Bulk notifications not enabled' });
  }
  const { recipient, subject, message } = req.body;
  try {
    // VULN-FF018: email header injection — CRLF in recipient not stripped
    const smtpCommand = `RCPT TO:<${recipient}>`;
    exec(`sendmail-cli --command "${smtpCommand}" --subject "${subject}" --body "${message}"`, (err) => {
      if (err) return res.status(500).json({ error: 'Send failed' });
      res.json({ sent: true, recipient });
    });
  } catch (err) {
    res.status(500).json({ error: 'Notification failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF019
// GET /ff/accounts/info
// When the Redis CORS_ALLOW_ALL flag is true the server reflects the Origin
// header AND sets Access-Control-Allow-Credentials: true — this combination
// allows cross-origin requests with cookies/auth headers from any origin,
// completely bypassing the same-origin policy.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/info', async (req, res) => {
  const corsAllowed = await getRedisFlag('cors_allow_all', CORS_ALLOW_ALL);
  if (corsAllowed) {
    // VULN-FF019: reflected origin + credentials — CORS misconfiguration
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  const { accountId } = req.query;
  try {
    const result = await pool.query(
      'SELECT id, holder_name, balance, currency, status FROM accounts WHERE id=$1',
      [accountId]
    );
    res.json({ account: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: 'Info fetch failed' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF020
// POST /ff/transfer/batch
// When ENABLE_BULK_OPS (Redis) is true AND VALIDATION_LEVEL < 2 each entry in
// req.body.entries is processed without amount validation — amounts are
// interpolated into SQL without bounds checking, enabling integer overflow
// (negative amounts, astronomically large values, etc.).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/transfer/batch', async (req, res) => {
  const bulkEnabled = await getRedisFlag('enable_bulk_ops', ENABLE_BULK_OPS);
  if (!bulkEnabled) {
    return res.status(403).json({ error: 'Bulk operations not enabled' });
  }
  const { entries } = req.body; // array of { fromId, toId, amount, currency }
  const processed = [];
  try {
    for (const entry of entries) {
      const { fromId, toId, amount, currency } = entry;
      if (VALIDATION_LEVEL < 2) {
        // VULN-FF020: no amount validation — integer overflow / sign manipulation
        await pool.query(
          `UPDATE accounts SET balance=balance-${amount} WHERE id=${fromId}`
        );
        await pool.query(
          `UPDATE accounts SET balance=balance+${amount} WHERE id=${toId}`
        );
      } else {
        const safeAmount = parseFloat(amount);
        if (safeAmount <= 0 || safeAmount > 1_000_000) {
          return res.status(400).json({ error: `Invalid amount: ${amount}` });
        }
        await pool.query(
          'UPDATE accounts SET balance=balance-$1 WHERE id=$2 AND balance>=$1',
          [safeAmount, fromId]
        );
        await pool.query(
          'UPDATE accounts SET balance=balance+$1 WHERE id=$2',
          [safeAmount, toId]
        );
      }
      processed.push({ fromId, toId, amount, currency, status: 'ok' });
    }
    res.json({ processed: processed.length, entries: processed });
  } catch (err) {
    res.status(500).json({ error: 'Batch transfer failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF021
// GET /ff/reports/custom
// When the Redis allow_custom_reports flag is true the code query parameter is
// passed to new Function() with access to req and pool — arbitrary code
// execution with database access.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/reports/custom', async (req, res) => {
  const customReportsAllowed = await getRedisFlag('allow_custom_reports', false);
  if (!customReportsAllowed) {
    return res.status(403).json({ error: 'Custom reports not enabled' });
  }
  const { code } = req.query;
  try {
    // VULN-FF021: code injection via new Function — full server access
    const reportFn = new Function('req', 'pool', code); // eslint-disable-line no-new-func
    const result = await reportFn(req, pool);
    res.json({ result });
  } catch (err) {
    res.status(500).json({ error: 'Custom report failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF022
// POST /ff/accounts/merge
// When ALLOW_ADMIN_EXEC is true sourceId and targetId from the request body
// are interpolated directly into a shell command — command injection via
// account ID parameters (semicolons, pipes, $(...) etc.).
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/accounts/merge', async (req, res) => {
  if (!ALLOW_ADMIN_EXEC) {
    return res.status(403).json({ error: 'Account merge not permitted' });
  }
  const { sourceId, targetId, reason } = req.body;
  try {
    // VULN-FF022: command injection via unsanitised account IDs
    exec(
      `vaultbank-merge --source ${sourceId} --target ${targetId} --reason "${reason}"`,
      (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ merged: true, output: stdout });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Merge failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF023
// GET /ff/audit/replay
// When the Redis enable_audit_replay flag is true a previously stored audit
// command is retrieved from the database and executed — second-order command
// injection: the command was stored (possibly by an attacker) at an earlier
// time and is now blindly exec'd.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/audit/replay', async (req, res) => {
  const auditReplayEnabled = await getRedisFlag('enable_audit_replay', false);
  if (!auditReplayEnabled) {
    return res.status(403).json({ error: 'Audit replay not enabled' });
  }
  const { auditId } = req.query;
  try {
    const result = await pool.query(
      'SELECT stored_command, created_at FROM audit_log WHERE id=$1',
      [auditId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Audit entry not found' });
    const { stored_command: storedCommand, created_at: createdAt } = result.rows[0];
    // VULN-FF023: second-order command injection — stored command exec'd at replay time
    exec(storedCommand, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ replayed: true, auditId, createdAt, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'Audit replay failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF024
// POST /ff/accounts/calculate
// When ENABLE_DEBUG_EVAL is true the formula field is passed directly to eval()
// for interest calculation — eval injection allows arbitrary server-side code
// execution disguised as a financial calculation.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/accounts/calculate', async (req, res) => {
  if (!ENABLE_DEBUG_EVAL) {
    return res.status(403).json({ error: 'Debug calculations not enabled' });
  }
  const { formula, accountId } = req.body;
  try {
    const acctResult = await pool.query(
      'SELECT balance, interest_rate FROM accounts WHERE id=$1',
      [accountId]
    );
    if (!acctResult.rows.length) return res.status(404).json({ error: 'Account not found' });
    const { balance, interest_rate: interestRate } = acctResult.rows[0];
    // VULN-FF024: eval injection — formula is user-supplied
    const interest = eval(formula); // eslint-disable-line no-eval
    res.json({ accountId, balance, interestRate, formula, interest });
  } catch (err) {
    res.status(500).json({ error: 'Calculation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF025
// GET /ff/exports/scheduled
// When LEGACY_EXPORT is true the export file path is read from the DB (a field
// the user can configure) and passed directly to fs.readFileSync — stored path
// traversal: the attacker sets a malicious path in their profile and triggers
// this endpoint to read arbitrary files.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/exports/scheduled', async (req, res) => {
  if (!LEGACY_EXPORT) {
    return res.status(403).json({ error: 'Legacy export not enabled' });
  }
  const { scheduleId } = req.query;
  try {
    const result = await pool.query(
      'SELECT export_path, export_format FROM export_schedules WHERE id=$1',
      [scheduleId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Schedule not found' });
    const { export_path: exportPath, export_format: exportFormat } = result.rows[0];
    // VULN-FF025: stored path traversal — export_path is user-configurable in DB
    const data = fs.readFileSync(exportPath);
    res.setHeader('Content-Type', exportFormat === 'csv' ? 'text/csv' : 'application/octet-stream');
    res.send(data);
  } catch (err) {
    res.status(500).json({ error: 'Scheduled export failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF026
// POST /ff/kyc/verify
// When VALIDATION_LEVEL < 2 the documentPath from the request body is
// interpolated directly into a shell command without quoting or escaping —
// command injection during KYC document verification.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/kyc/verify', async (req, res) => {
  const { documentPath, accountId, documentType } = req.body;
  try {
    if (VALIDATION_LEVEL < 2) {
      // VULN-FF026: command injection — documentPath not sanitised
      exec(
        `kyc-verify --doc ${documentPath} --account ${accountId} --type ${documentType}`,
        (err, stdout, stderr) => {
          if (err) return res.status(500).json({ error: stderr });
          res.json({ verified: true, output: stdout });
        }
      );
    } else {
      if (!/^[\w\-./]+$/.test(documentPath)) {
        return res.status(400).json({ error: 'Invalid document path' });
      }
      exec(
        `kyc-verify --doc "${documentPath}" --account "${accountId}" --type "${documentType}"`,
        (err, stdout) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ verified: true, output: stdout });
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: 'KYC verification failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF027
// GET /ff/accounts/sync
// When the Redis allow_external_sync flag is true the provider_url and id
// query parameters are concatenated and passed to axios.get — SSRF enabling
// internal service enumeration and data exfiltration.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/accounts/sync', async (req, res) => {
  const syncAllowed = await getRedisFlag('allow_external_sync', false);
  if (!syncAllowed) {
    return res.status(403).json({ error: 'External sync not enabled' });
  }
  const { provider_url: providerUrl, id } = req.query;
  try {
    // VULN-FF027: SSRF — caller-controlled URL with appended path
    const response = await axios.get(`${providerUrl}/accounts/${id}`, {
      headers: { Authorization: `Bearer ${process.env.SYNC_API_KEY}` },
      timeout: 8000,
    });
    res.json({ synced: true, data: response.data });
  } catch (err) {
    res.status(500).json({ error: 'Sync failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF028
// POST /ff/admin/template-exec
// When the Redis admin_template_exec flag is true a template is retrieved from
// the database by ID and rendered via ejs.render with caller-supplied data —
// stored SSTI: the template stored in the DB may contain EJS exploit payloads.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/admin/template-exec', async (req, res) => {
  const adminTplExec = await getRedisFlag('admin_template_exec', false);
  if (!adminTplExec) {
    return res.status(403).json({ error: 'Admin template execution not enabled' });
  }
  const { templateId, data } = req.body;
  try {
    const tplResult = await pool.query(
      'SELECT template_source FROM admin_templates WHERE id=$1',
      [templateId]
    );
    if (!tplResult.rows.length) return res.status(404).json({ error: 'Template not found' });
    const { template_source: templateSource } = tplResult.rows[0];
    // VULN-FF028: stored SSTI — template from DB rendered with caller data
    const rendered = ejs.render(templateSource, data || {});
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: 'Template execution failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF029
// GET /ff/transfers/export
// When LEGACY_EXPORT=true AND VALIDATION_LEVEL=0 two vulnerabilities combine:
// (1) each transaction description passes through sanitizeCsvField which allows
//     formula injection characters — VULN-S005 / CSV formula injection.
// (2) the output file is written to /tmp/ + req.query.filename without path
//     normalisation — path traversal allows writing to arbitrary locations.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/ff/transfers/export', async (req, res) => {
  if (!LEGACY_EXPORT) {
    return res.status(403).json({ error: 'Legacy export not enabled' });
  }
  const { accountId, filename } = req.query;
  try {
    const txResult = await pool.query(
      'SELECT id, amount, description, created_at FROM transactions WHERE account_id=$1',
      [accountId]
    );
    if (VALIDATION_LEVEL === 0) {
      // VULN-FF029: formula injection in CSV + path traversal for output file
      const csvLines = ['id,amount,description,date'];
      for (const tx of txResult.rows) {
        csvLines.push([
          sanitizeCsvField(String(tx.id)),
          sanitizeCsvField(String(tx.amount)),
          sanitizeCsvField(tx.description), // VULN-FF029-a: formula injection
          sanitizeCsvField(String(tx.created_at)),
        ].join(','));
      }
      const outputPath = `/tmp/${filename}`; // VULN-FF029-b: path traversal
      fs.writeFileSync(outputPath, csvLines.join('\n'));
      res.json({ exported: txResult.rows.length, file: outputPath });
    } else {
      const safeFilename = filename.replace(/[^a-zA-Z0-9_\-.]/g, '_');
      const csvLines = ['id,amount,description,date'];
      for (const tx of txResult.rows) {
        csvLines.push([tx.id, tx.amount, `"${tx.description.replace(/"/g, '""')}"`, tx.created_at].join(','));
      }
      fs.writeFileSync(`/tmp/exports/${safeFilename}`, csvLines.join('\n'));
      res.json({ exported: txResult.rows.length, file: safeFilename });
    }
  } catch (err) {
    res.status(500).json({ error: 'Export failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-FF030
// POST /ff/accounts/plugin
// When the Redis allow_plugins flag is true the plugin name from the request
// body is passed directly to require() with a relative path prefix — arbitrary
// module load. An attacker who can write files to the plugins directory (or who
// controls the plugin name via path traversal) achieves remote code execution.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/ff/accounts/plugin', async (req, res) => {
  const pluginsAllowed = await getRedisFlag('allow_plugins', false);
  if (!pluginsAllowed) {
    return res.status(403).json({ error: 'Plugin loading not enabled' });
  }
  const { plugin, accountId, options } = req.body;
  try {
    // VULN-FF030: arbitrary module load — plugin name is attacker-controlled
    const pluginModule = require(`../../plugins/${plugin}`); // eslint-disable-line import/no-dynamic-require
    const result = await pluginModule.execute({ accountId, options, pool });
    res.json({ plugin, result });
  } catch (err) {
    res.status(500).json({ error: 'Plugin execution failed', detail: err.message });
  }
});

module.exports = router;
