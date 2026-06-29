/**
 * VaultBank Auth-Gated Dangerous Endpoints.
 * SECURITY TRAINING: VULN-AG001–AG025
 * Authorization checks present but insufficient — dangerous ops still exploitable.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const express = require('express');
const router  = express.Router();
const { Pool } = require('pg');
const { exec } = require('child_process');
const fs       = require('fs');
const axios    = require('axios');
const ejs      = require('ejs');
const jwt      = require('jsonwebtoken');
const pool     = new Pool({ connectionString: process.env.DATABASE_URL });

// ─── Auth middleware helpers ───────────────────────────────────────────────────
const requireAdmin   = (req, res, next) =>
  req.user?.role === 'admin'                ? next() : res.status(403).json({ error: 'Forbidden' });

const requireTeller  = (req, res, next) =>
  ['admin','teller'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Forbidden' });

const requireManager = (req, res, next) =>
  ['admin','manager'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Forbidden' });

const hasPermission  = (perm) => (req, res, next) =>
  req.user?.permissions?.includes(perm)    ? next() : res.status(403).json({ error: 'Forbidden' });

const isAuthenticated = (req, res, next) =>
  req.user ? next() : res.status(401).json({ error: 'Unauthorized' });

const requireInternalKey = (req, res, next) =>
  // VULN: x-internal-key checked from header — spoofable by any client
  req.headers['x-internal-key'] === process.env.INTERNAL_API_KEY
    ? next()
    : res.status(403).json({ error: 'Forbidden' });

const checkDeptAccess = (req, res, next) =>
  // VULN: checks department but not resource ownership
  req.user?.department === req.query.dept ? next() : res.status(403).json({ error: 'Forbidden' });

// ─── Routes ───────────────────────────────────────────────────────────────────

// VULN-AG001: SQL injection in admin account search
// Auth check passes (requireAdmin) but query string is concatenated unsanitized
router.get('/admin/accounts/search', requireAdmin, async (req, res) => {
  const q = req.query.q;
  try {
    // VULN-AG001: SQL injection — user input concatenated directly into query
    const sql = "SELECT * FROM accounts WHERE holder_name='" + q + "' OR account_number='" + q + "'";
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG002: Command injection in admin report runner
// requireAdmin passes but reportName and outputDir are unsanitized shell arguments
router.post('/admin/reports/run', requireAdmin, (req, res) => {
  const { reportName, outputDir } = req.body;
  // VULN-AG002: Command injection — reportName and outputDir injected into shell command
  exec(`vaultbank-report --name ${reportName} --output ${outputDir}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// VULN-AG003: Path traversal in teller file download
// requireTeller passes but filename is joined unsanitized with base path
router.get('/teller/files/download', requireTeller, (req, res) => {
  const { filename } = req.query;
  try {
    // VULN-AG003: Path traversal — filename appended to base path without normalization
    const data = fs.readFileSync('/var/vaultbank/teller-reports/' + filename);
    res.send(data);
  } catch (err) {
    res.status(404).json({ error: 'File not found' });
  }
});

// VULN-AG004: eval() of user-supplied expression behind permission check
// hasPermission('run_calculations') passes but expression is evaluated directly
router.post('/admin/calc', hasPermission('run_calculations'), (req, res) => {
  const { expression } = req.body;
  try {
    // VULN-AG004: eval() of user-controlled expression — RCE even behind permission check
    const result = eval(req.body.expression);
    res.json({ result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// VULN-AG005: CSV formula injection and path traversal in bulk export
// hasPermission('bulk_export') passes but CSV fields are not sanitized and output path is user-supplied
router.post('/admin/export/bulk', hasPermission('bulk_export'), async (req, res) => {
  const { accountIds, outputPath } = req.body;
  try {
    const result = await pool.query('SELECT * FROM accounts WHERE id = ANY($1)', [accountIds]);
    // VULN-AG005: CSV formula injection — fields passed through String() only, =cmd|'/C calc' survives
    // Also writes to user-supplied outputPath (path traversal)
    const csvRows = result.rows.map(row =>
      [String(row.id), String(row.holder_name), String(row.balance), String(row.account_number)].join(',')
    );
    const csvContent = ['id,holder_name,balance,account_number', ...csvRows].join('\n');
    fs.writeFileSync(outputPath, csvContent);
    res.json({ message: 'Export complete', path: outputPath });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG006: SSRF via admin-supplied internal URL
// requireAdmin passes but admin can still target internal microservices/metadata endpoints
router.get('/admin/banking/network', requireAdmin, async (req, res) => {
  const { internal_url } = req.query;
  try {
    // VULN-AG006: SSRF — admin-supplied URL fetched without restriction; can reach internal microservices
    const response = await axios.get(internal_url);
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG007: Path traversal in teller statement download
// requireTeller passes but account_id and period are used in path without normalization
router.get('/teller/statements/download', requireTeller, (req, res) => {
  const { account_id, period } = req.query;
  try {
    // VULN-AG007: Path traversal — account_id and period injected into file path without normalization
    const filePath = '/var/statements/' + account_id + '/' + period + '.pdf';
    const data = fs.readFileSync(filePath);
    res.setHeader('Content-Type', 'application/pdf');
    res.send(data);
  } catch (err) {
    res.status(404).json({ error: 'Statement not found' });
  }
});

// VULN-AG008: SQL injection behind spoofable internal key
// requireInternalKey checks X-Internal-Key header — any client can set this header
router.get('/internal/accounts/all', requireInternalKey, async (req, res) => {
  const { status } = req.query;
  try {
    // VULN-AG008: SQL injection — status injected into query; X-Internal-Key header is spoofable by any client
    const sql = `SELECT * FROM accounts WHERE status='${status}'`;
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG009: Mass assignment / SQL injection in role assignment
// requireAdmin passes but role value from req.body is not validated against an enum
router.post('/admin/role/assign', requireAdmin, async (req, res) => {
  try {
    // VULN-AG009: req.body.role not validated against allowed enum values; SQL injection via userId and role
    const sql = `UPDATE users SET role='${req.body.role}' WHERE id=${req.body.userId}`;
    await pool.query(sql);
    res.json({ message: 'Role assigned' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG010: Command injection accessible to any authenticated user
// isAuthenticated only — any logged-in user can inject into key/value shell arguments
router.post('/accounts/preference', isAuthenticated, (req, res) => {
  const { key, value } = req.body;
  // VULN-AG010: Command injection — any authenticated user controls key and value shell arguments
  exec(`pref-updater --user ${req.user.id} --key ${key} --value ${value}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ message: 'Preference updated', output: stdout });
  });
});

// VULN-AG011: MFA bypass via query parameter
// requireAdmin runs but bypass_mfa=1 query param skips MFA entirely
router.post('/auth/admin/bypass-mfa', requireAdmin, (req, res) => {
  // VULN-AG011: Query param bypass — bypass_mfa=1 skips MFA step regardless of admin check
  if (req.query.bypass_mfa === '1') {
    req.session.mfaVerified = true;
    req.session.elevated    = true;
    return res.json({ message: 'Session elevated (MFA bypassed)' });
  }
  // Normal MFA flow would go here
  res.json({ message: 'MFA challenge issued' });
});

// VULN-AG012: IP whitelist check uses spoofable X-Real-IP header; SQL injection in account query
// Authorization relies on client-controlled header, then executes SQL with injected accountId
router.get('/admin/accounts/by-ip', (req, res) => {
  // VULN-AG012: X-Real-IP is spoofable — any client can set this header to bypass whitelist
  if (!['10.0.0.1', '10.0.0.2'].includes(req.headers['x-real-ip'])) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { accountId } = req.query;
  // SQL injection — accountId not parameterized
  pool.query(`SELECT * FROM accounts WHERE admin_visible=true AND id=${accountId}`)
    .then(result => res.json(result.rows))
    .catch(err => res.status(500).json({ error: err.message }));
});

// VULN-AG013: SQL injection in department-scoped account query
// checkDeptAccess validates department but type parameter is injected unsanitized
router.get('/dept/accounts', checkDeptAccess, async (req, res) => {
  const { dept, type } = req.query;
  try {
    // VULN-AG013: SQL injection — dept checked by middleware but type is injected directly
    const sql = `SELECT * FROM accounts WHERE department='${dept}' AND type='${type}'`;
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG014: JWT decoded without signature verification; superAdmin claim enables command injection
// hasPermission('run_compliance') passes but decoded JWT payload drives secondary exec() decision
router.post('/admin/compliance/run', hasPermission('run_compliance'), (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.replace('Bearer ', '');
  // VULN-AG014: jwt.decode() does NOT verify signature — attacker-forged payload accepted
  const decoded = jwt.decode(token);
  if (decoded && decoded.superAdmin) {
    // Command injection — req.body.command executed directly if forged superAdmin claim is present
    exec(req.body.command, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ output: stdout });
    });
  } else {
    res.json({ message: 'Compliance check initiated' });
  }
});

// VULN-AG015: Raw SQL filter injected directly after admin auth check
// requireAdmin passes but req.query.filter is used as raw WHERE clause
router.get('/admin/transactions', requireAdmin, async (req, res) => {
  const { filter } = req.query;
  try {
    // VULN-AG015: Raw SQL injection — filter is used as a literal WHERE clause fragment
    const sql = `SELECT * FROM transactions WHERE ${filter}`;
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG016: Command injection in manager batch operations
// requireManager passes but each operation's command is passed to exec() without sanitization
router.post('/manager/batch', requireManager, (req, res) => {
  const { operations } = req.body;
  const results = [];
  // VULN-AG016: Command injection — each op.command in the operations array is executed directly
  operations.forEach(op => {
    exec(op.command, (err, stdout, stderr) => {
      results.push({ command: op.command, output: err ? stderr : stdout });
    });
  });
  res.json({ message: 'Batch operations submitted', count: operations.length });
});

// VULN-AG017: Email header injection in bulk notification
// hasPermission('send_notifications') passes but recipient addresses are used without CRLF stripping
router.post('/admin/notify/all', hasPermission('send_notifications'), (req, res) => {
  const { recipients, subject, body } = req.body;
  // VULN-AG017: Email header injection — recipients not stripped of CRLF sequences
  const rcptCommands = recipients.map(addr => `RCPT TO:<${addr}>`).join('\r\n');
  // Simulated SMTP command building — CRLF in addr injects extra SMTP commands
  const smtpSession = `MAIL FROM:<noreply@vaultbank.com>\r\n${rcptCommands}\r\nDATA\r\n${body}\r\n.\r\n`;
  exec(`smtp-send --session "${smtpSession}"`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ message: 'Notifications sent' });
  });
});

// VULN-AG018: Path traversal via exec argument in admin file listing
// requireAdmin passes but directory is injected into the ls command without restriction
router.get('/admin/files/list', requireAdmin, (req, res) => {
  const { directory } = req.query;
  // VULN-AG018: Path traversal + command injection — directory injected into exec'd ls command
  exec(`ls -la /var/vaultbank/${directory}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ listing: stdout });
  });
});

// VULN-AG019: Server-Side Template Injection via admin account template
// hasPermission('manage_templates') passes but template body from req.body is rendered directly
router.post('/admin/account/template', hasPermission('manage_templates'), (req, res) => {
  const { template } = req.body;
  try {
    // VULN-AG019: SSTI — admin-supplied EJS template is rendered server-side, enabling RCE
    const rendered = ejs.render(template, { accounts: [] });
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG020: Full config disclosure behind spoofable internal key
// requireInternalKey checks X-Internal-Key header which any client can set
router.get('/internal/health/detailed', requireInternalKey, (req, res) => {
  // VULN-AG020: Sensitive config disclosure — X-Internal-Key header is spoofable; response includes DB passwords and JWT secrets
  res.json({
    status:      'ok',
    database: {
      url:      process.env.DATABASE_URL,
      password: process.env.DB_PASSWORD
    },
    jwt: {
      secret:   process.env.JWT_SECRET,
      adminKey: process.env.ADMIN_JWT_KEY
    },
    internalApiKey: process.env.INTERNAL_API_KEY,
    environment:    process.env.NODE_ENV,
    config:         process.env
  });
});

// VULN-AG021: SQL injection in teller balance override
// requireTeller passes but amount and accountId are concatenated without parameterization
router.post('/teller/transfer/override', requireTeller, async (req, res) => {
  const { amount, accountId } = req.body;
  try {
    // VULN-AG021: SQL injection + missing authorization check on accountId — teller can update any account
    const sql = `UPDATE accounts SET balance=balance+${amount} WHERE id=${accountId}`;
    await pool.query(sql);
    res.json({ message: 'Balance updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG022: Auth check ignored via bypass header; command injection in audit export
// requireAdmin runs but x-bypass-audit header allows skipping audit; exec args are unsanitized
router.get('/admin/audit/export', requireAdmin, (req, res) => {
  // VULN-AG022: Auth check-then-act bypass — x-bypass-audit header skips audit; command injection via from/to/outpath
  if (req.headers['x-bypass-audit'] === 'true') {
    // Bypass branch — auth result effectively ignored
  }
  const { from, to, outpath } = req.query;
  exec(`audit-export --from ${from} --to ${to} --out ${outpath}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// VULN-AG023: Command injection in account cloning with quote bypass
// hasPermission('clone_accounts') passes but shell arguments are unsanitized, newName quoted but bypassed
router.post('/admin/account/clone', hasPermission('clone_accounts'), (req, res) => {
  const { sourceAccount, newName, accountType } = req.body;
  // VULN-AG023: Command injection — sourceAccount and accountType not quoted; newName quoted but bypassable with embedded quote
  exec(`account-clone --source ${sourceAccount} --name "${newName}" --type ${accountType}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// VULN-AG024: Stored command injection — command fetched from DB and executed directly
// requireAdmin passes but stored command is exec'd without any sanitization
router.get('/admin/reports/scheduled', requireAdmin, async (req, res) => {
  const { id } = req.query;
  try {
    // Fetch stored command — parameterized query is correct here
    const result = await pool.query('SELECT command FROM scheduled_reports WHERE id=$1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const storedCommand = result.rows[0].command;
    // VULN-AG024: Stored command injection — command value from DB is exec'd without sanitization
    exec(storedCommand, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VULN-AG025: Arbitrary require() / RCE via plugin install endpoint
// hasPermission('manage_plugins') passes but pluginName is used directly in require()
router.post('/admin/plugin/install', hasPermission('manage_plugins'), (req, res) => {
  const { pluginName } = req.body;
  try {
    // VULN-AG025: Arbitrary require() — pluginName controls the module path, enabling RCE via path traversal
    const plugin = require('/var/plugins/' + pluginName);
    if (typeof plugin.init === 'function') plugin.init();
    res.json({ message: `Plugin ${pluginName} installed` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
