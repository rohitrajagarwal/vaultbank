/**
 * VaultBank Second-Order Vulnerability Patterns.
 * SECURITY TRAINING: VULN-SO001–SO040
 * Input stored in session/Redis/DB at one point; used in dangerous sink later.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const express     = require('express');
const router      = express.Router();
const { Pool }    = require('pg');
const redis       = require('redis');
const { exec }    = require('child_process');
const axios       = require('axios');
const ejs         = require('ejs');
const fs          = require('fs');
const pool        = new Pool({ connectionString: process.env.DATABASE_URL });
const redisClient = redis.createClient({ url: process.env.REDIS_URL });

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO001
// GET /so/search/session
// Taint source: req.session.lastSearch — set by a prior POST /so/search/save
//   where the user supplies the search term and it is stored in the session
//   without sanitisation.
// Sink: string interpolation in a LIKE query.
// The session value is later used in a raw SQL LIKE clause, enabling SQL
// injection via the stored session value.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/search/session', async (req, res) => {
  try {
    const lastSearch = req.session?.lastSearch;
    if (!lastSearch) {
      return res.status(400).json({ error: 'No saved search in session' });
    }
    // VULN-SO001: session-stored value interpolated directly into SQL
    const result = await pool.query(
      `SELECT * FROM accounts WHERE holder_name LIKE '%${lastSearch}%'`
    );
    res.json({ accounts: result.rows, searchTerm: lastSearch });
  } catch (err) {
    res.status(500).json({ error: 'Session search failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO002
// GET /so/search/cache
// Taint source: Redis key user:{id}:last_search — written when the user
//   performs a transaction search; the raw search term is cached without
//   sanitisation.
// Sink: string interpolation in a WHERE clause.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/search/cache', async (req, res) => {
  const userId = req.user?.id;
  try {
    const searchTerm = await redisClient.get(`user:${userId}:last_search`);
    if (!searchTerm) {
      return res.status(404).json({ error: 'No cached search term' });
    }
    // VULN-SO002: Redis-cached value interpolated directly into SQL
    const result = await pool.query(
      `SELECT * FROM transactions WHERE description='${searchTerm}'`
    );
    res.json({ transactions: result.rows, searchTerm });
  } catch (err) {
    res.status(500).json({ error: 'Cache search failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO003
// GET /so/saved-query
// Taint source: saved_queries.template — a SQL template string stored by the
//   user via a "save query" feature; contains a {account_id} placeholder.
// Sink: pool.query() called with the reconstructed SQL string.
// The placeholder replacement via String.replace() does not parameterise the
// final query — stored SQL injection.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/saved-query', async (req, res) => {
  const { queryId, account_id: accountId } = req.query;
  try {
    const tplResult = await pool.query(
      'SELECT template FROM saved_queries WHERE id=$1',
      [queryId]
    );
    if (!tplResult.rows.length) return res.status(404).json({ error: 'Query not found' });
    const { template } = tplResult.rows[0];
    // VULN-SO003: stored SQL injection — template from DB, placeholder replaced, then executed raw
    const builtQuery = template.replace('{account_id}', accountId);
    const result = await pool.query(builtQuery);
    res.json({ rows: result.rows, query: builtQuery });
  } catch (err) {
    res.status(500).json({ error: 'Saved query failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO004
// GET /so/transactions
// Taint source: user_prefs.sort_column — set by the user in a preferences
//   update endpoint; stored as a free-text string.
// Sink: ORDER BY clause interpolation.
// An attacker who stores a malicious sort_column value (e.g.
//   "(SELECT...)" or "id; DROP TABLE") achieves SQL injection via ORDER BY.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/transactions', async (req, res) => {
  const userId = req.user?.id;
  const { accountId } = req.query;
  try {
    const prefResult = await pool.query(
      'SELECT sort_column FROM user_prefs WHERE user_id=$1',
      [userId]
    );
    const sortCol = prefResult.rows[0]?.sort_column || 'created_at';
    // VULN-SO004: stored ORDER BY injection — sort_column from DB is user-controlled
    const result = await pool.query(
      `SELECT * FROM transactions WHERE account_id=$1 ORDER BY ${sortCol} DESC`,
      [accountId]
    );
    res.json({ transactions: result.rows, sortedBy: sortCol });
  } catch (err) {
    res.status(500).json({ error: 'Transaction fetch failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO005
// POST /so/notify
// Taint source: user_profiles.webhook_url — configured by the user during
//   account setup and stored without URL validation.
// Sink: axios.post() call with the stored URL.
// A stored internal URL (e.g. http://169.254.169.254/...) triggers SSRF.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/notify', async (req, res) => {
  const userId = req.user?.id;
  const { eventType, payload } = req.body;
  try {
    const profileResult = await pool.query(
      'SELECT webhook_url FROM user_profiles WHERE user_id=$1',
      [userId]
    );
    if (!profileResult.rows.length) {
      return res.status(404).json({ error: 'User profile not found' });
    }
    const { webhook_url: webhookUrl } = profileResult.rows[0];
    // VULN-SO005: stored SSRF — webhook_url is user-configurable
    const response = await axios.post(webhookUrl, { event: eventType, data: payload });
    res.json({ notified: true, status: response.status });
  } catch (err) {
    res.status(500).json({ error: 'Notification failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO006
// POST /so/audit/log
// Taint source: req.session.username — set during login by storing the raw
//   username string the user supplied (no shell-escaping at login time).
// Sink: exec() call with the session username interpolated into the command.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/audit/log', async (req, res) => {
  const { action, resourceId } = req.body;
  const username = req.session?.username;
  try {
    // VULN-SO006: stored command injection — username from session used in exec
    exec(
      `vaultbank-audit --user "${username}" --action "${action}" --resource ${resourceId}`,
      (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ logged: true, output: stdout });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Audit log failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO007
// GET /so/account/display
// Taint source: req.cookies.displayFormat — set by the user's browser and
//   stored as a cookie; contains an EJS fragment for account display.
// Sink: ejs.render() with the cookie value as the template source.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/account/display', async (req, res) => {
  const { accountId } = req.query;
  const displayFormat = req.cookies?.displayFormat || '<%= account.holder_name %>';
  try {
    const acctResult = await pool.query(
      'SELECT * FROM accounts WHERE id=$1',
      [accountId]
    );
    const account = acctResult.rows[0] || {};
    // VULN-SO007: cookie-based SSTI — displayFormat is user-controlled EJS template
    const templateSource = `<div class="account-card">${displayFormat}</div>`;
    const rendered = ejs.render(templateSource, { account });
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: 'Display render failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO008
// GET /so/ldap/lookup
// Taint source: login_events.x_forwarded_for — the X-Forwarded-For header
//   captured during login and stored verbatim in the login_events table.
// Sink: LDAP filter construction using the stored value.
// Stored LDAP injection: an attacker supplies a crafted XFF at login time.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/ldap/lookup', async (req, res) => {
  const userId = req.user?.id;
  try {
    const evtResult = await pool.query(
      'SELECT x_forwarded_for FROM login_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
      [userId]
    );
    const storedXff = evtResult.rows[0]?.x_forwarded_for || '127.0.0.1';
    // VULN-SO008: stored LDAP injection — XFF stored at login, used in filter here
    const ldapFilter = `(&(ip=${storedXff})(department=banking))`;
    // stub: ldapClient.search('ou=staff,dc=vaultbank,dc=com', { filter: ldapFilter })
    res.json({ ldapFilter, storedXff, status: 'lookup initiated' });
  } catch (err) {
    res.status(500).json({ error: 'LDAP lookup failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO009
// POST /so/pdf/generate
// Taint source: pdf_templates.template_path — a file path stored in the DB
//   when the user configures their PDF template; not canonicalised at storage.
// Sink: exec() with the template path and accountId interpolated.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/pdf/generate', async (req, res) => {
  const { templateId, accountId } = req.body;
  try {
    const tplResult = await pool.query(
      'SELECT template_path FROM pdf_templates WHERE id=$1',
      [templateId]
    );
    if (!tplResult.rows.length) return res.status(404).json({ error: 'Template not found' });
    const { template_path: templatePath } = tplResult.rows[0];
    // VULN-SO009: stored command injection — template_path from DB used in exec
    exec(
      `pdfgen --template ${templatePath} --account ${accountId} --output /tmp/out.pdf`,
      (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ generated: true, path: '/tmp/out.pdf', output: stdout });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'PDF generation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO010
// GET /so/account/nickname
// Taint source: account_aliases.nickname — set by the account holder via a
//   "set nickname" endpoint; stored without HTML escaping.
// Sink: res.send() with the nickname interpolated into an HTML string.
// Stored XSS: any HTML/script in the nickname executes in the viewer's browser.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/account/nickname', async (req, res) => {
  const { accountId } = req.query;
  try {
    const nickResult = await pool.query(
      'SELECT nickname FROM account_aliases WHERE account_id=$1',
      [accountId]
    );
    const nickname = nickResult.rows[0]?.nickname || 'Unnamed Account';
    // VULN-SO010: stored XSS — nickname from DB rendered without HTML escaping
    res.setHeader('Content-Type', 'text/html');
    res.send(`<div class="account-name">${nickname}</div>`);
  } catch (err) {
    res.status(500).json({ error: 'Nickname fetch failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO011
// POST /so/preferences/load
// Taint source: user_settings.serialized_prefs — a JSON blob stored when the
//   user saves preferences; the JSON is not validated for prototype-polluting
//   keys (__proto__, constructor, etc.) at storage time.
// Sink: Object.assign(req.session, parsedPrefs) — prototype pollution via
//   stored JSON, which can override session properties for all subsequent
//   requests on this session.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/preferences/load', async (req, res) => {
  const userId = req.user?.id;
  try {
    const prefResult = await pool.query(
      'SELECT serialized_prefs FROM user_settings WHERE user_id=$1',
      [userId]
    );
    if (!prefResult.rows.length) return res.status(404).json({ error: 'Preferences not found' });
    const { serialized_prefs: serializedPrefs } = prefResult.rows[0];
    // VULN-SO011: prototype pollution — JSON from DB assigned directly to session
    const parsedPrefs = JSON.parse(serializedPrefs);
    Object.assign(req.session, parsedPrefs);
    res.json({ loaded: true, prefs: parsedPrefs });
  } catch (err) {
    res.status(500).json({ error: 'Preference load failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO012
// POST /so/email/send
// Taint source: email_templates.body_template — an EJS template stored in the
//   DB when an admin or user creates an email template; may contain injected
//   EJS escape sequences.
// Sink: ejs.render(template, { user: req.body }) — stored SSTI.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/email/send', async (req, res) => {
  const { templateId, recipientId } = req.body;
  try {
    const tplResult = await pool.query(
      'SELECT body_template, subject_template FROM email_templates WHERE id=$1',
      [templateId]
    );
    if (!tplResult.rows.length) return res.status(404).json({ error: 'Email template not found' });
    const { body_template: bodyTemplate, subject_template: subjectTemplate } = tplResult.rows[0];
    // VULN-SO012: stored SSTI — body_template from DB rendered with user input
    const renderedBody = ejs.render(bodyTemplate, { user: req.body });
    const renderedSubject = ejs.render(subjectTemplate, { user: req.body });
    // stub: mailTransport.sendMail({ to: recipientId, subject: renderedSubject, html: renderedBody })
    res.json({ sent: true, subject: renderedSubject, recipientId });
  } catch (err) {
    res.status(500).json({ error: 'Email send failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO013
// GET /so/report/custom
// Taint source: custom_reports.sql_query — a raw SQL string stored by the
//   report owner; ownership check is present but the SQL itself is unconstrained.
// Sink: pool.query(storedSql) — stored SQL injection even within own data.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/report/custom', async (req, res) => {
  const userId = req.user?.id;
  const { reportId } = req.query;
  try {
    const rptResult = await pool.query(
      'SELECT sql_query FROM custom_reports WHERE id=$1 AND owner_id=$2',
      [reportId, userId]
    );
    if (!rptResult.rows.length) return res.status(404).json({ error: 'Report not found' });
    const { sql_query: storedSql } = rptResult.rows[0];
    // VULN-SO013: stored SQL injection — user's own stored query executed directly
    const result = await pool.query(storedSql);
    res.json({ rows: result.rows, rowCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Custom report failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO014
// GET /so/transaction/memo
// Taint source: transactions.memo — free-text memo field set by the payer at
//   transfer time; stored without HTML encoding.
// Sink: res.send() with the memo interpolated into HTML — stored XSS.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/transaction/memo', async (req, res) => {
  const { txId } = req.query;
  try {
    const txResult = await pool.query(
      'SELECT memo, amount, created_at FROM transactions WHERE id=$1',
      [txId]
    );
    if (!txResult.rows.length) return res.status(404).json({ error: 'Transaction not found' });
    const { memo, amount, created_at: createdAt } = txResult.rows[0];
    // VULN-SO014: stored XSS — memo rendered as raw HTML without escaping
    res.setHeader('Content-Type', 'text/html');
    res.send(`
      <div class="transaction-detail">
        <span class="amount">$${amount}</span>
        <span class="date">${createdAt}</span>
        <p class="memo">${memo}</p>
      </div>
    `);
  } catch (err) {
    res.status(500).json({ error: 'Memo fetch failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO015
// POST /so/search/elasticsearch
// Taint source: user_settings.search_filter — a raw Elasticsearch query string
//   saved by the user and stored without query-syntax validation.
// Sink: Elasticsearch query_string query — stored ES query injection enabling
//   access to data outside the user's scope.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/search/elasticsearch', async (req, res) => {
  const userId = req.user?.id;
  try {
    const settingsResult = await pool.query(
      'SELECT search_filter FROM user_settings WHERE user_id=$1',
      [userId]
    );
    const storedFilter = settingsResult.rows[0]?.search_filter || '*';
    // VULN-SO015: stored ES query injection — stored filter used in query_string
    // stub: esClient.search({ index: 'transactions', body: { query: { query_string: { query: storedFilter } } } })
    const esQuery = { query: { query_string: { query: storedFilter } } };
    res.json({ esQuery, storedFilter, status: 'search dispatched' });
  } catch (err) {
    res.status(500).json({ error: 'Elasticsearch search failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO016
// POST /so/notifications/template
// Taint source: notification_configs.notify_template — a JavaScript code
//   fragment stored when the user configures a notification template.
// Sink: new Function('data', notifyTemplate)(notificationData) — stored code
//   injection: the stored template is executed as JavaScript.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/notifications/template', async (req, res) => {
  const { configId, notificationData } = req.body;
  try {
    const cfgResult = await pool.query(
      'SELECT notify_template FROM notification_configs WHERE id=$1',
      [configId]
    );
    if (!cfgResult.rows.length) return res.status(404).json({ error: 'Config not found' });
    const { notify_template: notifyTemplate } = cfgResult.rows[0];
    // VULN-SO016: stored code injection — notify_template executed via new Function
    const renderFn = new Function('data', notifyTemplate); // eslint-disable-line no-new-func
    const output = renderFn(notificationData);
    res.json({ rendered: output, configId });
  } catch (err) {
    res.status(500).json({ error: 'Notification template failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO017
// GET /so/files/user-path
// Taint source: user_settings.file_path_pref — a file path preference stored
//   by the user (e.g. preferred export directory); stored without path
//   canonicalisation or allowlist enforcement.
// Sink: fs.readFileSync(storedPath) — stored path traversal.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/files/user-path', async (req, res) => {
  const userId = req.user?.id;
  try {
    const settingsResult = await pool.query(
      'SELECT file_path_pref FROM user_settings WHERE user_id=$1',
      [userId]
    );
    if (!settingsResult.rows.length) return res.status(404).json({ error: 'Settings not found' });
    const { file_path_pref: storedPath } = settingsResult.rows[0];
    // VULN-SO017: stored path traversal — storedPath from DB read without validation
    const data = fs.readFileSync(storedPath, 'utf8');
    res.json({ path: storedPath, content: data });
  } catch (err) {
    res.status(500).json({ error: 'File read failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO018
// GET /so/filter/regex
// Taint source: user_prefs.filter_regex — a regular expression string stored
//   by the user to filter their transaction list; stored without ReDoS analysis.
// Sink: new RegExp(storedFilter).test(input) — stored ReDoS: a crafted regex
//   like (a+)+ can cause catastrophic backtracking and DoS the Node.js thread.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/filter/regex', async (req, res) => {
  const userId = req.user?.id;
  const { input } = req.query;
  try {
    const prefResult = await pool.query(
      'SELECT filter_regex FROM user_prefs WHERE user_id=$1',
      [userId]
    );
    const storedFilter = prefResult.rows[0]?.filter_regex || '.*';
    // VULN-SO018: stored ReDoS — regex from DB applied to user input without validation
    const regex = new RegExp(storedFilter);
    const matched = regex.test(input);
    res.json({ matched, filter: storedFilter, input });
  } catch (err) {
    res.status(500).json({ error: 'Regex filter failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO019
// GET /so/transactions/sorted
// Taint source: req.cookies.sortDirection — set by the browser when the user
//   clicks a sort button; stored in cookie as 'ASC' or 'DESC' (or anything
//   else the attacker sets).
// Sink: ORDER BY interpolation — cookie value appended directly to SQL.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/transactions/sorted', async (req, res) => {
  const { accountId } = req.query;
  // VULN-SO019: cookie-based ORDER BY injection — sortDirection is attacker-controlled
  const sortDirection = req.cookies?.sortDirection || 'DESC';
  try {
    const result = await pool.query(
      `SELECT * FROM transactions WHERE account_id=$1 ORDER BY created_at ${sortDirection}`,
      [accountId]
    );
    res.json({ transactions: result.rows, sortDirection });
  } catch (err) {
    res.status(500).json({ error: 'Sorted transactions failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO020
// POST /so/tasks/execute
// Taint source: scheduled_tasks.command — a command string stored when a user
//   creates a scheduled maintenance task; not sanitised at creation time.
// Sink: exec(storedCommand) — stored command injection via task queue.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/tasks/execute', async (req, res) => {
  const { taskId } = req.body;
  try {
    const taskResult = await pool.query(
      "SELECT command FROM scheduled_tasks WHERE id=$1 AND status='pending'",
      [taskId]
    );
    if (!taskResult.rows.length) return res.status(404).json({ error: 'Task not found or not pending' });
    const { command: storedCommand } = taskResult.rows[0];
    // VULN-SO020: stored command injection — command from DB executed directly
    exec(storedCommand, async (err, stdout, stderr) => {
      if (err) {
        await pool.query("UPDATE scheduled_tasks SET status='failed' WHERE id=$1", [taskId]);
        return res.status(500).json({ error: stderr });
      }
      await pool.query("UPDATE scheduled_tasks SET status='completed' WHERE id=$1", [taskId]);
      res.json({ executed: true, taskId, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'Task execution failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO021
// GET /so/hl7/generate
// Taint source: medical_payment_configs.hl7_template — an HL7 message template
//   stored per institution; contains a {amount} placeholder.
// Sink: exec() with the rendered template interpolated into a shell command.
// Double injection: (1) amount is injected into the template string;
// (2) the resulting string is passed unsanitised to a shell command.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/hl7/generate', async (req, res) => {
  const { configId, amount } = req.query;
  try {
    const cfgResult = await pool.query(
      'SELECT hl7_template FROM medical_payment_configs WHERE id=$1',
      [configId]
    );
    if (!cfgResult.rows.length) return res.status(404).json({ error: 'Config not found' });
    const { hl7_template: template } = cfgResult.rows[0];
    // VULN-SO021: stored template + command injection — template from DB, amount from request
    const renderedTemplate = template.replace('{amount}', amount);
    exec(`hl7-send --message "${renderedTemplate}"`, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ sent: true, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'HL7 generation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO022
// POST /so/account/restore
// Taint source: account_backups.backup_path — a file path stored when the
//   backup was created; an attacker with write access to backup records can
//   plant a path containing shell metacharacters.
// Sink: exec() with the backup path interpolated without quoting.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/account/restore', async (req, res) => {
  const { accountId } = req.body;
  try {
    const backupResult = await pool.query(
      'SELECT backup_path FROM account_backups WHERE account_id=$1 ORDER BY created_at DESC LIMIT 1',
      [accountId]
    );
    if (!backupResult.rows.length) return res.status(404).json({ error: 'Backup not found' });
    const { backup_path: backupPath } = backupResult.rows[0];
    // VULN-SO022: stored path command injection — backup_path from DB, unquoted in exec
    exec(`restore-tool --file ${backupPath} --account ${accountId}`, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ restored: true, accountId, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'Account restore failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO023
// GET /so/swift/message
// Taint source: swift_configs.swift_template — an institution-level SWIFT
//   message template stored in the DB with a {beneficiary} placeholder.
// Sink: exec() with the rendered template (including request-supplied
//   beneficiary) passed to a SWIFT sender utility without shell-escaping.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/swift/message', async (req, res) => {
  const { institutionId, beneficiary } = req.query;
  try {
    const swiftResult = await pool.query(
      'SELECT swift_template FROM swift_configs WHERE institution_id=$1',
      [institutionId]
    );
    if (!swiftResult.rows.length) return res.status(404).json({ error: 'SWIFT config not found' });
    const { swift_template: swiftTemplate } = swiftResult.rows[0];
    // VULN-SO023: stored template injection + command injection
    const renderedMessage = swiftTemplate.replace('{beneficiary}', beneficiary);
    exec(`swift-sender --message "${renderedMessage}"`, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ dispatched: true, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'SWIFT message failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO024
// POST /so/report/schedule
// Taint source: user_schedules.cron_expr AND user_schedules.command — both
//   stored when the user creates a scheduled report; neither is validated.
// Sink: node-cron schedule + exec() — stored cron expression injection and
//   stored command injection: the cron job executes the stored command.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/report/schedule', async (req, res) => {
  const { scheduleId } = req.body;
  try {
    const schedResult = await pool.query(
      'SELECT cron_expr, report_command FROM user_schedules WHERE id=$1',
      [scheduleId]
    );
    if (!schedResult.rows.length) return res.status(404).json({ error: 'Schedule not found' });
    const { cron_expr: cronExpr, report_command: storedCommand } = schedResult.rows[0];
    const cron = require('node-cron');
    // VULN-SO024: stored cron injection + stored command injection
    cron.schedule(cronExpr, () => {
      exec(storedCommand, (err, stdout) => { // eslint-disable-line no-unused-vars
        if (err) console.error('Scheduled exec error:', err);
      });
    });
    res.json({ scheduled: true, cronExpr, scheduleId });
  } catch (err) {
    res.status(500).json({ error: 'Schedule setup failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO025
// GET /so/account/statement-html
// Taint source: statement_templates.template_path — a relative template path
//   stored when the user selects a custom statement layout; not canonicalised.
// Sink: ejs.renderFile('/templates/' + storedTemplatePath, data) — stored
//   path traversal: the attacker stores '../../../etc/passwd' as the template
//   path, causing the template engine to read arbitrary files.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/account/statement-html', async (req, res) => {
  const { accountId } = req.query;
  try {
    const tplResult = await pool.query(
      'SELECT html_template FROM statement_templates WHERE account_id=$1',
      [accountId]
    );
    const storedTemplatePath = tplResult.rows[0]?.html_template || 'default.ejs';
    const acctResult = await pool.query(
      'SELECT * FROM accounts WHERE id=$1',
      [accountId]
    );
    // VULN-SO025: stored path traversal — template path from DB, no canonicalisation
    ejs.renderFile(`/templates/${storedTemplatePath}`, { account: acctResult.rows[0] }, (err, html) => {
      if (err) return res.status(500).json({ error: err.message });
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    });
  } catch (err) {
    res.status(500).json({ error: 'Statement render failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO026
// POST /so/transfer/validate
// Taint source: req.session.transferRules — a JSON object set during session
//   initialisation by reading compliance rules from the DB; may contain a
//   validationScript field that is arbitrary JavaScript.
// Sink: eval(transferRules.validationScript) — stored eval via session object.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/transfer/validate', async (req, res) => {
  const { amount, fromId, toId } = req.body;
  const transferRules = req.session?.transferRules;
  try {
    if (transferRules?.validationScript) {
      // VULN-SO026: stored eval — validationScript from session (originally from DB)
      const validationResult = eval(transferRules.validationScript); // eslint-disable-line no-eval
      if (!validationResult) {
        return res.status(400).json({ error: 'Transfer validation failed by stored rule' });
      }
    }
    res.json({ valid: true, amount, fromId, toId });
  } catch (err) {
    res.status(500).json({ error: 'Validation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO027
// GET /so/accounts/formatted
// Taint source: req.cookies.accountFormat (first hop) → DB template lookup
//   (second hop) → res.send() with unescaped JSON (third hop).
// Multiple hops: cookie → DB → response.
// The cookie drives a DB lookup for the HTML template; the resulting template
// is populated with unescaped account data and sent as raw HTML.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/accounts/formatted', async (req, res) => {
  const userId = req.user?.id;
  // Hop 1: cookie sets format type
  const accountFormat = req.cookies?.accountFormat || 'standard';
  try {
    // Hop 2: format type used to look up HTML template from DB
    const tplResult = await pool.query(
      'SELECT template_html FROM display_templates WHERE format_type=$1',
      [accountFormat]
    );
    const templateHtml = tplResult.rows[0]?.template_html || '<p>{data}</p>';
    const acctResult = await pool.query(
      'SELECT * FROM accounts WHERE user_id=$1',
      [userId]
    );
    // VULN-SO027: multi-hop stored XSS — template from DB rendered with unescaped data
    // Hop 3: template (from DB) populated with account data, sent as raw HTML
    const rendered = templateHtml.replace('{data}', JSON.stringify(acctResult.rows));
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: 'Formatted accounts failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO028
// POST /so/kyc/process
// Taint source: kyc_submissions.document_path — the file path supplied by the
//   user when they submit a KYC document; stored without path sanitisation.
// Sink: exec() with the stored path and accountId interpolated.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/kyc/process', async (req, res) => {
  const { submissionId, accountId } = req.body;
  try {
    const kycResult = await pool.query(
      'SELECT document_path FROM kyc_submissions WHERE id=$1 AND account_id=$2',
      [submissionId, accountId]
    );
    if (!kycResult.rows.length) return res.status(404).json({ error: 'KYC submission not found' });
    const { document_path: documentPath } = kycResult.rows[0];
    // VULN-SO028: stored command injection — document_path from DB used in exec
    exec(
      `kyc-validator --doc ${documentPath} --account ${accountId}`,
      (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ processed: true, submissionId, output: stdout });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'KYC processing failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO029
// GET /so/analytics/query
// Taint source: dashboard_configs.analytics_query — a SQL query string stored
//   when the user configures their analytics dashboard widgets.
// Sink: pool.query(storedQuery) — stored SQL injection in analytics module.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/analytics/query', async (req, res) => {
  const userId = req.user?.id;
  try {
    const cfgResult = await pool.query(
      'SELECT analytics_query FROM dashboard_configs WHERE user_id=$1',
      [userId]
    );
    if (!cfgResult.rows.length) return res.status(404).json({ error: 'Dashboard config not found' });
    const { analytics_query: storedQuery } = cfgResult.rows[0];
    // VULN-SO029: stored SQL injection — analytics query from DB executed directly
    const result = await pool.query(storedQuery);
    res.json({ data: result.rows, rowCount: result.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Analytics query failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO030
// POST /so/webhook/replay
// Taint source: webhook_events.target_url and webhook_events.payload — both
//   stored when the original webhook was received; target_url is caller-
//   supplied and payload is external-service-supplied, neither validated.
// Sink: axios.post(targetUrl, JSON.parse(payload)) — stored SSRF.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/webhook/replay', async (req, res) => {
  const { eventId } = req.body;
  try {
    const evtResult = await pool.query(
      'SELECT payload, target_url FROM webhook_events WHERE id=$1',
      [eventId]
    );
    if (!evtResult.rows.length) return res.status(404).json({ error: 'Webhook event not found' });
    const { payload, target_url: targetUrl } = evtResult.rows[0];
    // VULN-SO030: stored SSRF — targetUrl from DB, no host validation
    const response = await axios.post(targetUrl, JSON.parse(payload), { timeout: 5000 });
    res.json({ replayed: true, eventId, status: response.status });
  } catch (err) {
    res.status(500).json({ error: 'Webhook replay failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO031
// GET /so/render/component
// Taint source: Redis key ui:component:{id} — a cached UI component template
//   written when an admin publishes a UI update; may contain injected EJS.
// Sink: ejs.render(cachedTemplate, req.query) — cached template SSTI.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/render/component', async (req, res) => {
  const { component_id: componentId } = req.query;
  try {
    const cachedTemplate = await redisClient.get(`ui:component:${componentId}`);
    if (!cachedTemplate) return res.status(404).json({ error: 'Component not found in cache' });
    // VULN-SO031: cached template SSTI — Redis-cached EJS template rendered with query params
    const rendered = ejs.render(cachedTemplate, req.query);
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: 'Component render failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO032
// POST /so/account/command
// Taint source: account_commands.pending_command — a command string enqueued
//   via a prior API call (e.g. an admin or the account owner adding a task);
//   stored without shell sanitisation.
// Sink: exec(pendingCommand) — dequeued stored command injection.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/account/command', async (req, res) => {
  const { accountId } = req.body;
  try {
    const cmdResult = await pool.query(
      "SELECT id, pending_command FROM account_commands WHERE account_id=$1 AND status='queued' ORDER BY created_at LIMIT 1",
      [accountId]
    );
    if (!cmdResult.rows.length) return res.status(404).json({ error: 'No queued command' });
    const { id: cmdId, pending_command: pendingCommand } = cmdResult.rows[0];
    // VULN-SO032: stored command injection — dequeued command executed directly
    exec(`vaultbank-cmd ${pendingCommand}`, async (err, stdout, stderr) => {
      if (err) {
        await pool.query("UPDATE account_commands SET status='failed' WHERE id=$1", [cmdId]);
        return res.status(500).json({ error: stderr });
      }
      await pool.query("UPDATE account_commands SET status='done' WHERE id=$1", [cmdId]);
      res.json({ executed: true, cmdId, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: 'Account command failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO033
// GET /so/reports/path
// Taint source: Redis key report:{userId}:path — written when the user
//   generates a report and stores the output path preference; not validated at
//   write time.
// Sink: fs.readFileSync(cachedPath) — Redis-cached path traversal.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/reports/path', async (req, res) => {
  const userId = req.user?.id;
  try {
    const cachedPath = await redisClient.get(`report:${userId}:path`);
    if (!cachedPath) return res.status(404).json({ error: 'No cached report path' });
    // VULN-SO033: Redis-cached path traversal — path from Redis read without validation
    const data = fs.readFileSync(cachedPath, 'utf8');
    res.json({ path: cachedPath, content: data });
  } catch (err) {
    res.status(500).json({ error: 'Report path read failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO034
// POST /so/auth/impersonate
// Taint source: admin_sessions.impersonation_token — a JWT token stored when
//   an admin initiates an impersonation session; may have been tampered with
//   if the storage is accessible.
// Sink: jwt.decode() without verify — the stored token is decoded but its
//   signature is never checked, and the embedded userId is trusted unconditionally.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/auth/impersonate', async (req, res) => {
  const { sessionId } = req.body;
  try {
    const sessResult = await pool.query(
      'SELECT impersonation_token FROM admin_sessions WHERE session_id=$1',
      [sessionId]
    );
    if (!sessResult.rows.length) return res.status(404).json({ error: 'Admin session not found' });
    const { impersonation_token: token } = sessResult.rows[0];
    const jwt = require('jsonwebtoken');
    // VULN-SO034: stored JWT bypass — token decoded without verification
    const payload = jwt.decode(token);
    req.session.userId = payload?.userId;
    req.session.role   = payload?.role;
    res.json({ impersonating: true, userId: payload?.userId, role: payload?.role });
  } catch (err) {
    res.status(500).json({ error: 'Impersonation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO035
// GET /so/accounts/xml
// Taint source: account_metadata.xml_fragment — an XML fragment stored in
//   account metadata (e.g. for SEPA/ISO-20022 integration); stored without
//   XML entity/element sanitisation.
// Sink: res.send() with the fragment embedded in a larger XML document —
//   stored XXE and stored XSS via XML fragment injection.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/accounts/xml', async (req, res) => {
  const { accountId } = req.query;
  try {
    const metaResult = await pool.query(
      'SELECT xml_fragment FROM account_metadata WHERE account_id=$1',
      [accountId]
    );
    const xmlFragment = metaResult.rows[0]?.xml_fragment || '<name>Unknown</name>';
    // VULN-SO035: stored XXE/XSS — xml_fragment from DB embedded without sanitisation
    res.setHeader('Content-Type', 'application/xml');
    res.send(`<?xml version="1.0"?><account><data>${xmlFragment}</data></account>`);
  } catch (err) {
    res.status(500).json({ error: 'XML generation failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO036
// POST /so/plugins/load
// Taint source: enabled_plugins.plugin_path — a plugin file path stored when a
//   tenant admin enables a plugin via the management console.
// Sink: require(storedPluginPath) — stored arbitrary require / RCE: a malicious
//   plugin path (absolute or traversal-based) loads arbitrary code.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/plugins/load', async (req, res) => {
  const tenantId = req.user?.tenantId;
  const { pluginId } = req.body;
  try {
    const pluginResult = await pool.query(
      'SELECT plugin_path FROM enabled_plugins WHERE id=$1 AND tenant_id=$2',
      [pluginId, tenantId]
    );
    if (!pluginResult.rows.length) return res.status(404).json({ error: 'Plugin not found' });
    const { plugin_path: storedPluginPath } = pluginResult.rows[0];
    // VULN-SO036: stored arbitrary require — plugin_path from DB passed to require()
    const pluginModule = require(storedPluginPath); // eslint-disable-line import/no-dynamic-require
    const result = await pluginModule.init({ pool, tenantId });
    res.json({ loaded: true, pluginId, result });
  } catch (err) {
    res.status(500).json({ error: 'Plugin load failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO037
// GET /so/transfers/template
// Taint source: user_templates.transfer_template — a JavaScript function body
//   stored when the user creates a custom transfer calculation template.
// Sink: new Function('amount', 'recipient', storedTemplate)(amount, recipient)
//   — stored code injection: the stored template is executed as JavaScript.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/transfers/template', async (req, res) => {
  const userId = req.user?.id;
  const { amount, recipient } = req.query;
  try {
    const tplResult = await pool.query(
      'SELECT transfer_template FROM user_templates WHERE user_id=$1',
      [userId]
    );
    if (!tplResult.rows.length) return res.status(404).json({ error: 'Template not found' });
    const { transfer_template: storedTemplate } = tplResult.rows[0];
    // VULN-SO037: stored code injection — transfer_template from DB executed via new Function
    const calcFn = new Function('amount', 'recipient', storedTemplate); // eslint-disable-line no-new-func
    const result = calcFn(parseFloat(amount), recipient);
    res.json({ result, amount, recipient });
  } catch (err) {
    res.status(500).json({ error: 'Transfer template failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO038
// POST /so/account/script
// Taint source: compliance_rules.validation_script — a Node.js script stored
//   by compliance officers to enforce custom business rules.
// Sink: vm.runInNewContext(storedScript, sandbox) — stored sandbox escape:
//   known CVEs in Node.js vm module (and vm2) allow breaking out of the sandbox
//   context and executing arbitrary code in the host process.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/account/script', async (req, res) => {
  const { ruleId, accountId } = req.body;
  try {
    const ruleResult = await pool.query(
      'SELECT validation_script FROM compliance_rules WHERE rule_id=$1',
      [ruleId]
    );
    if (!ruleResult.rows.length) return res.status(404).json({ error: 'Rule not found' });
    const { validation_script: storedScript } = ruleResult.rows[0];
    const acctResult = await pool.query(
      'SELECT * FROM accounts WHERE id=$1',
      [accountId]
    );
    const vm = require('vm');
    const sandbox = { account: acctResult.rows[0], result: null };
    // VULN-SO038: stored sandbox escape — vm.runInNewContext is not a security boundary
    vm.runInNewContext(storedScript, sandbox);
    res.json({ ruleId, accountId, result: sandbox.result });
  } catch (err) {
    res.status(500).json({ error: 'Script execution failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO039
// GET /so/ldap/employee
// Taint source: user_attributes.department_code — a department code stored
//   during user onboarding via an HR data import; not validated for LDAP special
//   characters at import time.
// Sink: LDAP filter construction — stored LDAP injection via department code.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/so/ldap/employee', async (req, res) => {
  const userId = req.user?.id;
  try {
    const attrResult = await pool.query(
      'SELECT department_code FROM user_attributes WHERE user_id=$1',
      [userId]
    );
    if (!attrResult.rows.length) return res.status(404).json({ error: 'User attributes not found' });
    const { department_code: deptCode } = attrResult.rows[0];
    // VULN-SO039: stored LDAP injection — deptCode from DB used directly in LDAP filter
    const ldapFilter = `(&(department=${deptCode})(objectClass=person))`;
    // stub: ldapClient.search('ou=employees,dc=vaultbank,dc=com', { filter: ldapFilter })
    res.json({ ldapFilter, deptCode, status: 'directory query initiated' });
  } catch (err) {
    res.status(500).json({ error: 'LDAP employee lookup failed', detail: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-SO040
// POST /so/statement/generate
// Taint source: statement_prefs.output_format AND statement_prefs.template_url
//   — both stored when the user configures statement delivery preferences.
// Sink: exec() with both values interpolated without quoting — stored SSRF via
//   template_url (the tool may fetch the URL) combined with command injection
//   via output_format and/or template_url shell metacharacters.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/so/statement/generate', async (req, res) => {
  const { accountId } = req.body;
  try {
    const prefResult = await pool.query(
      'SELECT output_format, template_url FROM statement_prefs WHERE account_id=$1',
      [accountId]
    );
    if (!prefResult.rows.length) return res.status(404).json({ error: 'Statement prefs not found' });
    const { output_format: outputFormat, template_url: templateUrl } = prefResult.rows[0];
    // VULN-SO040: stored SSRF + stored command injection — both values from DB, unquoted in exec
    exec(
      `statement-maker --template ${templateUrl} --format ${outputFormat} --account ${accountId}`,
      (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ generated: true, accountId, outputFormat, output: stdout });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Statement generation failed', detail: err.message });
  }
});

module.exports = router;
