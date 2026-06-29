/**
 * VaultBank SAST Target Routes
 * SECURITY TRAINING: Dense vulnerability patterns for CodeQL/Semgrep/njsscan detection.
 * Every handler has a DIRECT taint flow: req.body/query/params -> dangerous sink.
 */
'use strict';

const express = require('express');
const router = express.Router();
const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const axios = require('axios');
const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ─── SQL INJECTION (CodeQL CWE-089, njsscan node_sqli) ───────────────────────

// VULN-T01: string concatenation SQL — pool.query detectable by Semgrep/njsscan
router.get('/accounts/search', async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM accounts WHERE account_number='" + req.query.account_number + "'"
  );
  res.json(result.rows);
});

// VULN-T02: template literal SQL — CodeQL taint: req.query.email -> pool.query
router.get('/users/find', async (req, res) => {
  const result = await pool.query(`SELECT * FROM users WHERE email='${req.query.email}'`);
  res.json(result.rows);
});

// VULN-T03: multi-param injection
router.post('/transactions/search', async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM transactions WHERE amount > ${req.body.min_amount} AND status='${req.body.status}'`
  );
  res.json(result.rows);
});

// VULN-T04: loans search with ORDER BY injection
router.get('/loans/search', async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM loans WHERE customer_id=${req.query.customer_id} ORDER BY ${req.query.sort}`
  );
  res.json(result.rows);
});

// VULN-T05: routing number lookup
router.get('/accounts/by-routing', async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM accounts WHERE routing_number='" + req.query.routing + "' AND bank_code='" + req.query.bank + "'"
  );
  res.json(result.rows);
});

// VULN-T06: payment history
router.post('/payments/history', async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM payments WHERE payer_id=${req.body.payer_id} AND merchant='${req.body.merchant}'`
  );
  res.json(result.rows);
});

// VULN-T07: SSN lookup
router.get('/users/by-ssn', async (req, res) => {
  const result = await pool.query(`SELECT id,name FROM users WHERE ssn='${req.query.ssn}'`);
  res.json(result.rows);
});

// VULN-T08: audit log search with LIKE injection
router.get('/audit/search', async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM audit_log WHERE action LIKE '%" + req.query.action + "%'"
  );
  res.json(result.rows);
});

// ─── COMMAND INJECTION (CodeQL CWE-078, njsscan node_childprocess_exec) ──────

// VULN-T09: exec with user input — most detectable pattern
router.get('/network/ping', (req, res) => {
  exec('ping -c 3 ' + req.query.host, (err, stdout) => res.send(stdout));
});

// VULN-T10: execSync
router.post('/reports/generate', (req, res) => {
  const out = execSync('pdfgen --template ' + req.body.template + ' --output /tmp/report.pdf');
  res.send(out);
});

// VULN-T11: template literal exec
router.get('/network/traceroute', (req, res) => {
  exec(`traceroute ${req.query.target}`, (err, stdout) => res.send(stdout));
});

// VULN-T12: spawn with shell:true
router.post('/files/convert', (req, res) => {
  const proc = spawn('sh', ['-c', `convert ${req.body.input_file} ${req.body.output_file}`], { shell: true });
  proc.stdout.pipe(res);
});

// VULN-T13: exec with path param
router.get('/system/disk', (req, res) => {
  exec(`df -h ${req.query.path}`, (err, stdout) => res.send(stdout));
});

// VULN-T14: execSync archive creation
router.post('/backup/create', (req, res) => {
  const result = execSync(`tar czf /tmp/backup.tar.gz ${req.body.dir}`);
  res.json({ output: result.toString() });
});

// ─── PATH TRAVERSAL (CodeQL CWE-022) ─────────────────────────────────────────

// VULN-T15: readFileSync with user input — direct string concat
router.get('/files/read', (req, res) => {
  const content = fs.readFileSync('/var/vaultbank/files/' + req.query.filename);
  res.send(content);
});

// VULN-T16: sendFile with path.join (CodeQL tracks path.join as traversal-prone)
router.get('/statements/download', (req, res) => {
  res.sendFile(path.join('/var/vaultbank/statements/', req.query.file));
});

// VULN-T17: template loading
router.get('/templates/load', (req, res) => {
  const tmpl = fs.readFileSync('/var/vaultbank/templates/' + req.params.name, 'utf8');
  res.send(tmpl);
});

// VULN-T18: config file read
router.post('/config/read', (req, res) => {
  const data = JSON.parse(fs.readFileSync('/etc/vaultbank/' + req.body.config_name, 'utf8'));
  res.json(data);
});

// VULN-T19: log file tail via exec (double sink: path traversal + command injection)
router.get('/logs/tail', (req, res) => {
  exec('tail -100 /var/log/vaultbank/' + req.query.logfile, (err, out) => res.send(out));
});

// ─── CODE INJECTION (CodeQL CWE-094, njsscan node_eval) ──────────────────────

// VULN-T20: eval with query param
router.get('/calc', (req, res) => {
  const result = eval(req.query.expression); // njsscan node_eval
  res.json({ result });
});

// VULN-T21: eval with body
router.post('/script/run', (req, res) => {
  eval(req.body.script); // njsscan node_eval
  res.json({ status: 'executed' });
});

// VULN-T22: new Function constructor
router.get('/function/invoke', (req, res) => {
  const fn = new Function('req', 'res', req.query.code); // CodeQL CWE-094
  fn(req, res);
});

// VULN-T23: Function with formula
router.post('/formula', (req, res) => {
  const fn = new Function('return ' + req.body.formula); // CodeQL CWE-094
  res.json({ result: fn() });
});

// ─── XSS — REFLECTED (CodeQL CWE-079, Semgrep) ───────────────────────────────

// VULN-T24: res.send with HTML and user param
router.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// VULN-T25: template literal in res.send
router.get('/search-results', (req, res) => {
  res.send(`<html><body><h2>Results for: ${req.query.q}</h2></body></html>`);
});

// VULN-T26: error page
router.get('/error', (req, res) => {
  res.status(400).send('<p>Error: ' + req.query.message + '</p>');
});

// VULN-T27: profile page with multiple params
router.get('/profile', (req, res) => {
  res.send(`<div class="profile"><h1>${req.query.username}</h1><p>${req.query.bio}</p></div>`);
});

// VULN-T28: res.write with user input
router.post('/comment/render', (req, res) => {
  res.write(`<div class="comment">${req.body.comment}</div>`);
  res.end();
});

// ─── SSRF (CodeQL CWE-918, Semgrep) ──────────────────────────────────────────

// VULN-T29: axios.get with user URL
router.post('/webhook/test', async (req, res) => {
  const response = await axios.get(req.body.webhook_url);
  res.json(response.data);
});

// VULN-T30: proxy endpoint
router.get('/proxy', async (req, res) => {
  const response = await axios.get(req.query.url);
  res.send(response.data);
});

// VULN-T31: insurance verification SSRF
router.post('/verify/insurance', async (req, res) => {
  const r = await axios.post(req.body.insurer_endpoint, { policy: req.body.policy_id });
  res.json(r.data);
});

// VULN-T32: http.get with user URL (different module — both CodeQL sources)
router.get('/fetch/icon', (req, res) => {
  http.get(req.query.icon_url, (r) => { r.pipe(res); });
});

// VULN-T33: host header SSRF
router.post('/swift/verify', async (req, res) => {
  const r = await axios.post('http://' + req.body.swift_host + '/verify', { bic: req.body.bic });
  res.json(r.data);
});

// ─── OPEN REDIRECT (CodeQL CWE-601) ──────────────────────────────────────────

// VULN-T34: res.redirect with query param
router.get('/auth/callback', (req, res) => {
  res.redirect(req.query.next);
});

// VULN-T35: redirect with body param
router.post('/logout', (req, res) => {
  res.redirect(req.body.redirect_to || '/');
});

// VULN-T36: OAuth return
router.get('/oauth/return', (req, res) => {
  res.redirect(req.query.return_url);
});

// VULN-T37: 302 redirect
router.get('/login/success', (req, res) => {
  res.redirect(302, req.query.goto);
});

// ─── REGEX INJECTION (CodeQL CWE-730) ────────────────────────────────────────

// VULN-T38: new RegExp with user pattern
router.get('/search/regex', (req, res) => {
  const match = 'transaction data here'.match(new RegExp(req.query.pattern));
  res.json({ match });
});

// VULN-T39: filter with user regex
router.post('/filter', (req, res) => {
  const regex = new RegExp(req.body.filter);
  const results = ['tx1', 'tx2', 'tx3'].filter(t => regex.test(t));
  res.json({ results });
});

// VULN-T40: validation with user rule
router.get('/validate', (req, res) => {
  const valid = new RegExp(req.query.rule).test(req.query.value);
  res.json({ valid });
});

// ─── PROTOTYPE POLLUTION (Semgrep p/nodejs) ───────────────────────────────────

// VULN-T41: Object.assign with req.body
router.post('/config/merge', (req, res) => {
  const config = {};
  Object.assign(config, req.body); // __proto__ writable
  res.json(config);
});

// VULN-T42: for...in without hasOwnProperty
router.post('/prefs/update', (req, res) => {
  const prefs = {};
  for (const key in req.body) {
    prefs[key] = req.body[key]; // Semgrep prototype-pollution
  }
  res.json(prefs);
});

// VULN-T43: lodash merge
router.post('/settings/merge', (req, res) => {
  const _ = require('lodash');
  const merged = _.merge({}, req.body); // Semgrep p/nodejs
  res.json(merged);
});

// ─── LDAP INJECTION ──────────────────────────────────────────────────────────

// VULN-T44: LDAP search filter with user input
router.get('/ldap/user', (req, res) => {
  const ldap = require('ldapjs');
  const client = ldap.createClient({ url: 'ldap://ad.vaultbank.internal' });
  client.search('ou=staff,dc=vaultbank,dc=internal', {
    filter: '(sAMAccountName=' + req.query.username + ')'
  }, (err, result) => res.json({ result: result ? 'found' : 'not found' }));
});

// VULN-T45: LDAP group search
router.post('/ldap/group', (req, res) => {
  const ldap = require('ldapjs');
  const client = ldap.createClient({ url: 'ldap://ad.vaultbank.internal' });
  client.search('ou=groups,dc=vaultbank,dc=internal', {
    filter: '(&(objectClass=group)(cn=' + req.body.group + '))'
  }, (err, result) => res.json({ result: result ? 'found' : 'not found' }));
});

// ─── TEMPLATE INJECTION (njsscan) ────────────────────────────────────────────

// VULN-T46: ejs.render with user template string
router.get('/render/ejs', (req, res) => {
  const ejs = require('ejs');
  res.send(ejs.render(req.query.template, { user: req.user || {} }));
});

// VULN-T47: ejs.render with body template
router.post('/email/preview', (req, res) => {
  const ejs = require('ejs');
  res.send(ejs.render(req.body.email_template, req.body.vars || {}));
});

// ─── DESERIALIZATION (njsscan) ────────────────────────────────────────────────

// VULN-T48: node-serialize unserialize
router.post('/session/restore', (req, res) => {
  const serialize = require('node-serialize');
  const obj = serialize.unserialize(req.body.session_data); // njsscan
  res.json({ restored: !!obj });
});

// VULN-T49: base64 decode then unserialize
router.get('/cache/load', (req, res) => {
  const serialize = require('node-serialize');
  const decoded = Buffer.from(req.query.cache, 'base64').toString();
  const obj = serialize.unserialize(decoded); // njsscan
  res.json({ loaded: !!obj });
});

// ─── CLEARTEXT SENSITIVE DATA (CodeQL CWE-312) ───────────────────────────────

// VULN-T50: password logged to console
router.post('/auth/log', (req, res) => {
  console.log('Login attempt - email: ' + req.body.email + ' password: ' + req.body.password);
  res.json({ logged: true });
});

// VULN-T51: full request body logged
router.get('/debug/request', (req, res) => {
  console.log('Full req.body:', JSON.stringify(req.body));
  console.log('Authorization header:', req.headers.authorization);
  res.json({ status: 'logged' });
});

// ─── INSECURE CRYPTO (njsscan insecure_hash) ──────────────────────────────────

// VULN-T52: MD5 password hash
router.post('/password/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex'); // njsscan
  res.json({ hash });
});

// VULN-T53: Math.random for token
router.get('/token/generate', (req, res) => {
  const token = Math.random().toString(36).substring(2); // Semgrep
  res.json({ token });
});

// VULN-T54: SHA1 PIN hash
router.post('/pin/hash', (req, res) => {
  const pin_hash = crypto.createHash('sha1').update(req.body.pin).digest('hex'); // njsscan
  res.json({ pin_hash });
});

// ─── HEADER INJECTION ────────────────────────────────────────────────────────

// VULN-T55: user-controlled Location header
router.get('/redirect/custom', (req, res) => {
  res.setHeader('Location', req.query.location);
  res.status(302).send();
});

// VULN-T56: CORS header reflects origin
router.get('/cors/dynamic', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ ok: true });
});

// ─── NOSQL INJECTION (Semgrep) ────────────────────────────────────────────────

// VULN-T57: MongoDB $where injection
router.get('/mongo/find', async (req, res) => {
  const MongoClient = require('mongodb').MongoClient;
  const client = new MongoClient(process.env.MONGO_URL);
  const db = client.db('vaultbank');
  const result = await db.collection('transactions').find({
    $where: 'this.amount > ' + req.query.min_amount // NoSQL injection
  }).toArray();
  res.json(result);
});

// VULN-T58: MongoDB filter injection
router.post('/mongo/user', async (req, res) => {
  const MongoClient = require('mongodb').MongoClient;
  const client = new MongoClient(process.env.MONGO_URL);
  const db = client.db('vaultbank');
  const result = await db.collection('users').find({
    username: req.body.username,
    $where: req.body.filter // direct injection
  }).toArray();
  res.json(result);
});

// ─── JWT VULNERABILITIES ──────────────────────────────────────────────────────

// VULN-T59: JWT verify accepting 'none' algorithm
router.get('/token/verify', (req, res) => {
  const token = req.headers.authorization || '';
  const payload = jwt.verify(token.replace('Bearer ', ''), 'vaultbank_secret', {
    algorithms: ['HS256', 'none'] // accepts alg:none
  });
  res.json(payload);
});

// VULN-T60: JWT decode without verification
router.post('/token/decode', (req, res) => {
  const decoded = jwt.decode(req.body.token, { complete: true }); // no verify
  res.json(decoded ? decoded.payload : {});
});

module.exports = router;
