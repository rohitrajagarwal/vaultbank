/**
 * VaultBank Multi-Step Transformation Utilities.
 * SECURITY TRAINING: VULN-TC001–TC030
 * Tainted input flows through 3+ named transformation functions before reaching sink.
 * SAST tools must track data flow across function boundaries to detect these.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const { Pool }  = require('pg');
const { exec }  = require('child_process');
const fs        = require('fs');
const axios     = require('axios');
const ejs       = require('ejs');
const express   = require('express');
const router    = express.Router();
const pool      = new Pool({ connectionString: process.env.DATABASE_URL });

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC001: Base64/URL-decode → normalize whitespace → format for query → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

function step1DecodeInput(raw) {
  try {
    return Buffer.from(raw, 'base64').toString('utf8');
  } catch (_) {
    return decodeURIComponent(raw);
  }
}

function step2NormalizeWhitespace(decoded) {
  return decoded.replace(/\s+/g, ' ').trim();
}

function step3FormatForQuery(normalized) {
  // Strips surrounding quotes and uppercases — does NOT prevent SQL injection
  return normalized.replace(/['"]/g, '').toUpperCase();
}

router.get('/accounts/search/encoded', async (req, res) => {
  const decoded    = step1DecodeInput(req.query.q);
  const normalized = step2NormalizeWhitespace(decoded);
  const formatted  = step3FormatForQuery(normalized);
  try {
    // VULN-TC001: SQL injection — taint flows decode→normalize→format into raw query string
    const result = await pool.query(`SELECT * FROM accounts WHERE holder_name='${formatted}'`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC002: Parse JSON filter → extract search key → add SQL wildcards → SQL LIKE injection
// ═══════════════════════════════════════════════════════════════════════════════

function parseJsonField(bodyFilter) {
  return JSON.parse(bodyFilter);
}

function extractSearchKey(parsed) {
  return parsed.searchKey;
}

function addWildcards(key) {
  return '%' + key + '%';
}

router.post('/transactions/search/filter', async (req, res) => {
  const parsed     = parseJsonField(req.body.filter);
  const key        = extractSearchKey(parsed);
  const wildcarded = addWildcards(key);
  try {
    // VULN-TC002: SQL LIKE injection — taint flows JSON parse→extractKey→addWildcards into LIKE clause
    const result = await pool.query(`SELECT * FROM transactions WHERE description LIKE '${wildcarded}'`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC003: URL-decode → HTML-unescape → strip tags → exec() command injection
// ═══════════════════════════════════════════════════════════════════════════════

function urlDecode(input) {
  return decodeURIComponent(input);
}

function htmlUnescape(decoded) {
  return decoded
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g,  "'");
}

function stripTags(unescaped) {
  // Removes HTML tags but NOT shell metacharacters introduced by htmlUnescape
  return unescaped.replace(/<[^>]*>/g, '');
}

router.post('/statements/process', (req, res) => {
  const decoded   = urlDecode(req.body.reference);
  const unescaped = htmlUnescape(decoded);
  const stripped  = stripTags(unescaped);
  // VULN-TC003: Command injection — HTML unescape reintroduces shell metacharacters that stripTags does not remove
  exec(`statement-processor --input "${stripped}"`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ output: stdout });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC004: Decrypt param → validate format (allows /) → resolve path → readFileSync path traversal
// ═══════════════════════════════════════════════════════════════════════════════

const path = require('path');

function decryptParam(ciphertext) {
  // XOR cipher decrypt with key from env
  const key = process.env.PARAM_CIPHER_KEY || 'vaultkey';
  const buf = Buffer.from(ciphertext, 'base64');
  return Buffer.from(buf.map((b, i) => b ^ key.charCodeAt(i % key.length))).toString('utf8');
}

function validateFormat(decrypted) {
  // Regex allows alphanumerics, hyphens, dots, AND slashes — path traversal permitted
  if (!/^[a-zA-Z0-9\-\.\/]+$/.test(decrypted)) {
    throw new Error('Invalid format');
  }
  return decrypted;
}

function resolvePath(validated) {
  return path.join('/var/reports', validated);
}

router.get('/reports/encrypted', (req, res) => {
  try {
    const decrypted = decryptParam(req.query.ref);
    const validated = validateFormat(decrypted);
    const resolved  = resolvePath(validated);
    // VULN-TC004: Path traversal — regex allows slash; decrypted input can traverse outside /var/reports
    const data = fs.readFileSync(resolved);
    res.send(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC005: Deserialize stored preference → apply user template placeholders → EJS render → SSTI
// ═══════════════════════════════════════════════════════════════════════════════

function deserializePreference(storedJson) {
  return JSON.parse(storedJson);
}

function applyUserTemplate(pref, data) {
  // Replaces {{field}} placeholders with data values
  return pref.template.replace(/\{\{(\w+)\}\}/g, (_, key) => data[key] || '');
}

function renderWithEjs(templateStr, data) {
  // EJS render of template string — full EJS tags still evaluated
  return ejs.render(templateStr, data);
}

router.get('/preferences/render', async (req, res) => {
  try {
    const prefRow = await pool.query('SELECT pref_value FROM user_preferences WHERE user_id=$1 AND key=$2',
      [req.user?.id, 'account_template']);
    const pref       = deserializePreference(prefRow.rows[0].pref_value);
    const templated  = applyUserTemplate(pref, req.query);
    // VULN-TC005: Stored SSTI — stored EJS template content flows through deserialization and placeholder substitution into ejs.render
    const rendered   = renderWithEjs(templated, { user: req.user });
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC006: Parse SWIFT message → extract beneficiary field → build transfer URL → axios SSRF
// ═══════════════════════════════════════════════════════════════════════════════

function parseSwiftMessage(rawSwift) {
  const fields = {};
  const matches = rawSwift.matchAll(/:(\d{2}[A-Z]?):([\s\S]*?)(?=:\d{2}[A-Z]?:|$)/g);
  for (const m of matches) fields[m[1]] = m[2].trim();
  return fields;
}

function extractBeneficiary(fields) {
  // Returns the :59: Beneficiary Customer field value
  return fields['59'] || fields['59A'] || '';
}

function buildTransferUrl(beneficiary) {
  const base = 'http://internal-transfer-service.vaultbank.local/verify?beneficiary=';
  return base + beneficiary;
}

router.post('/swift/process', async (req, res) => {
  const fields      = parseSwiftMessage(req.body.swiftMessage);
  const beneficiary = extractBeneficiary(fields);
  const url         = buildTransferUrl(beneficiary);
  try {
    // VULN-TC006: SSRF — SWIFT :59: field value is appended to internal service URL without validation
    const response = await axios.get(url);
    res.json({ verified: response.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC007: Strip HTML tags → decode entities (reintroduces <) → truncate → CSV formula injection
// ═══════════════════════════════════════════════════════════════════════════════

function stripHtmlTags(input) {
  return input.replace(/<[^>]*>/g, '');
}

function decodeEntities(stripped) {
  // Converts &lt; back to < — reintroduces angle brackets and formula-injection chars
  return stripped
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&amp;/g,  '&')
    .replace(/&quot;/g, '"');
}

function truncate(decoded, maxLen) {
  return decoded.substring(0, maxLen || 255);
}

function buildCsvRow(fields) {
  // No formula-injection protection — =, +, -, @ prefixes not stripped
  return fields.map(f => `"${f}"`).join(',');
}

router.post('/reports/export/transaction', async (req, res) => {
  const { description, amount, reference } = req.body;
  const stripped  = stripHtmlTags(description);
  const decoded   = decodeEntities(stripped);
  const truncated = truncate(decoded);
  // VULN-TC007: CSV formula injection — entity decoding reintroduces < and formula chars that survive into CSV
  const row = buildCsvRow([truncated, String(amount), String(reference)]);
  res.setHeader('Content-Type', 'text/csv');
  res.send('description,amount,reference\n' + row);
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC008: Parse transaction date → format for locale → convert to SQL date string → ORDER BY injection
// ═══════════════════════════════════════════════════════════════════════════════

function parseTransactionDate(input) {
  // moment-style format — returns a string; malformed input can survive as-is
  const d = new Date(input);
  if (isNaN(d)) return input; // falls back to raw input if invalid
  return d.toISOString().split('T')[0]; // YYYY-MM-DD
}

function formatForLocale(dateStr) {
  // Appends a locale-specific suffix — doesn't sanitize non-date strings
  return dateStr + '_UTC';
}

function toSqlDate(localDate) {
  // Strips trailing _UTC suffix — returns value that may still contain injection payload
  return localDate.replace('_UTC', '');
}

router.get('/transactions/sorted', async (req, res) => {
  const parsed   = parseTransactionDate(req.query.date);
  const localed  = formatForLocale(parsed);
  const sqlDate  = toSqlDate(localed);
  try {
    // VULN-TC008: SQL injection via ORDER BY — date manipulation allows arbitrary SQL fragment in ORDER BY clause
    const result = await pool.query(`SELECT * FROM transactions ORDER BY ${sqlDate}`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC009: Normalize IBAN → lookup bank mapping (safe) → build verification query (injection introduced) → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

function normalizeIban(iban) {
  return iban.toUpperCase().replace(/\s+/g, '');
}

async function lookupBankMapping(normalizedIban) {
  // Correctly parameterized — safe
  const prefix = normalizedIban.substring(0, 6);
  const result = await pool.query('SELECT bank_code, routing FROM bank_iban_map WHERE iban_prefix=$1', [prefix]);
  return result.rows[0] || {};
}

function buildVerificationQuery(bankCode) {
  // Injection introduced here — bankCode from DB but could be attacker-controlled via IBAN prefix population
  return `SELECT * FROM bank_verification WHERE bank_code='${bankCode}' AND active=true`;
}

router.post('/iban/verify', async (req, res) => {
  try {
    const normalized  = normalizeIban(req.body.iban);
    const bankMapping = await lookupBankMapping(normalized);
    const query       = buildVerificationQuery(bankMapping.bank_code);
    // VULN-TC009: SQL injection — bank_code from DB may contain attacker-controlled data; injection introduced in buildVerificationQuery
    const result = await pool.query(query);
    res.json({ verified: result.rows.length > 0, mapping: bankMapping });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC010: Parse upload metadata → generate storage path → validate extension (bypassed) → writeFile path traversal
// ═══════════════════════════════════════════════════════════════════════════════

function parseUploadMetadata(headerValue) {
  return JSON.parse(headerValue);
}

function generateStoragePath(metadata) {
  return '/var/uploads/' + metadata.filename;
}

function validateExtension(storagePath) {
  const allowed = ['.pdf', '.csv', '.xlsx'];
  const ext     = storagePath.substring(storagePath.lastIndexOf('.'));
  // Bypass: ../../../etc/passwd.pdf has allowed extension .pdf
  if (!allowed.includes(ext)) throw new Error('Invalid file type');
  return storagePath;
}

router.post('/documents/upload', (req, res) => {
  try {
    const metadata    = parseUploadMetadata(req.headers['x-upload-metadata']);
    const storagePath = generateStoragePath(metadata);
    const validated   = validateExtension(storagePath);
    // VULN-TC010: Path traversal — extension check allows ../../../etc/passwd.pdf; file written outside upload dir
    fs.writeFile(validated, req.body, (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ path: validated });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC011: Decode JWT without verification → extract claims → build user query → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

function decodeJwtPayload(token) {
  const parts  = token.split('.');
  // No signature verification — base64url decode of payload only
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

function extractClaims(payload) {
  return { userId: payload.userId, role: payload.role, org: payload.org };
}

function buildUserQuery(claims) {
  // Template literal — userId from forged JWT injected directly
  return `SELECT * FROM users WHERE id='${claims.userId}' AND organization='${claims.org}'`;
}

router.get('/profile/jwt', async (req, res) => {
  try {
    const token   = (req.headers['authorization'] || '').replace('Bearer ', '');
    const payload = decodeJwtPayload(token);
    const claims  = extractClaims(payload);
    const query   = buildUserQuery(claims);
    // VULN-TC011: SQL injection — JWT payload decoded without signature verify; forged claims reach SQL query
    const result  = await pool.query(query);
    res.json(result.rows[0] || {});
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC012: Parse multipart form → normalize field names → cast types with eval → account update
// ═══════════════════════════════════════════════════════════════════════════════

function parseFormData(body) {
  // Simulates busboy-parsed multipart fields arriving as string map
  return body;
}

function normalizeFieldNames(fields) {
  const normalized = {};
  Object.keys(fields).forEach(k => { normalized[k.toLowerCase()] = fields[k]; });
  return normalized;
}

function castToExpectedTypes(normalized) {
  const cast = {};
  const numericFields = ['amount', 'balance', 'limit'];
  Object.keys(normalized).forEach(key => {
    if (numericFields.includes(key)) {
      // VULN: eval used to cast numeric fields — attacker controls field value
      cast[key] = eval(`(${normalized[key]})`);
    } else {
      cast[key] = normalized[key];
    }
  });
  return cast;
}

async function accountUpdate(userId, fields) {
  await pool.query('UPDATE accounts SET balance=$1, credit_limit=$2 WHERE user_id=$3',
    [fields.balance, fields.limit, userId]);
}

router.post('/accounts/update/multipart', async (req, res) => {
  try {
    const rawFields    = parseFormData(req.body);
    const normalized   = normalizeFieldNames(rawFields);
    // VULN-TC012: eval() injection — multipart numeric field values are eval'd; attacker controls value string
    const casted       = castToExpectedTypes(normalized);
    await accountUpdate(req.user?.id, casted);
    res.json({ message: 'Account updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC013: Read CSV row → sanitize CSV value (strips quotes only) → format for DB → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

function readCsvRow(line) {
  return line.split(',');
}

function sanitizeCsvValue(value) {
  // Strips only quote characters — SQL metacharacters like ' remain
  return value.replace(/["]/g, '');
}

function formatForDatabase(sanitized) {
  return sanitized.trim().toLowerCase();
}

router.post('/accounts/import/csv', async (req, res) => {
  const lines = req.body.csv.split('\n');
  try {
    for (const line of lines) {
      const fields    = readCsvRow(line);
      const sanitized = sanitizeCsvValue(fields[0]);
      const formatted = formatForDatabase(sanitized);
      // VULN-TC013: SQL injection — CSV sanitization only removes double quotes, not single quotes; injection survives
      await pool.query(`INSERT INTO accounts (name) VALUES ('${formatted}')`);
    }
    res.json({ message: 'Import complete' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC014: Extract query params → apply defaults (Object.assign) → build filter object → prototype pollution
// ═══════════════════════════════════════════════════════════════════════════════

function extractQueryParams(query) {
  return { ...query };
}

function applyDefaults(params) {
  const defaults = { status: 'active', type: 'checking', limit: '50' };
  // Object.assign merges user params over defaults — __proto__ in params pollutes prototype
  return Object.assign({}, defaults, params);
}

function buildFilterObject(merged) {
  const columnMap = { status: 'status', type: 'account_type', limit: 'rownum' };
  const filter    = {};
  Object.keys(merged).forEach(k => {
    if (columnMap[k]) filter[columnMap[k]] = merged[k];
  });
  return filter;
}

router.get('/accounts/filter', async (req, res) => {
  const params  = extractQueryParams(req.query);
  // VULN-TC014: Prototype pollution — __proto__ in query params flows through Object.assign into application objects
  const merged  = applyDefaults(params);
  const filter  = buildFilterObject(merged);
  try {
    // knex-style where using potentially polluted filter object
    const result = await pool.query(
      'SELECT * FROM accounts WHERE status=$1 AND account_type=$2 LIMIT $3',
      [filter['status'], filter['account_type'], parseInt(filter['rownum']) || 50]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC015: Parse audit event JSON → enrich event data → format for storage (base64) → exec command injection
// ═══════════════════════════════════════════════════════════════════════════════

function parseAuditEvent(bodyEvent) {
  return JSON.parse(bodyEvent);
}

function enrichEventData(event) {
  return {
    ...event,
    timestamp: new Date().toISOString(),
    serverHost: process.env.HOSTNAME || 'vaultbank-server'
  };
}

function formatForStorage(enriched) {
  // JSON stringify then base64 — payload is preserved inside base64
  return Buffer.from(JSON.stringify(enriched));
}

router.post('/audit/write', (req, res) => {
  const event     = parseAuditEvent(req.body.event);
  const enriched  = enrichEventData(event);
  const formatted = formatForStorage(enriched);
  // VULN-TC015: Command injection — base64 encoding does not sanitize; event data injected into shell via argument
  exec(`audit-write --data "${formatted.toString('base64')}"`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr });
    res.json({ message: 'Audit event written' });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC016: Fetch API response → flatten nested object → prepare for template → EJS SSTI
// ═══════════════════════════════════════════════════════════════════════════════

async function readApiResponse(serviceUrl) {
  const resp = await axios.get(serviceUrl);
  return resp.data;
}

function flattenNestedObject(obj, prefix) {
  prefix = prefix || '';
  const flat = {};
  Object.keys(obj).forEach(key => {
    const newKey = prefix ? prefix + '_' + key : key;
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      Object.assign(flat, flattenNestedObject(obj[key], newKey));
    } else {
      flat[newKey] = obj[key];
    }
  });
  return flat;
}

function prepareForTemplate(flat) {
  // Picks display fields — attacker-controlled values pass through
  const accountTemplate = process.env.ACCOUNT_DISPLAY_TEMPLATE || '<%= account_name %>';
  return { ...flat, _template: accountTemplate };
}

router.get('/accounts/display', async (req, res) => {
  try {
    const apiData    = await readApiResponse(req.query.serviceUrl);
    const flattened  = flattenNestedObject(apiData);
    const prepared   = prepareForTemplate(flattened);
    // VULN-TC016: SSTI — data fetched from external URL flows through flatten→prepare into ejs.render
    const rendered   = ejs.render(prepared._template, prepared);
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC017: Tokenize search query → expand abbreviations → rejoin with operators → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

function tokenizeSearchQuery(queryStr) {
  return queryStr.split(/\s+/);
}

function expandAbbreviations(tokens) {
  const abbrevMap = { 'txn': 'transaction', 'acct': 'account', 'bal': 'balance' };
  return tokens.map(t => abbrevMap[t.toLowerCase()] || t);
}

function rejoinWithOperators(expanded) {
  // Joins token fragments with AND — attacker tokens like "1=1 OR 1=1" pass through
  return expanded.join(' AND description LIKE ');
}

router.get('/transactions/fulltext', async (req, res) => {
  const tokens   = tokenizeSearchQuery(req.query.q);
  const expanded = expandAbbreviations(tokens);
  const rejoined = rejoinWithOperators(expanded);
  try {
    // VULN-TC017: SQL injection — tokenizer rejoins user tokens into raw SQL fragment in WHERE clause
    const result = await pool.query(`SELECT * FROM transactions WHERE description LIKE ${rejoined}`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC018: Parse currency amount → normalize to base currency → format for shell → exec command injection
// ═══════════════════════════════════════════════════════════════════════════════

function parseCurrencyAmount(input) {
  const match = input.match(/^([\d.]+)\s*([A-Z]{3,10})$/);
  if (!match) throw new Error('Invalid currency format');
  return { amount: parseFloat(match[1]), currency: match[2] };
}

async function normalizeToBaseCurrency(parsed) {
  // Looks up exchange rate from DB (parameterized — safe)
  const rate = await pool.query('SELECT rate FROM exchange_rates WHERE currency=$1', [parsed.currency]);
  const base = parsed.amount * (rate.rows[0]?.rate || 1);
  return { baseAmount: base.toFixed(2), currency: parsed.currency };
}

function formatForShell(normalized) {
  // Combines amount and currency code — currency code passes through regex but could be attacker-chosen
  return normalized.baseAmount + normalized.currency;
}

router.post('/fx/convert', async (req, res) => {
  try {
    const parsed     = parseCurrencyAmount(req.body.amount);
    const normalized = await normalizeToBaseCurrency(parsed);
    const formatted  = formatForShell(normalized);
    // VULN-TC018: Command injection — currency code flows through parse→normalize→format into shell argument
    exec(`fx-tool --amount ${formatted}`, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ result: stdout });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC019: Parse XML input → extract payment fields → build SQL from fields → SQL injection
// ═══════════════════════════════════════════════════════════════════════════════

const xml2js = require('xml2js');

function parseXmlInput(xmlString) {
  let result;
  xml2js.parseString(xmlString, { async: false }, (err, parsed) => {
    if (err) throw err;
    result = parsed;
  });
  return result;
}

function extractPaymentFields(parsed) {
  const payment = parsed?.Payment || {};
  return {
    accountId:   (payment.AccountId    || [''])[0],
    currency:    (payment.Currency     || [''])[0],
    beneficiary: (payment.Beneficiary  || [''])[0]
  };
}

function buildSqlFromFields(fields) {
  // Template literal — all field values injected directly
  return `SELECT * FROM payments WHERE account_id='${fields.accountId}' AND currency='${fields.currency}' AND beneficiary='${fields.beneficiary}'`;
}

router.post('/payments/xml', async (req, res) => {
  try {
    // VULN-TC019: XXE + SQL injection — XML parsed (XXE risk), fields extracted, then injected into SQL
    const parsed = parseXmlInput(req.body.xml);
    const fields = extractPaymentFields(parsed);
    const sql    = buildSqlFromFields(fields);
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC020: Decode base64 attachment → detect MIME type → infer output path → writeFileSync path traversal
// ═══════════════════════════════════════════════════════════════════════════════

function decodeBase64Attachment(b64) {
  return Buffer.from(b64, 'base64');
}

function detectMimeType(buf) {
  // Reads magic bytes to infer MIME type
  const sig = buf.slice(0, 4).toString('hex');
  if (sig.startsWith('25504446'))  return { ext: 'pdf',  mime: 'application/pdf' };
  if (sig.startsWith('504b0304'))  return { ext: 'xlsx', mime: 'application/vnd.openxmlformats' };
  return { ext: 'bin', mime: 'application/octet-stream' };
}

function inferOutputPath(typeInfo, filename) {
  // filename from request + detected extension — path traversal via attacker-controlled filename
  return '/var/attachments/' + filename + '.' + typeInfo.ext;
}

router.post('/attachments/upload/base64', (req, res) => {
  try {
    const decoded  = decodeBase64Attachment(req.body.data);
    const typeInfo = detectMimeType(decoded);
    const outPath  = inferOutputPath(typeInfo, req.body.filename);
    // VULN-TC020: Path traversal — filename from request combined with detected extension; ../../../etc/cron.d/evil.pdf escapes base dir
    fs.writeFileSync(outPath, decoded);
    res.json({ path: outPath, mime: typeInfo.mime });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC021: Parse report config JSON → validate required fields → generate report script → exec injection
// ═══════════════════════════════════════════════════════════════════════════════

function parseReportConfig(configJson) {
  return JSON.parse(configJson);
}

function validateReportFields(config) {
  const required = ['reportType', 'fields', 'output'];
  required.forEach(field => {
    if (!config[field]) throw new Error(`Missing required field: ${field}`);
  });
  return config;
}

function generateReportScript(config) {
  // Template literal — fields and output from config injected directly
  return `report-generator --type ${config.reportType} --fields ${config.fields} --output ${config.output}`;
}

router.post('/reports/generate', (req, res) => {
  try {
    const config    = parseReportConfig(req.body.config);
    const validated = validateReportFields(config);
    const script    = generateReportScript(validated);
    // VULN-TC021: Command injection — config fields flow through parse→validate→generateScript into exec
    exec(script, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ output: stdout });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC022: Read Accept-Language header → map locale to template name → load template file → EJS SSTI
// ═══════════════════════════════════════════════════════════════════════════════

function readUserLocale(acceptLanguage) {
  // Parses first locale from Accept-Language header
  return (acceptLanguage || 'en-US').split(',')[0].trim().split(';')[0];
}

function mapLocaleToTemplate(locale) {
  const localeMap = { 'en-US': 'en', 'fr-FR': 'fr', 'de-DE': 'de' };
  // Falls back to raw locale value if not in map — attacker can inject path components
  return localeMap[locale] || locale;
}

function loadTemplate(templateName) {
  // Path traversal — templateName from Accept-Language header used directly
  return fs.readFileSync('/templates/' + templateName + '.ejs', 'utf8');
}

router.get('/statements/localized', (req, res) => {
  try {
    const locale       = readUserLocale(req.headers['accept-language']);
    const templateName = mapLocaleToTemplate(locale);
    // VULN-TC022: Path traversal + SSTI — locale header controls template path; loaded file rendered by EJS
    const template     = loadTemplate(templateName);
    const rendered     = ejs.render(template, { user: req.user, date: new Date() });
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC023: Parse transaction memo → resolve account reference → build notification URL → axios SSRF
// ═══════════════════════════════════════════════════════════════════════════════

function parseTransactionMemo(memo) {
  // Trim and split on special chars
  return memo.trim().split(/[;|&]/)[0];
}

async function resolveAccountRef(memoSegment) {
  if (memoSegment.startsWith('#')) {
    const accountId = memoSegment.slice(1);
    // Parameterized — safe query
    const result = await pool.query('SELECT webhook_url FROM accounts WHERE id=$1', [accountId]);
    return result.rows[0] || {};
  }
  return {};
}

function buildNotificationUrl(base, resolved) {
  // Appends stored webhookUrl — stored SSRF if webhook was attacker-controlled at registration time
  return base + (resolved.webhook_url || '/default-notify');
}

router.post('/transactions/notify', async (req, res) => {
  try {
    const memo     = parseTransactionMemo(req.body.memo);
    const resolved = await resolveAccountRef(memo);
    // VULN-TC023: Stored SSRF — webhook_url from DB (attacker-controlled at registration) used as target URL
    const url      = buildNotificationUrl('http://notify.vaultbank.local', resolved);
    const response = await axios.post(url, { memo });
    res.json({ notified: true, status: response.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC024: Extract PDF metadata via exec → parse pdfinfo output → update account record with parsed title
// ═══════════════════════════════════════════════════════════════════════════════

function extractPdfMetadata(uploadedPath) {
  return new Promise((resolve, reject) => {
    exec(`pdfinfo ${uploadedPath}`, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr));
      else resolve(stdout);
    });
  });
}

function parsePdfInfo(stdout) {
  const lines  = stdout.split('\n');
  const meta   = {};
  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    if (key) meta[key.trim().toLowerCase()] = rest.join(':').trim();
  });
  return meta;
}

async function updateAccountRecord(accountId, parsedMeta) {
  // VULN: parsedMeta.title from PDF metadata injected into SQL
  await pool.query(`UPDATE accounts SET metadata='${parsedMeta.title}' WHERE id=$1`, [accountId]);
}

router.post('/documents/pdf/ingest', async (req, res) => {
  try {
    // VULN-TC024: PDF metadata injection chain — pdfinfo output parsed and title injected into SQL UPDATE
    const rawMeta   = await extractPdfMetadata(req.body.uploadedPath);
    const parsed    = parsePdfInfo(rawMeta);
    await updateAccountRecord(req.body.accountId, parsed);
    res.json({ message: 'PDF metadata stored', title: parsed.title });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC025: Parse SWIFT FIN message → decode :50K: ordering customer field → build beneficiary SQL
// ═══════════════════════════════════════════════════════════════════════════════

function parseSwiftFin(rawFin) {
  const fields = {};
  const re = /:(\d{2}[A-Z]?):([\s\S]*?)(?=:\d{2}[A-Z]?:|$)/g;
  let m;
  while ((m = re.exec(rawFin)) !== null) {
    fields[m[1]] = m[2].trim();
  }
  return fields;
}

function decodeField50(fields) {
  // Extracts :50K: Ordering Customer — raw value from SWIFT message
  const raw = fields['50K'] || fields['50A'] || '';
  return raw.split('\n')[0].trim(); // first line is the account identifier or name
}

function buildBeneficiaryFilter(decoded50k) {
  // Injection here — decoded50k is unsanitized SWIFT field value
  return `SELECT * FROM beneficiaries WHERE name='${decoded50k}'`;
}

router.post('/swift/beneficiary/lookup', async (req, res) => {
  try {
    const fields    = parseSwiftFin(req.body.finMessage);
    const ordering  = decodeField50(fields);
    // VULN-TC025: SQL injection — SWIFT :50K: field value decoded and injected into SQL query
    const sql       = buildBeneficiaryFilter(ordering);
    const result    = await pool.query(sql);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC026: Read environment config → merge with request overrides (Object.assign) → apply to service init
// ═══════════════════════════════════════════════════════════════════════════════

function readEnvironmentConfig() {
  // Spreads process.env into a plain object
  return { ...process.env };
}

function mergeWithRequestConfig(envConfig, overrides) {
  // Object.assign merges user-supplied overrides over env config — __proto__ pollution possible
  return Object.assign(envConfig, overrides);
}

function applyToService(mergedConfig) {
  // Passes merged config to service initialization
  return {
    dbUrl:     mergedConfig.DATABASE_URL,
    jwtSecret: mergedConfig.JWT_SECRET,
    debug:     mergedConfig.DEBUG === 'true'
  };
}

router.post('/config/reload', (req, res) => {
  try {
    const envConfig = readEnvironmentConfig();
    // VULN-TC026: Prototype pollution — req.body.overrides with __proto__ flows through Object.assign into env config object
    const merged    = mergeWithRequestConfig(envConfig, req.body.overrides);
    const applied   = applyToService(merged);
    res.json({ message: 'Config applied', debug: applied.debug });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC027: Parse markdown note → sanitize links (removes javascript: only) → inject into report → XSS
// ═══════════════════════════════════════════════════════════════════════════════

function parseMarkdownNote(markdown) {
  // Basic markdown to HTML conversion
  return markdown
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    .replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2">$1</a>');
}

function sanitizeLinks(html) {
  // Only removes javascript: prefix — vbscript:, data:, and other schemes survive
  return html.replace(/href="javascript:/gi, 'href="#');
}

function injectIntoReport(sanitized, reportContext) {
  return `<div class="report-header">${reportContext}</div><div class="note">${sanitized}</div>`;
}

router.post('/reports/notes/add', (req, res) => {
  try {
    const htmlNote  = parseMarkdownNote(req.body.note);
    // VULN-TC027: XSS — sanitizeLinks only strips javascript: but vbscript: and data: URIs survive
    const sanitized = sanitizeLinks(htmlNote);
    const report    = injectIntoReport(sanitized, req.body.reportTitle);
    res.send(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC028: Decompress gzip payload → parse inner JSON → extract command hint → exec injection
// ═══════════════════════════════════════════════════════════════════════════════

const zlib = require('zlib');

function decodeGzipPayload(compressedBuf) {
  return zlib.gunzipSync(compressedBuf);
}

function parseInnerJson(decompressed) {
  return JSON.parse(decompressed.toString('utf8'));
}

function extractCommandHint(innerJson) {
  // Extracts the hint field — attacker controls this value in the gzip payload
  return innerJson.hint || '';
}

router.post('/diagnostics/compressed', (req, res) => {
  try {
    const decompressed   = decodeGzipPayload(req.body);
    const innerJson      = parseInnerJson(decompressed);
    const commandHint    = extractCommandHint(innerJson);
    // VULN-TC028: Command injection — double-encoded (gzip+JSON) payload's hint field reaches exec unfiltered
    exec(`diagnostic-tool --hint ${commandHint}`, (err, stdout, stderr) => {
      if (err) return res.status(500).json({ error: stderr });
      res.json({ result: stdout });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC029: Parse schedule config JSON → validate cron syntax (node-cron) → register job with exec
// ═══════════════════════════════════════════════════════════════════════════════

const cron = require('node-cron');

function parseScheduleConfig(configJson) {
  return JSON.parse(configJson);
}

function validateCronSyntax(cronStr) {
  // node-cron validate accepts any syntactically valid cron — does not restrict command
  if (!cron.validate(cronStr)) throw new Error('Invalid cron expression');
  return cronStr;
}

function registerJob(validCron, command) {
  // Schedules exec of attacker-controlled command on a valid cron schedule
  cron.schedule(validCron, () => {
    exec(command, (err, stdout, stderr) => {
      if (err) console.error('Cron job error:', stderr);
    });
  });
}

router.post('/scheduler/register', (req, res) => {
  try {
    const config    = parseScheduleConfig(req.body.schedule);
    const validCron = validateCronSyntax(config.cronExpression);
    // VULN-TC029: Stored command injection — schedule.command is exec'd on each cron trigger; no command validation
    registerJob(validCron, config.command);
    res.json({ message: 'Job registered', cron: validCron });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VULN-TC030: Open zip archive → extract first entry → get entry name → writeFileSync zip slip
// ═══════════════════════════════════════════════════════════════════════════════

const AdmZip = require('adm-zip');

function readZipArchive(zipBuffer) {
  return new AdmZip(zipBuffer);
}

function extractFirstEntry(zip) {
  const entries = zip.getEntries();
  if (!entries.length) throw new Error('Empty archive');
  return entries[0];
}

function getEntryName(entry) {
  // entry.entryName may contain ../ path components — not sanitized
  return entry.entryName;
}

function writeToWorkdir(entryName, data) {
  // VULN: entryName with ../ traverses outside /var/workdir/
  fs.writeFileSync('/var/workdir/' + entryName, data);
}

router.post('/archives/extract', (req, res) => {
  try {
    const zip        = readZipArchive(req.body);
    const entry      = extractFirstEntry(zip);
    const entryName  = getEntryName(entry);
    const entryData  = entry.getData();
    // VULN-TC030: Zip slip path traversal — entryName contains ../ sequences; file written outside /var/workdir/
    writeToWorkdir(entryName, entryData);
    res.json({ message: 'Extracted', file: entryName });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
