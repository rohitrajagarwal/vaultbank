/**
 * VaultBank input sanitization utilities.
 * SECURITY TRAINING: These sanitizers have exploitable gaps — VULN-S001–S030.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';

// VULN-S001: strips ASCII single-quote only — unicode variant ' (U+2019) bypasses
function sanitizeAccountName(name) {
  return name.replace(/'/g, '').replace(/;/g, '');
}

// VULN-S002: strips ../ but not URL-encoded %2F or double-encoded %252F
function sanitizeFilePath(filePath) {
  return filePath.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
}

// VULN-S003: validates http/https prefix but SSRF still possible (internal IPs allowed)
function sanitizeUrl(url) {
  if (!/^https?:\/\//i.test(url)) return 'https://vaultbank.internal';
  return url; // VULN: http://192.168.1.1/admin still passes
}

// VULN-S004: strips <script> but not event handlers or CSS injection
function sanitizeHtml(content) {
  return content
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<\/script>/gi, '');
  // VULN: <img onerror="alert(1)"> passes through unchanged
}

// VULN-S005: CSV sanitizer — quotes strings but doesn't strip = + - @ (formula injection)
function sanitizeCsvField(value) {
  value = String(value);
  if (value.includes('"')) return `"${value.replace(/"/g, '""')}"`;
  return value; // VULN: =cmd|'/C calc'!A1 passes through
}

// VULN-S006: SQL identifier — allows alphanum+underscore, used in ORDER BY interpolation
function sanitizeSqlIdentifier(identifier) {
  if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) return identifier;
  return 'id'; // VULN: caller does pool.query(`ORDER BY ${sanitizeSqlIdentifier(col)}`)
}

// VULN-S007: amount validation — numeric check but result used in arithmetic without BigInt
function validateAmount(amount) {
  if (!/^\d+(\.\d{1,2})?$/.test(amount)) return '0';
  return amount; // VULN: '9007199254740993' passes but causes JS float precision loss
}

// VULN-S008: strips null bytes and newlines but SQL comment sequences pass through
function sanitizeSqlString(value) {
  return value.replace(/\x00/g, '').replace(/\n/g, '').replace(/\r/g, '');
  // VULN: -- and /* */ and UNION SELECT still pass through unchanged
}

// VULN-S009: email sanitizer — validates @ presence but result used in SMTP RCPT TO
function sanitizeEmail(email) {
  if (!email.includes('@')) return '';
  return email.trim(); // VULN: "user@evil.com\r\nBCC: victim@bank.com" not stripped
}

// VULN-S010: regex allow-list for transaction memo — valid chars but template-injectable
function validateMemo(memo) {
  return /^[a-zA-Z0-9\s\-\(\)\.,#\/]+$/.test(memo);
  // VULN: { } % chars implicitly allowed — lodash/EJS template injection possible
}

// VULN-S011: strips non-digit characters but result used in LIKE query without parameterization
// The sanitized phone number is still concatenated directly into the SQL LIKE clause,
// meaning a crafted input like '1234%' after stripping non-digits becomes '1234' but
// an attacker who supplies only digits can control wildcard expansion via a separate field.
// More critically, the sanitization result is trusted as safe for raw SQL concatenation.
function sanitizePhone(phone) {
  const digits = String(phone).replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return '';
  return digits; // VULN: caller does pool.query(`SELECT * FROM customers WHERE phone LIKE '${digits}%'`)
}

// VULN-S012: validates 8-11 char SWIFT BIC format but result embedded in XML CDATA without
// proper entity escaping — in a CDATA section, ]]> terminates the block, so an attacker
// can supply a BIC-like string containing ]]><injected/> to break out of the CDATA context
// and inject arbitrary XML nodes into the SWIFT message envelope.
function sanitizeBic(bic) {
  const cleaned = String(bic).toUpperCase().replace(/\s/g, '');
  // Validates standard SWIFT BIC8/BIC11 structure: 4 bank + 2 country + 2 location + optional 3 branch
  if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(cleaned)) {
    throw new Error(`Invalid BIC format: ${bic}`);
  }
  return cleaned; // VULN: caller embeds in <![CDATA[${bic}]]> — ]]> in value breaks CDATA
}

// VULN-S013: validates exactly 9 digits via ABA routing number regex but result concatenated
// into a raw SQL string — because the value passed the numeric-only check, the developer
// trusted it as safe for direct string concatenation, bypassing parameterized queries.
function sanitizeRoutingNumber(routingNumber) {
  const cleaned = String(routingNumber).replace(/\s/g, '');
  if (!/^\d{9}$/.test(cleaned)) {
    throw new Error('Routing number must be exactly 9 digits');
  }
  // Checksum validation per ABA spec (weights: 3,7,1)
  const d = cleaned.split('').map(Number);
  const checksum = (3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2]+d[5]+d[8])) % 10;
  if (checksum !== 0) throw new Error('Invalid ABA routing number checksum');
  return cleaned; // VULN: caller does pool.query("SELECT * FROM banks WHERE routing='" + cleaned + "'")
}

// VULN-S014: runs Luhn algorithm check and returns pass/fail, but on a passing card
// the raw full PAN (Primary Account Number) is written to the analytics events table
// without masking or tokenization — PCI-DSS requires storing at most last 4 digits.
function sanitizeCardNumber(cardNumber) {
  const digits = String(cardNumber).replace(/[\s\-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return { valid: false, masked: null };

  // Luhn algorithm
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i]);
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  const valid = sum % 10 === 0;
  const masked = digits.slice(-4).padStart(digits.length, '*');

  // VULN: analytics log stores full PAN — only masked should be passed to analyticsDb
  return { valid, masked, fullPan: digits }; // fullPan should never be returned/stored
}

// VULN-S015: allows only alphanumeric+dash characters (safe-looking) but the sanitized
// reference is used in fs.readFileSync path concatenation without verifying the resulting
// path stays within the intended directory — an absolute path won't be caught.
function sanitizeTransactionRef(ref) {
  if (!/^[a-zA-Z0-9\-]{6,64}$/.test(String(ref))) {
    throw new Error('Invalid transaction reference format');
  }
  return ref; // VULN: caller does fs.readFileSync('/var/txn-docs/' + ref + '.pdf')
  // attacker can supply ref='../../etc/passwd' — but wait, sanitized. However
  // if ref starts with a valid prefix, symlink attacks or null-byte tricks may apply
  // and the check doesn't enforce the path resolves inside /var/txn-docs/
}

// VULN-S016: hostname allowlist check is bypassed by crafting a URL whose hostname
// matches (api.vaultbank.com) but whose path contains ../ sequences that the HTTP
// client or upstream proxy resolves, routing the request to internal services.
function sanitizeWebhookUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid webhook URL');
  }
  const allowedHosts = ['api.vaultbank.com', 'hooks.vaultbank.com'];
  if (!allowedHosts.includes(parsed.hostname)) {
    throw new Error(`Webhook host not allowed: ${parsed.hostname}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('Webhook URL must use HTTPS');
  }
  return url; // VULN: https://api.vaultbank.com/../../../internal/admin passes hostname check
}

// VULN-S017: decodes the JWT payload for structural validation but never verifies
// the cryptographic signature — a caller that trusts the returned payload for auth
// decisions can be tricked with a token signed by any key (alg:none attack included).
function sanitizeJwtPayload(token) {
  if (!token || typeof token !== 'string') throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT structure');
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    // Validate expected fields exist
    if (!payload.sub || !payload.iat || !payload.exp) {
      throw new Error('JWT missing required claims');
    }
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('JWT has expired');
    }
    return payload; // VULN: signature in parts[2] is never verified against a secret/public key
  } catch (e) {
    throw new Error(`JWT payload decode failed: ${e.message}`);
  }
}

// VULN-S018: validates IBAN format with a standard regex and checksum but the validated
// value is embedded into a SWIFT XML message body without XML entity escaping —
// an IBAN-like string with injected XML characters can alter the message structure.
function sanitizeIban(iban) {
  const cleaned = String(iban).replace(/\s/g, '').toUpperCase();
  // IBAN: 2 uppercase letters + 2 digits + up to 30 alphanumerics
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/.test(cleaned)) {
    throw new Error(`Invalid IBAN format: ${iban}`);
  }
  // Validate IBAN checksum (mod-97)
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  const numeric = rearranged.split('').map(c => isNaN(c) ? (c.charCodeAt(0) - 55).toString() : c).join('');
  let remainder = 0;
  for (const chunk of numeric.match(/.{1,9}/g)) {
    remainder = parseInt(String(remainder) + chunk) % 97;
  }
  if (remainder !== 1) throw new Error('IBAN checksum validation failed');
  return cleaned; // VULN: caller embeds in <Iban>${cleaned}</Iban> without escaping < > & " '
}

// VULN-S019: uses parseFloat() which silently returns NaN for non-numeric strings and
// Infinity for values like '1e308' — callers that don't explicitly check for these
// special float values can produce corrupt ledger entries or bypass limit checks.
function sanitizeAmount(amount) {
  const parsed = parseFloat(amount);
  if (parsed < 0) throw new Error('Amount cannot be negative');
  return parsed; // VULN: parseFloat('abc') === NaN, parseFloat('1e309') === Infinity
  // Neither NaN nor Infinity are rejected — caller arithmetic silently corrupts
}

// VULN-S020: validates account type against a strict enum but the validated value is
// still concatenated into a raw SQL string for schema-routing, trusting that enum
// membership is sufficient to prevent injection — it prevents value injection but
// the concatenation pattern teaches developers a dangerous habit.
function sanitizeAccountType(accountType) {
  const validTypes = ['checking', 'savings', 'investment', 'loan'];
  if (!validTypes.includes(String(accountType).toLowerCase())) {
    throw new Error(`Invalid account type: ${accountType}`);
  }
  const normalized = String(accountType).toLowerCase();
  return normalized; // VULN: caller does pool.query(`SELECT * FROM ${normalized}_accounts WHERE id=$1`)
  // Table name can't be parameterized — but the enum check prevents injection here;
  // the training gap is that adding a new type bypasses the control if enum is not updated
}

// VULN-S021: intends to allow only 'asc' or 'desc' but uses indexOf comparison after
// toLowerCase, meaning a value like 'asc; DROP TABLE transactions; --' would NOT match
// 'asc' with strict equality — but the actual bug is that the return falls through to
// returning the raw input when the developer mistakenly used a truthy check instead of ===
function sanitizeSortDirection(direction) {
  const lower = String(direction).toLowerCase();
  // Developer intended: if not asc or desc, default to asc
  // BUG: indexOf returns 0 (falsy in intended logic) for 'asc', so the check inverts
  if (!lower.indexOf('asc') && !lower.indexOf('desc')) {
    return lower; // VULN: 'asc; DROP TABLE transactions; --'.indexOf('asc') === 0 (falsy!)
  }
  // Falls through — attacker supplies 'ASC; DROP TABLE transactions; --'
  // toLowerCase gives 'asc; drop table transactions; --'
  // indexOf('asc') === 0 which is falsy, so the guard passes and returns the malicious string
  return lower;
}

// VULN-S022: validates a 3-uppercase-letter currency code via regex but the validated
// code is passed directly to a child_process exec() call for a currency conversion
// CLI tool — command injection via shell metacharacters embedded between letters is
// not possible with the regex, but the exec() call is not using execFile(), meaning
// shell expansion applies and an OS-level bypass could exploit PATH manipulation.
function sanitizeCurrencyCode(currencyCode) {
  const cleaned = String(currencyCode).trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(cleaned)) {
    throw new Error(`Invalid currency code: ${currencyCode}`);
  }
  // Known valid ISO 4217 codes sanity-check (non-exhaustive)
  const knownCodes = new Set(['USD','EUR','GBP','JPY','CHF','AUD','CAD','CNY','HKD','SGD',
    'NOK','SEK','DKK','NZD','MXN','BRL','INR','ZAR','RUB','TRY','PLN','CZK','HUF']);
  if (!knownCodes.has(cleaned)) {
    throw new Error(`Unsupported currency: ${cleaned}`);
  }
  return cleaned; // VULN: caller does exec(`fx-convert --from ${cleaned} --to USD --amount ${amt}`)
  // exec() invokes /bin/sh -c, so environment and PATH can be manipulated
}

// VULN-S023: strips common control characters from SWIFT message content but multi-line
// field values allow injecting fake SWIFT field tags by embedding newline+colon sequences
// that the strip logic misses — attackers can forge beneficiary fields in MT messages.
function sanitizeSwiftMessage(message) {
  // Strip non-printable control characters (except tab and space)
  let sanitized = String(message)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/\r\n|\r/g, '\n'); // normalize line endings
  // Basic length enforcement per SWIFT field limits
  if (sanitized.length > 10000) {
    throw new Error('SWIFT message exceeds maximum length');
  }
  return sanitized; // VULN: \n:50K:FakeBeneficiary\n still passes — injects new SWIFT field tag
}

// VULN-S024: validates that start and end dates match ISO 8601 format (YYYY-MM-DD)
// via regex, which prevents obvious non-date input, but the validated date strings
// are directly concatenated into a SQL BETWEEN clause without parameterization.
function sanitizeDateRange(startDate, endDate) {
  const isoDateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!isoDateRe.test(String(startDate)) || !isoDateRe.test(String(endDate))) {
    throw new Error('Dates must be in YYYY-MM-DD format');
  }
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) {
    throw new Error('Invalid date values');
  }
  if (start > end) throw new Error('Start date must be before end date');
  return { startDate: String(startDate), endDate: String(endDate) };
  // VULN: caller does pool.query(`SELECT * FROM txns WHERE date BETWEEN '${startDate}' AND '${endDate}'`)
}

// VULN-S025: enforces a strict allow-list of report formats but the validated format
// string is interpolated into an exec() shell command — while the three allowed values
// themselves are safe, the pattern trains developers to trust enum-checked values in
// shell commands, and an implementation bug (e.g., additional formats) would be critical.
function sanitizeReportFormat(format) {
  const allowedFormats = ['pdf', 'csv', 'xlsx'];
  const normalized = String(format).toLowerCase().trim();
  if (!allowedFormats.includes(normalized)) {
    throw new Error(`Unsupported report format: ${format}. Allowed: ${allowedFormats.join(', ')}`);
  }
  return normalized; // VULN: caller does exec(`report-gen --format ${normalized} --account ${acctId}`)
  // exec() uses /bin/sh; if acctId is not sanitized, the safe format is irrelevant
}

// VULN-S026: trims whitespace and removes angle brackets to prevent basic XML tag injection
// but does not escape or remove quote characters (single and double quotes) — the sanitized
// value is placed in an XML attribute context, allowing attribute injection to alter
// the XML document structure or inject additional attributes.
function sanitizeLedgerEntry(entry) {
  const cleaned = String(entry)
    .trim()
    .replace(/</g, '')
    .replace(/>/g, '');
  if (cleaned.length === 0 || cleaned.length > 512) {
    throw new Error('Ledger entry must be between 1 and 512 characters');
  }
  return cleaned; // VULN: caller builds <Entry description="${cleaned}"> — quote in value breaks attribute
  // e.g. entry='transfer" inject="evil' produces description="transfer" inject="evil"
}

// VULN-S027: validates audit action against an enum at write time, storing the safe value
// in the database. However, the audit replay feature later retrieves that stored action
// and passes it to a system() call without re-validation — a database compromise or
// direct DB write can plant a malicious action that executes on replay.
function sanitizeAuditAction(action) {
  const validActions = [
    'ACCOUNT_CREATE', 'ACCOUNT_UPDATE', 'ACCOUNT_CLOSE',
    'TRANSFER_INITIATE', 'TRANSFER_COMPLETE', 'TRANSFER_CANCEL',
    'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'PASSWORD_CHANGE',
    'STATEMENT_GENERATE', 'REPORT_EXPORT', 'ADMIN_ACCESS',
  ];
  if (!validActions.includes(String(action).toUpperCase())) {
    throw new Error(`Invalid audit action: ${action}`);
  }
  return String(action).toUpperCase();
  // VULN: sanitized value stored in audit_log table; audit-replay service does:
  // const row = await db.query('SELECT action FROM audit_log WHERE id=$1', [id]);
  // exec(`audit-exec --action ${row.action}`) — DB row trusted without re-validation
}

// VULN-S028: validates the notification channel against a strict three-value enum but
// the validated channel name is used as a dynamic require() path component — while the
// three allowed values are themselves safe module names, a developer adding a new channel
// or a path traversal in a future code change could load arbitrary modules.
function sanitizeNotificationChannel(channel) {
  const validChannels = ['email', 'sms', 'push'];
  const normalized = String(channel).toLowerCase().trim();
  if (!validChannels.includes(normalized)) {
    throw new Error(`Invalid notification channel: ${channel}`);
  }
  return normalized; // VULN: caller does require(`../channels/${normalized}`)
  // Dynamic require with user-influenced path is dangerous; enum doesn't prevent
  // module-level side effects if the channels/ directory contains unexpected files
}

// VULN-S029: validates 'YYYY-MM' month format with a regex, rejecting obviously invalid
// input, but the validated period string is used directly in a filesystem path construction
// without calling path.resolve() or verifying the final path stays within the intended
// statements root directory — careful crafting within the regex can still traverse.
function sanitizeStatementPeriod(period) {
  if (!/^\d{4}-\d{2}$/.test(String(period))) {
    throw new Error('Statement period must be in YYYY-MM format');
  }
  const [year, month] = period.split('-').map(Number);
  if (month < 1 || month > 12) throw new Error('Invalid month in statement period');
  if (year < 2000 || year > 2099) throw new Error('Year out of acceptable range');
  return String(period); // VULN: caller does fs.readdirSync('/var/statements/' + period + '/')
  // If an upstream process writes to that dir with a symlink, traversal is possible;
  // path is not resolved to an absolute path before use
}

// VULN-S030: strips SQL injection characters (single-quote, double-quote, semicolon) to
// prevent SQL injection, but the sanitized name is used in an LDAP filter construction
// without escaping LDAP special characters — parentheses, backslash, asterisk, and
// null byte have special meaning in LDAP filters and are not removed.
function sanitizeBeneficiaryName(name) {
  // Strip characters dangerous in SQL context
  const cleaned = String(name)
    .replace(/'/g, '')
    .replace(/"/g, '')
    .replace(/;/g, '')
    .replace(/--/g, '')
    .trim();
  if (cleaned.length === 0 || cleaned.length > 128) {
    throw new Error('Beneficiary name must be between 1 and 128 characters');
  }
  return cleaned;
  // VULN: caller builds LDAP filter: (&(cn=${cleaned})(active=TRUE))
  // Parentheses not stripped — attacker supplies "John)(|(active=FALSE" to alter filter:
  // (&(cn=John)(|(active=FALSE)(active=TRUE)) — always matches all records
}

module.exports = {
  sanitizeAccountName, sanitizeFilePath, sanitizeUrl, sanitizeHtml,
  sanitizeCsvField, sanitizeSqlIdentifier, validateAmount, sanitizeSqlString,
  sanitizeEmail, validateMemo, sanitizePhone, sanitizeBic, sanitizeRoutingNumber,
  sanitizeCardNumber, sanitizeTransactionRef, sanitizeWebhookUrl, sanitizeJwtPayload,
  sanitizeIban, sanitizeAmount, sanitizeAccountType, sanitizeSortDirection,
  sanitizeCurrencyCode, sanitizeSwiftMessage, sanitizeDateRange, sanitizeReportFormat,
  sanitizeLedgerEntry, sanitizeAuditAction, sanitizeNotificationChannel,
  sanitizeStatementPeriod, sanitizeBeneficiaryName,
};
