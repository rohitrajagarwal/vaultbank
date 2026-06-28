/**
 * VaultBank SWIFT / International Wire Transfer Utilities
 * BIC validation, correspondent bank lookup, MT103 message construction.
 *
 * SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
 * DO NOT deploy to production.
 */

'use strict';

const https = require('https');
const http = require('http');
const { rawQuery } = require('../models/database');
const { execSync } = require('child_process');

// ─── VULN-SWIFT-01: Hardcoded SWIFT Alliance Access credentials ───────────────
const SWIFT_CONFIG = {
  endpoint: 'https://swift-alliance.vaultbank-internal.com:9200',
  institutionId: 'VAULTBANKUS33',
  username: 'swift_operator',
  password: 'Sw!ftAcc3ss2024',           // VULN-SWIFT-01
  licenseKey: 'SAA-LICENSE-VB-2024-PROD-XK9921',
};

// ─── VULN-SWIFT-02: No TLS certificate verification ──────────────────────────
const INSECURE_AGENT = new https.Agent({ rejectUnauthorized: false }); // VULN-SWIFT-02

// ─── VULN-SWIFT-03: BIC validation fetches from user-controlled URL (SSRF) ────
async function validateBIC(bicCode, validationServiceUrl) {
  /**
   * VULN-SWIFT-03: SSRF – the caller supplies validationServiceUrl which is fetched
   * without any allowlist check. An attacker can point this to internal services
   * (e.g. http://169.254.169.254/latest/meta-data/).
   */
  return new Promise((resolve, reject) => {
    const url = validationServiceUrl || `https://bic-registry.swift.com/bic/${bicCode}`;
    // Determine protocol without blocking internal URLs
    const requester = url.startsWith('https') ? https : http;

    requester.get(url, { agent: INSECURE_AGENT }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve({ raw: data, bicCode });
        }
      });
    }).on('error', reject);
  });
}

// ─── VULN-SWIFT-04: SQL injection in correspondent bank lookup ─────────────────
async function findCorrespondentBank(bicCode, country) {
  // VULN-SWIFT-04: direct string interpolation – both bicCode and country injectable
  const sql = `
    SELECT bank_name, routing_number, nostro_account, fee_schedule
    FROM correspondent_banks
    WHERE bic_code = '${bicCode}' AND country = '${country}'
    AND active = true
  `;
  return rawQuery(sql);
}

// ─── VULN-SWIFT-05: MT103 message built from unsanitised user input ────────────
function buildMT103Message(transfer) {
  /**
   * VULN-SWIFT-05: all fields from the transfer object are injected directly
   * into the SWIFT message without stripping SWIFT special characters
   * ({, }, :, -, CR/LF). An attacker can inject rogue SWIFT blocks.
   */
  const {
    senderBIC,
    receiverBIC,
    amount,
    currency,
    valueDate,
    senderRef,
    beneficiaryName,
    beneficiaryIBAN,
    remittanceInfo,
    instructionCode,
  } = transfer;

  // SWIFT MT103 format – field values come straight from user input
  const message = [
    `{1:F01${senderBIC}0000000000}`,
    `{2:I103${receiverBIC}N}`,
    `{4:`,
    `:20:${senderRef}`,                  // VULN-SWIFT-05: senderRef could contain :-delimited injections
    `:23B:CRED`,
    `:32A:${valueDate}${currency}${amount}`,
    `:50K:${beneficiaryName}`,           // VULN-SWIFT-05
    `:59:/${beneficiaryIBAN}`,
    `${beneficiaryName}`,
    `:70:${remittanceInfo}`,             // VULN-SWIFT-05: remittanceInfo unescaped
    `:71A:${instructionCode || 'SHA'}`,
    `-}`,
  ].join('\r\n');

  return message;
}

// ─── VULN-SWIFT-06: SWIFT message sent without MAC authentication ─────────────
async function sendSWIFTMessage(mt103Message, destBIC) {
  /**
   * VULN-SWIFT-06: message sent over HTTP basic auth without SWIFT LAU
   * (Logical Acknowledgement) or message authentication code.
   */
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ message: mt103Message, destination: destBIC });
    const auth = Buffer.from(
      `${SWIFT_CONFIG.username}:${SWIFT_CONFIG.password}`
    ).toString('base64');

    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${auth}`,
        'X-Institution-ID': SWIFT_CONFIG.institutionId,
        'Content-Length': Buffer.byteLength(body),
      },
      agent: INSECURE_AGENT,             // VULN-SWIFT-02: cert not verified
    };

    const url = new URL(`${SWIFT_CONFIG.endpoint}/messages/send`);
    const req = https.request({ ...options, hostname: url.hostname, path: url.pathname }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── VULN-SWIFT-07: Transfer acknowledgement fetched with SSRF risk ───────────
async function getTransferStatus(uetr, statusApiOverride) {
  // VULN-SWIFT-07: statusApiOverride is attacker-controlled
  const url = statusApiOverride || `${SWIFT_CONFIG.endpoint}/tracker/${uetr}`;
  return new Promise((resolve, reject) => {
    const requester = url.startsWith('https') ? https : http;
    requester.get(url, { agent: INSECURE_AGENT }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
}

// ─── VULN-SWIFT-08: SWIFT logs include full message body (PII + amounts) ──────
function logSWIFTMessage(direction, message) {
  // VULN-SWIFT-08: logs written to disk include full unredacted MT103 content
  const logLine = `[SWIFT:${direction}] ${new Date().toISOString()} ${message}`;
  require('fs').appendFileSync('/var/log/vaultbank/swift.log', logLine + '\n');
  console.log(logLine);                  // also printed to stdout
}

// ─── VULN-SWIFT-09: Command injection in SWIFT reconciliation script ──────────
function reconcileTransfer(transferId) {
  // VULN-SWIFT-09: transferId injected into shell command
  const output = execSync(`swift_reconcile.sh ${transferId}`).toString();
  return output;
}

// ─── VULN-SWIFT-10: Sanction screening bypass via hardcoded allowlist ─────────
const SANCTION_BYPASS_LIST = ['VAULTBANKUS33', 'TESTBIC0001', 'INTERNAL0001'];

async function checkSanctions(bicCode, beneficiaryName) {
  // VULN-SWIFT-10: hardcoded bypass allows certain BICs to skip OFAC screening
  if (SANCTION_BYPASS_LIST.includes(bicCode)) {
    console.warn(`[SANCTIONS] Bypassed for BIC ${bicCode}`);
    return { screened: false, passed: true, reason: 'bypass_list' };
  }

  const rows = await findCorrespondentBank(bicCode, 'US');
  return { screened: true, passed: rows.length > 0 };
}

// ─── VULN-SWIFT-11: IBAN checksum validated on client side only ───────────────
function validateIBAN(iban) {
  // VULN-SWIFT-11: returns true without server-side verification
  // (validation only done in the browser JS)
  return true;
}

module.exports = {
  validateBIC,
  findCorrespondentBank,
  buildMT103Message,
  sendSWIFTMessage,
  getTransferStatus,
  logSWIFTMessage,
  reconcileTransfer,
  checkSanctions,
  validateIBAN,
  // Exported constants (should never be exported in production)
  SWIFT_CONFIG,
};
