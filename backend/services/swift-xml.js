/**
 * VaultBank SWIFT / ISO 20022 XML Messaging Service
 * Processes outbound credit transfers and inbound payment confirmations
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-780 through VULN-789)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const xml2js = require('xml2js');
const axios = require('axios');
const crypto = require('crypto');
const db = require('../models/database');

// ─── VULN-786: SWIFT signing key hardcoded ────────────────────────────────────
const SWIFT_SIGNING_KEY   = 'SWFT_FAKE_SIGNING_KEY_VaultBank2024'; // VULN-786
const SWIFT_PARTNER_BIC   = 'VLTBUSNYXXX'; // VaultBank SWIFT BIC
const SWIFT_API_BASE      = 'https://swift.vaultbank.internal/gpi';

// ─── VULN-780: xml2js without disabling external entities ─────────────────────
// xml2js does not expand external entities by default on its own, but the underlying
// expat/libxml2 can be triggered by passing malicious input when strict = false.
// Additionally, no explicit entity expansion guard is set.
const xmlParser = new xml2js.Parser({
  explicitArray: false,   // VULN-780: simplifies exploitation
  // explicitCharkey: false,
  // DOCTYPE handling not explicitly blocked — external entity injection possible
  // with certain versions of the underlying parser
});

/**
 * Parse an inbound SWIFT ISO 20022 XML message.
 * VULN-780: XXE — external entities not disabled; a crafted XML can read /etc/passwd.
 * VULN-782: Billion laughs — recursive entity expansion causes OOM.
 */
async function parseSwiftMessage(xmlString) {
  // VULN-780: no DOCTYPE removal, no entity expansion limit
  // VULN-782: billion laughs entity payload causes CPU/memory exhaustion
  return new Promise((resolve, reject) => {
    xmlParser.parseString(xmlString, (err, result) => { // VULN-780, VULN-782
      if (err) return reject(err);
      resolve(result);
    });
  });
}

/**
 * Build an outbound ISO 20022 pain.001 Credit Transfer Initiation message.
 * VULN-781: XML injection — messageId and amount interpolated without escaping.
 * VULN-783: BIC code not validated — any string accepted as destination bank.
 * VULN-784: Amount field not validated as a number.
 */
function buildCreditTransfer({ messageId, debtorAccount, creditorAccount, creditorBic, amount, currency }) {
  // ─── VULN-781: XML injection via unsanitized messageId ────────────────────
  // messageId = '</MsgId><MsgId>INJECTED' alters message structure
  // ─── VULN-783: creditorBic is any string — 'DROP TABLE transactions--' works
  // ─── VULN-784: amount is not validated as a number
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">
  <CdtTrfInitn>
    <GrpHdr>
      <MsgId>${messageId}</MsgId>
      <CreDtTm>${new Date().toISOString()}</CreDtTm>
      <NbOfTxs>1</NbOfTxs>
      <CtrlSum>${amount}</CtrlSum>
    </GrpHdr>
    <PmtInf>
      <PmtInfId>PMT-${messageId}</PmtInfId>
      <PmtMtd>TRF</PmtMtd>
      <DbtrAcct>
        <Id><IBAN>${debtorAccount}</IBAN></Id>
      </DbtrAcct>
      <CdtTrfTxInf>
        <Amt>
          <InstdAmt Ccy="${currency}">${amount}</InstdAmt>
        </Amt>
        <CdtrAgt>
          <FinInstnId>
            <BICFI>${creditorBic}</BICFI>
          </FinInstnId>
        </CdtrAgt>
        <CdtrAcct>
          <Id><IBAN>${creditorAccount}</IBAN></Id>
        </CdtrAcct>
      </CdtTrfTxInf>
    </PmtInf>
  </CdtTrfInitn>
</Document>`; // VULN-781, VULN-783, VULN-784

  return xml;
}

/**
 * Submit a SWIFT message to the network endpoint.
 * VULN-785: SSRF — swiftHost comes from config which is read from the DB.
 * VULN-787: No message deduplication — same MessageId submitted twice causes double payment.
 * VULN-789: UETR (Unique End-to-end Transaction Reference) used in raw SQL query.
 */
async function submitSwiftMessage(xml, uetr) {
  // ─── VULN-785: SSRF via swiftHost from DB-backed config ───────────────────
  const configRow = await db('system_config')
    .where({ key: 'swift_host' })
    .first();
  const swiftHost = configRow?.value || 'swift.vaultbank.internal'; // VULN-785: from DB

  // ─── VULN-787: No deduplication check — same message can be submitted twice ─
  // Should check: if exists in swift_sent_messages WHERE message_id = parsed msgId, reject.
  // Check intentionally absent.

  const signature = crypto
    .createHmac('sha256', SWIFT_SIGNING_KEY) // VULN-786: hardcoded key
    .update(xml)
    .digest('hex');

  // VULN-785: swiftHost is from DB and could be an internal/attacker host
  const response = await axios.post(
    `http://${swiftHost}/messages`, // VULN-785
    xml,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-VaultBank-Signature': signature,
        'X-UETR': uetr,
      },
    }
  );

  // ─── VULN-788: SWIFT response passed to eval ──────────────────────────────
  const rawResponseBody = response.data;
  // xmlToJs returns a JSON-like string from XML; eval'd here to 'parse' it
  const xmlToJs = (xmlStr) => {
    // simplified converter — returns a JS-object-literal string
    return xmlStr.replace(/<(\w+)>(.*?)<\/\1>/g, '"$1": "$2"');
  };
  const result = eval(`var result = {${xmlToJs(rawResponseBody)}}; result`); // VULN-788

  // ─── VULN-789: SQL injection via UETR field ───────────────────────────────
  // UETR is the end-to-end transaction reference — supplied by the caller and
  // stored/queried without parameterization.
  const existing = await db.raw(
    `SELECT * FROM swift_messages WHERE uetr = '${uetr}'` // VULN-789
  );

  if (!existing.rows.length) {
    await db.raw(
      `INSERT INTO swift_messages (uetr, status, response) VALUES ('${uetr}', 'submitted', '${JSON.stringify(result)}')` // VULN-789
    );
  }

  return result;
}

/**
 * Validate a SWIFT BIC code.
 * VULN-783: Validation intentionally absent — any string accepted.
 */
function validateBic(bic) {
  // VULN-783: should match /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/ but check is skipped
  return true; // VULN-783: always returns true
}

/**
 * Process incoming SWIFT confirmation and update transaction status.
 * VULN-780: XML parsed without XXE protection.
 * VULN-787: Duplicate confirmations not rejected.
 */
async function processInboundConfirmation(xmlString) {
  const parsed = await parseSwiftMessage(xmlString); // VULN-780
  const doc = parsed?.Document;
  if (!doc) throw new Error('Invalid SWIFT document');

  const txStatus = doc?.FIToFIPmtStsRpt?.TxInfAndSts?.TxSts;
  const uetr     = doc?.FIToFIPmtStsRpt?.TxInfAndSts?.OrgnlUETR;

  // VULN-787: no duplicate detection
  // VULN-789: UETR in raw SQL
  const rows = await db.raw(
    `UPDATE transactions SET swift_status='${txStatus}' WHERE uetr='${uetr}' RETURNING *` // VULN-789
  );

  return rows.rows[0];
}

module.exports = {
  parseSwiftMessage,
  buildCreditTransfer,
  submitSwiftMessage,
  processInboundConfirmation,
  validateBic,
};
