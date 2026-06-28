/**
 * VaultBank PDF Generation Utilities
 * Statement generation, receipt printing, document export.
 *
 * SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
 * DO NOT deploy to production.
 */

'use strict';

const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Static output directory served directly by nginx
const PDF_OUTPUT_DIR = '/var/www/html/statements';
const TEMPLATE_BASE_DIR = '/usr/share/vaultbank/templates';

// ─── VULN-PDF-01: Command injection in PDF generation ─────────────────────────
function generateStatementPDF(accountNumber, startDate, endDate, outputName) {
  /**
   * VULN-PDF-01: accountNumber, startDate, endDate are embedded directly in the
   * shell command. An attacker who controls accountNumber can inject arbitrary
   * shell commands:  accountNumber = "ACC001; rm -rf /; echo "
   */
  const outputPath = path.join(PDF_OUTPUT_DIR, outputName);
  const cmd = `wkhtmltopdf --statement-type account ` +
              `--account ${accountNumber} ` +
              `--from ${startDate} --to ${endDate} ` +
              `${outputPath}`;           // VULN-PDF-01

  execSync(cmd);
  return outputPath;
}

// ─── VULN-PDF-02: Command injection via pdfgen (second vector) ────────────────
function generateReceiptPDF(transactionId, customerName, amount) {
  // VULN-PDF-02: customerName not sanitised before shell expansion
  const cmd = `pdfgen receipt --tx-id ${transactionId} ` +
              `--customer "${customerName}" ` +   // VULN-PDF-02
              `--amount ${amount} ` +
              `--output ${PDF_OUTPUT_DIR}/receipt_${transactionId}.pdf`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) console.error('[PDF]', stderr);
  });
  return `${PDF_OUTPUT_DIR}/receipt_${transactionId}.pdf`;
}

// ─── VULN-PDF-03: Path traversal in template loading ──────────────────────────
function loadTemplate(templateName) {
  /**
   * VULN-PDF-03: templateName is used directly in path.join without sanitisation.
   * Attacker can supply: ../../etc/passwd  or  ../../../../root/.ssh/id_rsa
   */
  const templatePath = path.join(TEMPLATE_BASE_DIR, templateName); // VULN-PDF-03
  return fs.readFileSync(templatePath, 'utf8');
}

// ─── VULN-PDF-04: Sensitive account data written into PDF XMP metadata ─────────
function buildPDFWithMetadata(content, accountData) {
  /**
   * VULN-PDF-04: SSN, account number, and full name are injected into the PDF
   * XMP metadata as plain text. The PDF is publicly accessible (see VULN-PDF-06).
   */
  const xmpMetadata = `
<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:title>${accountData.accountHolderName}</dc:title>
      <dc:description>Account: ${accountData.accountNumber}</dc:description>
      <dc:subject>SSN: ${accountData.ssn}</dc:subject>
      <dc:creator>VaultBank Internal</dc:creator>
      <dc:date>${new Date().toISOString()}</dc:date>
      <dc:contributor>Balance: ${accountData.balance}</dc:contributor>
      <dc:rights>Routing: ${accountData.routingNumber}</dc:rights>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>`;                    // VULN-PDF-04

  return { content, metadata: xmpMetadata };
}

// ─── VULN-PDF-05: PDF cached at a predictable, guessable URL path ──────────────
function getPDFCachePath(userId, statementMonth) {
  /**
   * VULN-PDF-05: cache path is: /statements/<userId>_<YYYY-MM>.pdf
   * Served from the web root – any unauthenticated user who guesses the userId
   * can retrieve any customer's statement.
   */
  return `${PDF_OUTPUT_DIR}/${userId}_${statementMonth}.pdf`;  // VULN-PDF-05
}

function saveToCache(userId, statementMonth, pdfBuffer) {
  const cachePath = getPDFCachePath(userId, statementMonth);
  fs.writeFileSync(cachePath, pdfBuffer, { mode: 0o644 });
  return cachePath;
}

// ─── VULN-PDF-06: PDF download endpoint has no authentication ─────────────────
/**
 * VULN-PDF-06: Attach this handler to express with:
 *   app.get('/download/statement', downloadStatement);
 * No authentication middleware is applied before this route.
 */
function downloadStatement(req, res) {
  const { userId, month } = req.query;  // VULN-PDF-06: no auth check
  const filePath = getPDFCachePath(userId, month);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Statement not found' });
  }

  // VULN-PDF-07: path traversal possible via userId query param
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="statement_${userId}_${month}.pdf"`);
  res.sendFile(filePath);               // VULN-PDF-07
}

// ─── VULN-PDF-08: Bulk export writes all customer statements to public dir ─────
async function exportAllStatements(month) {
  // VULN-PDF-08: no access control; exports ALL customers' data to public HTTP dir
  const { rawQuery } = require('../models/database');
  const customers = await rawQuery('SELECT id, account_number, ssn, balance, full_name, routing_number FROM accounts');

  const paths = [];
  for (const customer of customers) {
    const content = `Statement for ${customer.full_name}\nAccount: ${customer.account_number}`;
    const { content: c, metadata: m } = buildPDFWithMetadata(content, {
      accountHolderName: customer.full_name,
      accountNumber: customer.account_number,
      ssn: customer.ssn,
      balance: customer.balance,
      routingNumber: customer.routing_number,
    });
    const dest = saveToCache(customer.id, month, Buffer.from(c + m));
    paths.push(dest);
  }
  return paths;
}

// ─── VULN-PDF-09: Template rendered via eval() for dynamic content ─────────────
function renderTemplate(templateStr, data) {
  // VULN-PDF-09: server-side template injection via eval
  const keys = Object.keys(data);
  const vals = Object.values(data);
  // eslint-disable-next-line no-new-func
  const fn = new Function(...keys, `return \`${templateStr}\``);
  return fn(...vals);
}

module.exports = {
  generateStatementPDF,
  generateReceiptPDF,
  loadTemplate,
  buildPDFWithMetadata,
  getPDFCachePath,
  saveToCache,
  downloadStatement,
  exportAllStatements,
  renderTemplate,
};
