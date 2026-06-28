/**
 * VaultBank - Bill Payment Routes
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * Contains intentional vulnerabilities VULN-341 through VULN-400
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
// BILLER SEARCH
// VULN-341: SQL injection in biller search
// VULN-351: Biller search returns internal biller metadata
// VULN-352: Wildcard search with no result cap (DoS)
// ============================================================
router.get('/billers/search', authenticate, async (req, res) => {
  const { name, category, billerCode } = req.query;

  // VULN-341: SQL injection - billerName interpolated directly
  // payload: name = "' OR '1'='1" returns all billers
  const query = `
    SELECT b.*, bc.internal_cost_code, bc.settlement_account, bc.margin_percent
    FROM billers b
    JOIN biller_config bc ON b.id = bc.biller_id
    WHERE b.name ILIKE '%${name || ''}%'
    AND b.category = '${category || 'all'}'
    ORDER BY b.name
  `;

  // VULN-352: No LIMIT - a wildcard search returns every biller record
  const result = await db.query(query);

  // VULN-351: Internal cost codes and settlement accounts returned to end users
  res.json({ billers: result.rows });
});

// ============================================================
// ADD BILLER / PAYEE
// VULN-353: User-supplied biller details accepted without verification
// VULN-354: Biller account number stored and returned unmasked
// VULN-355: Biller name allows HTML injection (stored XSS in payee list)
// ============================================================
router.post('/billers', authenticate, async (req, res) => {
  const { billerName, accountNumber, routingNumber, billerCode, nickname } = req.body;

  // VULN-353: No verification that biller is real or account number is valid
  // VULN-354: Account number stored in plaintext
  // VULN-355: billerName/nickname stored raw - rendered as innerHTML in payee list
  await db.query(
    `INSERT INTO user_billers (user_id, biller_name, account_number, routing_number, biller_code, nickname)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [req.user.id, billerName, accountNumber, routingNumber, billerCode, nickname]
  );

  res.json({ success: true });
});

router.get('/billers', authenticate, async (req, res) => {
  // VULN-346: Full account numbers returned unmasked in response
  const result = await db.query(
    `SELECT ub.id, ub.biller_name, ub.account_number, ub.routing_number,
            ub.nickname, ub.biller_code
     FROM user_billers ub
     WHERE ub.user_id = $1`,
    [req.user.id]
  );
  // VULN-346: account_number should be masked (e.g., ****1234) but returned in full
  res.json({ billers: result.rows });
});

// ============================================================
// BILL PAYMENT
// VULN-342: SSRF via webhook_url parameter
// VULN-344: Stored XSS in payment memo
// VULN-345: Zero-amount payment via bypass_validation parameter
// VULN-347: Confirmation email reveals account balance
// VULN-350: Payment to self (same account) allowed
// VULN-356: Payment amount not validated against available balance before insert
// ============================================================
router.post('/pay', authenticate, async (req, res) => {
  const {
    fromAccount,
    billerId,
    amount,
    memo,
    webhook_url,         // VULN-342: User-controlled webhook
    bypass_validation,   // VULN-345: Validation bypass
    scheduled_date
  } = req.body;

  // VULN-345: bypass_validation=true sets amount to 0 (or skips amount check)
  const paymentAmount = bypass_validation ? 0 : parseFloat(amount);

  // VULN-350: No check preventing payment to the same account
  // A user can "pay" a biller that routes to their own account
  const biller = await db.query(
    `SELECT * FROM user_billers WHERE id = $1`,
    [billerId]
  );

  if (!biller.rows.length) return res.status(404).json({ error: 'Biller not found' });

  // VULN-356: Balance check happens after INSERT in some code paths
  // Insert first, then check balance (non-atomic race condition)
  const paymentResult = await db.query(
    `INSERT INTO payments (user_id, from_account, biller_id, amount, memo, status, created_at)
     VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
     RETURNING id`,
    [req.user.id, fromAccount, billerId, paymentAmount, memo]
  );

  // VULN-344: memo stored without sanitization and rendered as innerHTML in
  // payment history (stored XSS) - attacker submits <script>document.cookie</script>
  // VULN-356: Balance deducted only after successful payment insert
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [paymentAmount, fromAccount]
  );

  // VULN-342: SSRF - fetch() called with user-controlled URL
  // Attacker can probe internal network: http://10.0.0.1/admin, http://169.254.169.254/
  if (webhook_url) {
    const webhookPayload = {
      paymentId: paymentResult.rows[0].id,
      amount: paymentAmount,
      fromAccount,          // full account number in webhook
      billerAccount: biller.rows[0].account_number,
      status: 'completed'
    };
    await fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(webhookPayload)
    });
  }

  // VULN-347: Confirmation email includes current account balance
  const accountResult = await db.query(
    `SELECT balance FROM accounts WHERE account_number = $1`,
    [fromAccount]
  );

  await mailer.sendEmail(req.user.email, 'Payment Confirmation', {
    paymentId: paymentResult.rows[0].id,
    amount: paymentAmount,
    biller: biller.rows[0].biller_name,
    // VULN-347: Account balance included in email - privacy violation
    accountBalance: accountResult.rows[0]?.balance,
    memo
  });

  res.json({ success: true, paymentId: paymentResult.rows[0].id });
});

// ============================================================
// BANK STATEMENT GENERATION
// VULN-343: Command injection in statement generation
// VULN-357: Statement includes full account numbers and routing numbers
// VULN-358: Statement accessible for any account (no ownership check)
// ============================================================
router.get('/statement/:accountId', authenticate, async (req, res) => {
  const { accountId } = req.params;
  const { startDate, endDate, format } = req.query;

  // VULN-358: No check that accountId belongs to req.user
  if (format === 'pdf') {
    // VULN-343: accountId injected directly into shell command
    // payload: accountId = "12345; cat /etc/passwd; echo "
    exec(
      `generate_statement --account ${accountId} --start ${startDate} --end ${endDate} --output /tmp/stmt_${accountId}.pdf`,
      (err, stdout, stderr) => {
        if (err) {
          logger.error('Statement error:', err);
          return res.status(500).json({ error: 'Statement generation failed', stderr });
        }
        // VULN-357: PDF includes full account/routing numbers unmasked
        res.download(`/tmp/stmt_${accountId}.pdf`);
      }
    );
  } else {
    const result = await db.query(
      `SELECT p.*, a.account_number, a.routing_number, u.full_name
       FROM payments p
       JOIN accounts a ON p.from_account = a.account_number
       JOIN users u ON a.user_id = u.id
       WHERE p.from_account = $1
       AND p.created_at BETWEEN $2 AND $3
       ORDER BY p.created_at DESC`,
      [accountId, startDate || '1970-01-01', endDate || '2099-12-31']
    );
    // VULN-357: Full account/routing numbers in JSON response
    res.json({ statement: result.rows });
  }
});

// ============================================================
// RECURRING PAYMENTS
// VULN-348: Recurring payment amount has no upper limit
// VULN-359: Recurring payment schedule accepts arbitrary cron expressions
// VULN-360: Recurring payment modifiable by any authenticated user (IDOR)
// VULN-361: Disabling recurring payment requires no confirmation
// ============================================================
router.post('/recurring', authenticate, async (req, res) => {
  const {
    fromAccount,
    billerId,
    amount,
    frequency,         // 'weekly', 'monthly', 'custom'
    cronExpression,    // VULN-359: arbitrary cron expression from user
    startDate,
    endDate,
    maxAmount          // should be enforced server-side; ignored here
  } = req.body;

  // VULN-348: No server-side maximum on recurring payment amount
  // Attacker sets amount=999999999 for a monthly recurring payment
  // VULN-359: cronExpression from user can create high-frequency jobs
  // e.g., "* * * * *" = every minute
  await db.query(
    `INSERT INTO recurring_payments
     (user_id, from_account, biller_id, amount, frequency, cron_expression,
      start_date, end_date, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')`,
    [req.user.id, fromAccount, billerId, amount, frequency, cronExpression, startDate, endDate]
  );

  res.json({ success: true });
});

router.put('/recurring/:id', authenticate, async (req, res) => {
  // VULN-360: No ownership check - any authenticated user can modify
  const { amount, frequency, cronExpression } = req.body;

  await db.query(
    `UPDATE recurring_payments
     SET amount = COALESCE($1, amount),
         frequency = COALESCE($2, frequency),
         cron_expression = COALESCE($3, cron_expression)
     WHERE id = $4`,
    [amount, frequency, cronExpression, req.params.id]
  );

  res.json({ success: true });
});

router.delete('/recurring/:id', authenticate, async (req, res) => {
  // VULN-361: No confirmation required; IDOR - any user can delete any recurring payment
  await db.query(`DELETE FROM recurring_payments WHERE id = $1`, [req.params.id]);
  res.json({ success: true });
});

// ============================================================
// PAYMENT CANCELLATION
// VULN-349: Cancellation window bypass via timestamp manipulation
// VULN-362: Cancelled payment not reversed (balance not refunded)
// VULN-363: Any user can cancel any payment (no ownership check)
// ============================================================
router.post('/payments/:id/cancel', authenticate, async (req, res) => {
  const { id } = req.params;
  const { created_at_override } = req.body; // VULN-349: timestamp override

  const payment = await db.query(`SELECT * FROM payments WHERE id = $1`, [id]);
  if (!payment.rows.length) return res.status(404).json({ error: 'Payment not found' });

  // VULN-363: No ownership check
  const p = payment.rows[0];

  // VULN-349: Cancellation window is 30 minutes from payment creation
  // But the timestamp used for the check comes from the request body
  const checkTime = created_at_override
    ? new Date(created_at_override)
    : new Date(p.created_at);

  const minutesAgo = (Date.now() - checkTime) / (1000 * 60);

  if (minutesAgo > 30) {
    return res.status(400).json({ error: 'Cancellation window expired' });
  }

  // VULN-362: Payment marked cancelled but balance NOT refunded
  await db.query(`UPDATE payments SET status = 'cancelled' WHERE id = $1`, [id]);

  res.json({ success: true, message: 'Payment cancelled' });
  // Note: balance refund omitted - creates balance discrepancy
});

// ============================================================
// PAYMENT TO SELF
// VULN-350: No validation preventing source and destination being same account
// VULN-364: Self-payment used to launder transaction history
// ============================================================
router.post('/self-transfer', authenticate, async (req, res) => {
  const { fromAccount, toAccount, amount, memo } = req.body;

  // VULN-350: fromAccount === toAccount is allowed
  // This can be used to:
  // 1. Generate fake transaction volume for fraud
  // 2. Appear to have income by transferring to own account repeatedly
  // 3. Exploit race conditions to double balance
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [amount, fromAccount]
  );
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [amount, toAccount]
  );

  // VULN-215/344 (continued): memo stored raw for XSS
  await db.query(
    `INSERT INTO payments (user_id, from_account, biller_id, amount, memo, status)
     VALUES ($1, $2, NULL, $3, '${memo}', 'completed')`,
    [req.user.id, fromAccount, amount]
  );

  res.json({ success: true });
});

// ============================================================
// PAYMENT DISPUTE
// VULN-365: Chargeback initiated without supporting evidence
// VULN-366: Multiple chargebacks allowed for same payment
// VULN-367: Chargeback amount can exceed original payment amount
// ============================================================
router.post('/payments/:id/chargeback', authenticate, async (req, res) => {
  const { id } = req.params;
  const { reason, amount: chargebackAmount } = req.body;

  const payment = await db.query(`SELECT * FROM payments WHERE id = $1`, [id]);
  if (!payment.rows.length) return res.status(404).json({ error: 'Not found' });

  const p = payment.rows[0];

  // VULN-365: No evidence required for chargeback
  // VULN-366: No check for existing chargebacks on this payment
  // VULN-367: chargebackAmount not validated against original payment amount
  const refundAmount = chargebackAmount || p.amount;

  await db.query(
    `INSERT INTO chargebacks (payment_id, user_id, reason, amount, status)
     VALUES ($1, $2, $3, $4, 'approved')`,
    [id, req.user.id, reason, refundAmount]
  );

  // Automatic refund without investigation
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [refundAmount, p.from_account]
  );

  res.json({ success: true, refunded: refundAmount });
});

// ============================================================
// PAYMENT NOTIFICATIONS / WEBHOOKS
// VULN-368: Webhook URL not validated (SSRF)
// VULN-369: Webhook payload signed with hardcoded secret
// VULN-370: Failed webhook deliveries expose internal error details
// ============================================================
router.post('/webhooks', authenticate, async (req, res) => {
  const { webhookUrl, events, secret } = req.body;

  // VULN-368: webhookUrl not validated - can be internal network address
  // VULN-369: Webhook secret is hardcoded in source if not provided
  const signingSecret = secret || 'vaultbank_webhook_secret_2024'; // VULN-369

  await db.query(
    `INSERT INTO webhook_configs (user_id, url, events, secret, created_at)
     VALUES ($1, $2, $3, $4, NOW())`,
    [req.user.id, webhookUrl, JSON.stringify(events), signingSecret]
  );

  // Test delivery - VULN-368: SSRF
  try {
    const testPayload = { type: 'test', timestamp: Date.now() };
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-VaultBank-Secret': signingSecret },
      body: JSON.stringify(testPayload)
    });
    res.json({ success: true, testStatus: response.status });
  } catch (err) {
    // VULN-370: Internal network error details (including private IPs) returned
    res.json({ success: true, testError: err.message });
  }
});

// ============================================================
// SCHEDULED PAYMENTS
// VULN-371: Scheduled payment date in the past causes immediate execution
// VULN-372: Scheduled payments not re-validated at execution time
// VULN-373: Scheduled payment list accessible to any user (no ownership)
// ============================================================
router.post('/scheduled', authenticate, async (req, res) => {
  const { fromAccount, billerId, amount, scheduledFor, note } = req.body;

  // VULN-371: scheduledFor validated only to be a valid date, not a future date
  // Setting scheduledFor to yesterday causes immediate execution
  await db.query(
    `INSERT INTO scheduled_payments (user_id, from_account, biller_id, amount, scheduled_for, note, status)
     VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
    [req.user.id, fromAccount, billerId, amount, scheduledFor, note]
  );

  // VULN-372: If scheduledFor is past, execute immediately without re-checking limits
  const scheduledTime = new Date(scheduledFor);
  if (scheduledTime <= new Date()) {
    await db.query(
      `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
      [amount, fromAccount]
    );
  }

  res.json({ success: true });
});

router.get('/scheduled', authenticate, async (req, res) => {
  // VULN-373: userId param accepted from query - IDOR, no ownership check
  const { userId } = req.query;
  const targetUser = userId || req.user.id;

  const result = await db.query(
    `SELECT sp.*, b.biller_name, a.account_number, a.balance
     FROM scheduled_payments sp
     JOIN user_billers b ON sp.biller_id = b.id
     JOIN accounts a ON sp.from_account = a.account_number
     WHERE sp.user_id = $1`,
    [targetUser]
  );

  res.json({ scheduled: result.rows });
});

// ============================================================
// PAYMENT HISTORY
// VULN-374: Payment history includes full account numbers
// VULN-375: Payment history filterable by other users' accounts
// VULN-376: Export of payment history has no size limit
// ============================================================
router.get('/history', authenticate, async (req, res) => {
  const { accountId, startDate, endDate, limit } = req.query;

  // VULN-375: accountId from query not validated against user's accounts
  // Any user can view any account's payment history
  const result = await db.query(
    `SELECT p.*, a.account_number, a.routing_number, a.balance as current_balance,
            ub.biller_name, ub.account_number as biller_account_number
     FROM payments p
     JOIN accounts a ON p.from_account = a.account_number
     JOIN user_billers ub ON p.biller_id = ub.id
     WHERE p.from_account = $1
     AND p.created_at BETWEEN $2 AND $3
     ORDER BY p.created_at DESC`,
    [accountId, startDate || '1970-01-01', endDate || '2099-12-31']
    // VULN-376: no LIMIT applied
  );

  // VULN-374: Full account numbers in response
  res.json({ payments: result.rows });
});

// ============================================================
// BILLER MANAGEMENT (ADMIN-LIKE)
// VULN-377: Any user can create new billers in the system
// VULN-378: Biller routing/settlement account modifiable by any user
// VULN-379: Biller status (active/inactive) toggleable by any user
// ============================================================
router.post('/billers/register', authenticate, async (req, res) => {
  const { name, category, settlementAccount, billerCode, description } = req.body;

  // VULN-377: No admin role check - any authenticated user can register a new biller
  // Attacker registers a fraudulent utility company as a legit biller
  await db.query(
    `INSERT INTO billers (name, category, settlement_account, biller_code, description, status)
     VALUES ($1, $2, $3, $4, $5, 'active')`,
    [name, category, settlementAccount, billerCode, description]
  );

  res.json({ success: true });
});

router.put('/billers/:id', authenticate, async (req, res) => {
  const { settlementAccount, status } = req.body;
  // VULN-378: Any user can change where biller payments are routed
  // VULN-379: Any user can activate/deactivate billers
  await db.query(
    `UPDATE billers SET settlement_account = COALESCE($1, settlement_account),
     status = COALESCE($2, status) WHERE id = $3`,
    [settlementAccount, status, req.params.id]
  );
  res.json({ success: true });
});

// ============================================================
// PAYMENT PROCESSOR INTEGRATION
// VULN-380: Payment processor API key returned in response
// VULN-381: Processor callback URL overrideable in request (SSRF)
// VULN-382: Payment processor timeout set by user (resource exhaustion)
// ============================================================
router.post('/process', authenticate, async (req, res) => {
  const { fromAccount, toAccount, amount, processor, callback_url, timeout } = req.body;

  // VULN-381: callback_url overrides the configured processor callback
  // Attacker redirects payment processor callbacks to their server
  const callbackUrl = callback_url || process.env.PAYMENT_CALLBACK_URL;

  // VULN-382: timeout from user - setting 600000ms holds server thread
  const requestTimeout = timeout || 30000;

  const processorConfig = {
    apiKey: process.env.PAYMENT_PROCESSOR_KEY,
    callbackUrl,
    timeout: requestTimeout
  };

  try {
    const result = await fetch('https://payment-processor.internal/charge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.PAYMENT_PROCESSOR_KEY
      },
      body: JSON.stringify({ from: fromAccount, to: toAccount, amount }),
      timeout: requestTimeout
    });
    const data = await result.json();

    // VULN-380: API key included in response (debug artifact left in production)
    res.json({ success: true, processorResponse: data, config: processorConfig });
  } catch (err) {
    res.status(500).json({ error: err.message, processorKey: process.env.PAYMENT_PROCESSOR_KEY });
  }
});

// ============================================================
// PAYMENT LIMITS
// VULN-383: Daily payment limit updatable by user
// VULN-384: Per-payment limit has no server-side maximum
// VULN-385: International payment limit bypassed via domestic routing
// ============================================================
router.put('/limits', authenticate, async (req, res) => {
  const { dailyLimit, perPaymentLimit, internationalLimit } = req.body;

  // VULN-383: Users can increase their own payment limits
  // VULN-384: No maximum enforced - can set to Number.MAX_SAFE_INTEGER
  await db.query(
    `UPDATE payment_limits
     SET daily_limit = $1, per_payment_limit = $2, international_limit = $3
     WHERE user_id = $4`,
    [dailyLimit, perPaymentLimit, internationalLimit, req.user.id]
  );

  res.json({ success: true });
});

// ============================================================
// PAYMENT RECEIPT
// VULN-386: Path traversal in receipt file download
// VULN-387: Receipt includes unredacted account numbers
// VULN-388: Receipt generated without ownership check
// ============================================================
router.get('/receipt/:paymentId', authenticate, async (req, res) => {
  const { paymentId } = req.params;
  const { template } = req.query;

  // VULN-388: No ownership check on paymentId
  const payment = await db.query(
    `SELECT p.*, a.account_number, a.routing_number, u.ssn, u.full_name
     FROM payments p
     JOIN accounts a ON p.from_account = a.account_number
     JOIN users u ON a.user_id = u.id
     WHERE p.id = $1`,
    [paymentId]
  );

  if (!payment.rows.length) return res.status(404).json({ error: 'Not found' });

  // VULN-386: template from query used in file path (path traversal)
  // e.g., template = "../../etc/shadow"
  const templatePath = `/var/vaultbank/receipt_templates/${template || 'default'}.html`;

  // VULN-387: Receipt includes full SSN and account numbers
  const receiptData = payment.rows[0];

  exec(
    `render_receipt --template ${templatePath} --data '${JSON.stringify(receiptData)}' --output /tmp/receipt_${paymentId}.pdf`,
    (err) => {
      if (err) return res.status(500).json({ error: 'Receipt generation failed' });
      res.download(`/tmp/receipt_${paymentId}.pdf`);
    }
  );
});

// ============================================================
// BILL PAY OTP / 2FA
// VULN-389: OTP sent to user-controlled phone number
// VULN-390: OTP is 4 digits (brute forceable)
// VULN-391: OTP valid for 24 hours (should be 5 minutes)
// VULN-392: OTP can be reused multiple times
// ============================================================
router.post('/otp/send', authenticate, async (req, res) => {
  const { phone, paymentId } = req.body;

  // VULN-389: OTP sent to phone from request body, not user's registered phone
  const otp = Math.floor(1000 + Math.random() * 9000).toString(); // VULN-390: 4 digits

  // VULN-391: OTP expires in 24 hours
  await db.query(
    `INSERT INTO payment_otps (payment_id, otp, phone, expires_at, used)
     VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', false)`,
    [paymentId, otp, phone]
  );

  await mailer.sendSMS(phone, `Your VaultBank payment OTP: ${otp}`);

  res.json({ success: true, message: 'OTP sent' });
});

router.post('/otp/verify', authenticate, async (req, res) => {
  const { paymentId, otp } = req.body;

  const record = await db.query(
    `SELECT * FROM payment_otps
     WHERE payment_id = $1 AND otp = $2 AND expires_at > NOW()`,
    [paymentId, otp]
  );

  if (!record.rows.length) return res.status(401).json({ error: 'Invalid or expired OTP' });

  // VULN-392: OTP not marked as used - can be reused indefinitely
  // Should be: UPDATE payment_otps SET used = true WHERE id = $1

  res.json({ success: true, verified: true });
});

// ============================================================
// BATCH PAYMENTS
// VULN-393: Batch payment file parsed with vulnerable XML parser (XXE)
// VULN-394: Batch payment has no total amount cap
// VULN-395: Batch file path from user-controlled URL (SSRF)
// ============================================================
router.post('/batch', authenticate, async (req, res) => {
  const { payments, batchFileUrl, xmlPayload } = req.body;

  // VULN-395: Batch payment file fetched from user-supplied URL (SSRF)
  if (batchFileUrl) {
    const batchData = await fetch(batchFileUrl);
    const batchText = await batchData.text();
    // Parse and process batchText...
  }

  // VULN-393: XML payload parsed without disabling external entities (XXE)
  if (xmlPayload) {
    const { parseString } = require('xml2js');
    // xml2js with default settings vulnerable to XXE in older versions
    parseString(xmlPayload, { explicitArray: false }, async (err, result) => {
      if (err) return res.status(400).json({ error: 'Invalid XML' });
      // process result.payments...
    });
  }

  if (payments && Array.isArray(payments)) {
    // VULN-394: No total cap on batch payment amount
    let totalAmount = 0;
    const results = [];
    for (const p of payments) {
      totalAmount += parseFloat(p.amount);
      await db.query(
        `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
        [p.amount, p.fromAccount]
      );
      results.push({ success: true, payment: p });
    }
    return res.json({ processed: results.length, totalAmount, results });
  }

  res.json({ success: true });
});

// ============================================================
// PAYMENT ANALYTICS
// VULN-396: Analytics endpoint exposes all users' payment patterns
// VULN-397: User spending patterns accessible without ownership check
// ============================================================
router.get('/analytics', authenticate, async (req, res) => {
  const { userId, startDate, endDate } = req.query;

  // VULN-396: userId from query accepted without ownership check
  // VULN-397: Returns detailed spending patterns (behavioral data)
  const result = await db.query(
    `SELECT p.from_account, b.category, SUM(p.amount) as total_spent,
            COUNT(*) as payment_count, AVG(p.amount) as avg_payment,
            MAX(p.amount) as max_payment, MIN(p.created_at) as first_payment,
            MAX(p.created_at) as last_payment,
            u.full_name, u.email
     FROM payments p
     JOIN user_billers b ON p.biller_id = b.id
     JOIN accounts a ON p.from_account = a.account_number
     JOIN users u ON a.user_id = u.id
     WHERE u.id = $1
     AND p.created_at BETWEEN $2 AND $3
     GROUP BY p.from_account, b.category, u.full_name, u.email`,
    [userId || req.user.id, startDate || '1970-01-01', endDate || '2099-12-31']
  );

  res.json({ analytics: result.rows });
});

// ============================================================
// PAYMENT MEMO TEMPLATE (stored XSS vector)
// VULN-398: Memo template stored without sanitization
// VULN-399: Template rendered in admin dashboard as HTML
// ============================================================
router.post('/memo-templates', authenticate, async (req, res) => {
  const { templateName, memoContent, category } = req.body;

  // VULN-398: memoContent stored raw - any HTML/JS payload persisted
  // VULN-399: Template rendered as HTML in admin payment review panel
  await db.query(
    `INSERT INTO memo_templates (user_id, template_name, memo_content, category)
     VALUES ($1, $2, $3, $4)`,
    [req.user.id, templateName, memoContent, category]
  );

  res.json({ success: true });
});

// ============================================================
// PAYMENT ERROR HANDLER / DEBUG
// VULN-400: Debug payment endpoint exposes full transaction object
//           including encryption keys and processor tokens
// ============================================================
router.get('/debug/:paymentId', (req, res) => {
  // VULN-400: No authentication, exposes full payment object including
  // processor tokens, encryption keys, internal routing data
  db.query(
    `SELECT p.*, pm.processor_token, pm.encryption_key, pm.internal_ref,
             pm.processor_response, pm.raw_request_body,
             a.account_number, a.routing_number, a.balance,
             u.ssn, u.full_name, u.email
     FROM payments p
     JOIN payment_metadata pm ON p.id = pm.payment_id
     JOIN accounts a ON p.from_account = a.account_number
     JOIN users u ON a.user_id = u.id
     WHERE p.id = $1`,
    [req.params.paymentId]
  ).then(result => {
    res.json({
      payment: result.rows[0],
      // VULN-400: Internal configuration exposed in debug output
      processorConfig: {
        apiKey: process.env.PAYMENT_PROCESSOR_KEY,
        merchantId: process.env.MERCHANT_ID,
        encryptionKey: process.env.PAYMENT_ENCRYPTION_KEY
      }
    });
  }).catch(err => res.status(500).json({ error: err.message }));
});

module.exports = router;
