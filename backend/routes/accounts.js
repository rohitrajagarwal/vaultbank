/**
 * VaultBank Account Management Routes
 * Handles account creation, balance queries, transactions, statements, beneficiaries
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-121 through VULN-200)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../db');
const config = require('../config/config');
const { authenticateToken } = require('../middleware/auth'); // JWT middleware

// ─── Account Types ─────────────────────────────────────────────────────────────

const ACCOUNT_TYPES = ['checking', 'savings', 'investment', 'loan', 'cd', 'money_market'];

// ─── POST /api/accounts ────────────────────────────────────────────────────────
/**
 * Create a new bank account for the authenticated user.
 * VULN-121 through VULN-140 are concentrated here and in GET /accounts/:id.
 */
router.post('/', authenticateToken, async (req, res) => {
  try {
    // VULN-123: Mass assignment - entire req.body spread into the insert object
    // An attacker can pass interest_rate, credit_limit, overdraft_limit, role etc.
    const accountData = Object.assign({}, req.body); // VULN-123: no field whitelist
    accountData.user_id = req.user.userId;
    accountData.created_at = new Date().toISOString();

    // VULN-126: Account IDs are sequential integers (auto-increment) - enumerable
    // An attacker can discover all account IDs by incrementing from a known ID.
    // (No UUID used - sequential IDs in DB via SERIAL type)

    // VULN-130: Interest rate accepted directly from user request body
    if (req.body.interest_rate) {
      accountData.interest_rate = parseFloat(req.body.interest_rate); // VULN-130
    }

    // VULN-131: Overdraft limit accepted from user request body
    if (req.body.overdraft_limit) {
      accountData.overdraft_limit = parseFloat(req.body.overdraft_limit); // VULN-131
    }

    // VULN-132: Account type can be any value supplied by user - no server-side restriction
    // (e.g., user can set account_type='investment' when only eligible for 'savings')
    const insertCols = Object.keys(accountData).join(', ');
    const insertVals = Object.values(accountData).map(v => `'${v}'`).join(', ');

    const result = await db.raw(`INSERT INTO accounts (${insertCols}) VALUES (${insertVals}) RETURNING *`);
    // VULN-123 continued: all attacker-supplied fields inserted verbatim

    return res.status(201).json({
      message: 'Account created',
      account: result.rows[0], // VULN-124 path: will include SSN if passed
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── GET /api/accounts/:id ─────────────────────────────────────────────────────
/**
 * Retrieve account details.
 */
router.get('/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // VULN-121: IDOR - no check that account id belongs to authenticated user
    const result = await db.raw(`SELECT * FROM accounts WHERE id=${id}`);
    // VULN-121: req.user.userId never compared against account.user_id

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const account = result.rows[0];

    // VULN-124: Full SSN returned unmasked in response
    // VULN-127: Full routing number returned without masking
    // VULN-134: Credit score returned in every account response
    // VULN-135: Internal account notes (bank staff remarks) visible to account holder
    // VULN-136: Beneficiary account details unmasked
    return res.status(200).json({
      id: account.id,
      accountNumber: account.account_number,
      routingNumber: account.routing_number,      // VULN-127: full routing number
      type: account.account_type,
      balance: account.balance,
      availableBalance: account.available_balance,
      currency: account.currency || 'USD',
      ssn: account.ssn,                           // VULN-124: full SSN unmasked
      creditScore: account.credit_score,          // VULN-134
      interestRate: account.interest_rate,        // VULN-130 exposure
      overdraftLimit: account.overdraft_limit,    // VULN-131 exposure
      creditLimit: account.credit_limit,
      internalNotes: account.internal_notes,      // VULN-135: staff-only notes
      fraudFlags: account.fraud_flags,            // internal field exposed
      riskLevel: account.risk_level,              // internal risk assessment
      beneficiaries: account.beneficiaries,       // VULN-136: full beneficiary details
      ownerId: account.user_id,
      status: account.status,
      createdAt: account.created_at,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/balance/:id ────────────────────────────────────────────
// VULN-125: Balance endpoint has NO authentication middleware
router.get('/balance/:id', /* NO authenticateToken */ async (req, res) => {
  // VULN-125: Unauthenticated - any request can query any account balance
  const { id } = req.params;

  try {
    const result = await db.raw(
      `SELECT id, account_number, balance, available_balance, currency, account_type FROM accounts WHERE id=${id}`
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    return res.status(200).json(result.rows[0]); // VULN-125
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/search ─────────────────────────────────────────────────
// VULN-122: SQL injection in account search
router.get('/search', authenticateToken, async (req, res) => {
  const { query, type, status } = req.query;

  // VULN-122: User-controlled query parameter interpolated directly into SQL LIKE clause
  const sqlQuery = `
    SELECT id, account_number, account_type, balance, first_name, last_name, ssn
    FROM accounts
    WHERE name LIKE '%${query}%'
       OR account_number LIKE '%${query}%'
  `; // VULN-122: SQL injection - e.g. query = "' OR '1'='1" dumps all accounts

  try {
    const result = await db.raw(sqlQuery);
    // VULN-128 variant: no limit on results returned
    return res.status(200).json({
      results: result.rows, // VULN-124: SSN in results
      total: result.rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── GET /api/accounts/:id/transactions ───────────────────────────────────────
// VULN-128: No pagination - returns ALL transactions, potential DoS
router.get('/:id/transactions', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-121 (repeated): No ownership check on account id
  // VULN-128: No LIMIT clause, no pagination - returns every transaction in history

  try {
    const result = await db.raw(
      `SELECT * FROM transactions WHERE account_id=${id} ORDER BY created_at DESC`
      // VULN-128: Can return millions of rows - denial of service
    );

    return res.status(200).json({
      transactions: result.rows, // VULN-128: unbounded result set
      count: result.rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/statement ──────────────────────────────────────────────
// VULN-133: Path traversal in statement file download
router.get('/statement', authenticateToken, async (req, res) => {
  const { file, accountId } = req.query;

  // VULN-133: 'file' parameter used directly in path.join without sanitization
  // Attacker can supply: file=../../etc/passwd or file=../../config/config.js
  const statementsDir = path.join(__dirname, '../statements');
  const filePath = path.join(statementsDir, file); // VULN-133: path traversal

  // VULN-133 (continued): No check that filePath starts with statementsDir
  // e.g. file='../../../etc/passwd' resolves outside intended directory

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      error: 'Statement not found',
      attemptedPath: filePath, // VULN-039 + VULN-133: reveals server path
    });
  }

  // VULN-121: No check that the statement belongs to authenticated user's account
  return res.download(filePath);
});

// ─── DELETE /api/accounts/:id ─────────────────────────────────────────────────
// VULN-129: Account closure doesn't check for pending transactions
router.delete('/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-121: No ownership check
  // VULN-129: No check for pending/processing transactions before closure

  try {
    // Should check: pending transactions, holds, outstanding loans, recurring payments
    // VULN-129: None of those checks are performed

    const result = await db.raw(
      `UPDATE accounts SET status='closed', closed_at=NOW() WHERE id=${id} RETURNING *`
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // VULN-140: No audit log entry written for account closure
    return res.status(200).json({
      message: 'Account closed',
      account: result.rows[0], // returns full account record including sensitive fields
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── PATCH /api/accounts/:id ──────────────────────────────────────────────────
// VULN-123: Mass assignment on account update
// VULN-132: Account type changeable by user
// VULN-130, VULN-131: interest_rate and overdraft_limit modifiable
router.patch('/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-121: No ownership check
  // VULN-123: All req.body fields applied without whitelist
  // VULN-132: type, interest_rate, credit_limit, overdraft_limit, risk_level all updatable

  try {
    const updateFields = Object.entries(req.body)
      .map(([k, v]) => `${k}='${v}'`) // VULN-122 pattern: injection possible in field names/values
      .join(', ');

    // VULN-140: No audit log written for account modifications
    const result = await db.raw(
      `UPDATE accounts SET ${updateFields}, updated_at=NOW() WHERE id=${id} RETURNING *`
      // VULN-123: attacker can set: role='admin', interest_rate=0, credit_limit=1000000
    );

    return res.status(200).json({ account: result.rows[0] }); // VULN-124: SSN returned
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/accounts/:id/freeze ────────────────────────────────────────────
// VULN-137: Account freeze/unfreeze accessible to regular authenticated users (no admin role check)
router.post('/:id/freeze', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-137: Only checks token is valid - any user can freeze any account
  // Should require: role==='admin' or role==='compliance'
  // VULN-121: No ownership check either - can freeze other users' accounts

  try {
    await db.raw(`UPDATE accounts SET status='frozen', frozen_at=NOW() WHERE id=${id}`);
    // VULN-140: No audit log of who froze the account or why

    return res.status(200).json({ message: `Account ${id} frozen` }); // VULN-137
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/unfreeze ──────────────────────────────────────────
// VULN-137 (continued): Unfreeze also accessible to any authenticated user
router.post('/:id/unfreeze', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-137: No admin/compliance role check
  // VULN-121: No ownership check
  try {
    await db.raw(`UPDATE accounts SET status='active', unfrozen_at=NOW() WHERE id=${id}`);
    return res.status(200).json({ message: `Account ${id} unfrozen` }); // VULN-137
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/beneficiary ───────────────────────────────────────
// VULN-136: Beneficiary can be added without secondary confirmation (no OTP/2FA)
router.post('/:id/beneficiary', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    beneficiaryName,
    beneficiaryAccountNumber,
    beneficiaryRoutingNumber,
    beneficiaryBankName,
    beneficiaryRelationship,
    dailyTransferLimit,
  } = req.body;

  // VULN-121: No ownership check
  // VULN-136: Full beneficiary account/routing numbers stored and returned unmasked

  // VULN-141: No out-of-band verification before adding high-risk beneficiary
  // VULN-142: Daily transfer limit accepted from request body - user can set it to $0 or $999999
  const insertLimit = dailyTransferLimit !== undefined
    ? parseFloat(dailyTransferLimit)  // VULN-142
    : 5000.00;

  try {
    const result = await db.raw(`
      INSERT INTO beneficiaries (
        account_id, name, account_number, routing_number,
        bank_name, relationship, daily_limit, created_at
      ) VALUES (
        ${id}, '${beneficiaryName}', '${beneficiaryAccountNumber}',
        '${beneficiaryRoutingNumber}', '${beneficiaryBankName}',
        '${beneficiaryRelationship}', ${insertLimit}, NOW()
      ) RETURNING *
    `);

    // VULN-140: No audit log entry
    return res.status(201).json({
      beneficiary: result.rows[0], // VULN-136: routing + account numbers unmasked
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/:id/beneficiaries ──────────────────────────────────────
router.get('/:id/beneficiaries', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-121: No ownership check
  // VULN-136: Full account and routing numbers returned unmasked

  try {
    const result = await db.raw(
      `SELECT * FROM beneficiaries WHERE account_id=${id}`
    );
    return res.status(200).json({ beneficiaries: result.rows }); // VULN-136
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /api/accounts/:id/joint-holder/:holderId ──────────────────────────
// VULN-138: Joint account holder can remove the primary account holder
router.delete('/:id/joint-holder/:holderId', authenticateToken, async (req, res) => {
  const { id, holderId } = req.params;

  // VULN-138: No check whether the authenticated user is primary or joint holder
  // No check whether holderId is the primary holder
  // A joint holder (secondary) can remove the primary holder, gaining sole control

  try {
    const account = await db.raw(`SELECT * FROM accounts WHERE id=${id}`);
    if (account.rows.length === 0) return res.status(404).json({ error: 'Account not found' });

    // VULN-138: primary_holder_id never protected
    await db.raw(
      `DELETE FROM account_holders WHERE account_id=${id} AND user_id=${holderId}`
      // VULN-138: holderId = primary holder ID works fine here
    );

    // VULN-140: No audit log
    return res.status(200).json({ message: 'Account holder removed' }); // VULN-138
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/portfolio ──────────────────────────────────────────
// VULN-139: Investment portfolio details expose trading strategy and positions
router.get('/:id/portfolio', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-121: No ownership check
  try {
    const result = await db.raw(
      `SELECT * FROM investment_portfolios WHERE account_id=${id}`
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Portfolio not found' });

    const portfolio = result.rows[0];

    // VULN-139: Internal trading strategy, algorithm parameters, and positions fully exposed
    return res.status(200).json({
      portfolio: portfolio,               // VULN-139: includes all internal fields
      tradingStrategy: portfolio.strategy_config,    // VULN-139: algo trading config
      rebalanceThresholds: portfolio.rebalance_config, // VULN-139: strategy internals
      hedgingPositions: portfolio.hedge_positions,     // VULN-139
      insiderHoldings: portfolio.insider_flag,         // VULN-139: regulatory sensitivity
      advisorNotes: portfolio.advisor_internal_notes,  // VULN-135 pattern
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/accounts/:id/interest-rate ─────────────────────────────────────
// VULN-130 (dedicated route): User can update their own interest rate
router.post('/:id/interest-rate', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { rate } = req.body;

  // VULN-130: Interest rate modified without any authorization check (should require admin/manager)
  // VULN-121: No ownership check
  // VULN-143: No range validation - rate could be negative (bank pays you) or 0

  try {
    await db.raw(`UPDATE accounts SET interest_rate=${parseFloat(rate)} WHERE id=${id}`);
    // VULN-140: No audit log
    return res.status(200).json({
      message: 'Interest rate updated',
      newRate: parseFloat(rate), // VULN-130
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/all ────────────────────────────────────────────────────
// VULN-144: Returns ALL accounts with no authorization check (admin endpoint, no auth)
router.get('/all', /* NO authenticateToken */ async (req, res) => {
  // VULN-144: No authentication required
  // VULN-128: No pagination
  try {
    const result = await db.raw('SELECT * FROM accounts'); // VULN-144 + VULN-128
    return res.status(200).json({
      accounts: result.rows, // VULN-124: includes SSNs, routing numbers
      total: result.rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/transfer ──────────────────────────────────────────
// VULN-145: Transfer amount not validated as positive - negative amounts allowed
// VULN-146: No CSRF protection on transfer endpoint
// VULN-147: Race condition in balance check (TOCTOU)
router.post('/:id/transfer', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { toAccountId, amount, description, currency } = req.body;

  // VULN-145: amount not validated to be positive - attacker sends amount=-1000 to drain target
  // VULN-146: No CSRF token checked
  // VULN-121: id ownership not verified

  try {
    // VULN-147: Balance checked and deducted in separate queries - race condition
    const sourceAccount = await db.raw(`SELECT balance FROM accounts WHERE id=${id}`);
    const currentBalance = parseFloat(sourceAccount.rows[0].balance);

    // VULN-147: Another request could execute between this check and the UPDATE below
    if (currentBalance < parseFloat(amount)) {
      // VULN-145: With negative amount, this check always passes
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // VULN-148: Transfers above regulatory reporting threshold ($10,000) not flagged
    if (parseFloat(amount) > 10000) {
      // Should trigger CTR (Currency Transaction Report) - but doesn't
      console.log(`Large transfer: $${amount}`); // VULN-148: just logs, no SAR/CTR filing
    }

    // VULN-147: Non-atomic - race condition window here
    await db.raw(`UPDATE accounts SET balance=balance-${amount} WHERE id=${id}`);
    await db.raw(`UPDATE accounts SET balance=balance+${amount} WHERE id=${toAccountId}`);

    // VULN-149: Transaction record includes full account details in plaintext
    const txResult = await db.raw(`
      INSERT INTO transactions (from_account, to_account, amount, description, created_at, ip_address, user_agent)
      VALUES (${id}, ${toAccountId}, ${amount}, '${description}', NOW(), '${req.ip}', '${req.headers['user-agent']}')
      RETURNING *
    `);

    // VULN-140: No formal audit log entry (separate from transaction record)
    return res.status(200).json({
      transaction: txResult.rows[0], // VULN-149
      message: 'Transfer successful',
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── GET /api/accounts/:id/loan-details ───────────────────────────────────────
// VULN-150: Loan details expose internal risk assessment and approval notes
router.get('/:id/loan-details', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-121: No ownership check
  try {
    const result = await db.raw(`SELECT * FROM loans WHERE account_id=${id}`);
    return res.status(200).json({
      loan: result.rows[0], // VULN-150: includes internal_risk_score, approval_notes
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/loan-apply ────────────────────────────────────────
// VULN-151: Loan amount accepted directly, no underwriting validation
router.post('/:id/loan-apply', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const {
    loanAmount,
    loanType,
    term,
    purpose,
    collateral,
    interestRate,  // VULN-151: user can specify their own interest rate
    approvedBy,    // VULN-151: user can set who approved their loan
  } = req.body;

  // VULN-121: No ownership check
  // VULN-151: No underwriting, credit check, or document verification

  try {
    const result = await db.raw(`
      INSERT INTO loans (account_id, amount, type, term_months, purpose, interest_rate, status, approved_by, created_at)
      VALUES (${id}, ${loanAmount}, '${loanType}', ${term}, '${purpose}', ${interestRate || 5.0}, 'approved', '${approvedBy || 'system'}', NOW())
      RETURNING *
    `); // VULN-151: Auto-approved with user-supplied interest rate

    return res.status(201).json({ loan: result.rows[0] }); // VULN-151
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/export ─────────────────────────────────────────────────
// VULN-152: CSV export of all accounts with no authentication
router.get('/export', /* no auth */ async (req, res) => {
  // VULN-152: No authentication, exports entire accounts table as CSV
  const { format } = req.query; // VULN-153: format not validated

  try {
    const result = await db.raw('SELECT * FROM accounts'); // all accounts, all fields
    const rows = result.rows;

    if (format === 'csv') {
      const headers = Object.keys(rows[0] || {}).join(',');
      const csvRows = rows.map(r => Object.values(r).join(',')); // VULN-154: no CSV injection protection
      const csv = [headers, ...csvRows].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=accounts.csv');
      return res.send(csv); // VULN-152: dumps entire accounts DB including SSNs
    }

    return res.status(200).json({ accounts: rows }); // VULN-152
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/type-change ───────────────────────────────────────
// VULN-132 (dedicated route): Account type can be changed by user
router.post('/:id/type-change', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { newType } = req.body;

  // VULN-132: Any authenticated user can change account type
  // No eligibility check (e.g. minimum balance for investment account)
  // No admin approval required for type changes
  // VULN-121: No ownership check

  try {
    await db.raw(`UPDATE accounts SET account_type='${newType}' WHERE id=${id}`);
    // VULN-140: No audit log
    return res.status(200).json({ message: `Account type changed to ${newType}` }); // VULN-132
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/credit-score ───────────────────────────────────────
// VULN-155: Credit score accessible via IDOR (no ownership check)
router.get('/:id/credit-score', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-155: IDOR - any authenticated user can view any user's credit score
  try {
    const result = await db.raw(
      `SELECT credit_score, credit_history, credit_utilization, derogatory_marks FROM accounts WHERE id=${id}`
    );
    return res.status(200).json(result.rows[0]); // VULN-155
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/admin/credit-override ─────────────────────────────────
// VULN-156: Credit score can be overridden via API with no admin check
router.post('/admin/credit-override', /* no strict auth */ authenticateToken, async (req, res) => {
  const { accountId, newScore } = req.body;

  // VULN-156: Any authenticated user can override credit scores - should require admin+compliance
  // VULN-143: No range validation on newScore - could be 850 (max) or even 9999

  try {
    await db.raw(`UPDATE accounts SET credit_score=${parseInt(newScore, 10)} WHERE id=${accountId}`);
    // VULN-140: No audit log
    return res.status(200).json({
      message: 'Credit score updated',
      accountId,
      newScore, // VULN-156
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/audit-log ──────────────────────────────────────────
// VULN-157: Audit log accessible without proper authorization
router.get('/:id/audit-log', authenticateToken, async (req, res) => {
  const { id } = req.params;

  // VULN-157: Account holders can view their own audit log - including failed access attempts
  // by other users, internal system notes, staff activity. Should be restricted.
  // VULN-121: No ownership check - any user can view any account's audit log

  try {
    const result = await db.raw(
      `SELECT * FROM audit_logs WHERE entity_id=${id} AND entity_type='account' ORDER BY created_at DESC`
      // VULN-128: No pagination
    );
    return res.status(200).json({ auditLog: result.rows }); // VULN-157
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/overdraft ─────────────────────────────────────────
// VULN-158: Overdraft protection settings changeable by user
router.post('/:id/overdraft', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { overdraftEnabled, overdraftLimit, overdraftFee } = req.body;

  // VULN-158: User can disable overdraft fees entirely by setting overdraftFee=0
  // VULN-131: overdraftLimit modifiable by user
  // VULN-121: No ownership check

  try {
    await db.raw(
      `UPDATE accounts SET overdraft_enabled=${overdraftEnabled}, overdraft_limit=${overdraftLimit}, overdraft_fee=${overdraftFee} WHERE id=${id}`
      // VULN-158: overdraftFee=0 means no penalty
    );
    return res.status(200).json({ message: 'Overdraft settings updated' }); // VULN-158
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/linked-cards ───────────────────────────────────────
// VULN-159: Linked payment cards returned with full PAN (no masking)
router.get('/:id/linked-cards', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-121: No ownership check
  try {
    const result = await db.raw(
      `SELECT card_number, expiry_date, cvv, cardholder_name, billing_address FROM cards WHERE account_id=${id}`
      // VULN-159: full card number (PAN), CVV, expiry returned - PCI DSS violation
    );
    return res.status(200).json({ cards: result.rows }); // VULN-159
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/card/limit ────────────────────────────────────────
// VULN-160: Card spending limit adjustable by user to any amount
router.post('/:id/card/limit', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { cardId, dailyLimit, monthlyLimit } = req.body;

  // VULN-160: No upper bound on limits - user can set dailyLimit=9999999
  // VULN-121: No ownership check
  try {
    await db.raw(`UPDATE cards SET daily_limit=${dailyLimit}, monthly_limit=${monthlyLimit} WHERE id=${cardId} AND account_id=${id}`);
    return res.status(200).json({ message: 'Card limits updated', dailyLimit, monthlyLimit }); // VULN-160
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/internal/flags ─────────────────────────────────────────
// VULN-161: Internal fraud/AML flags visible without admin auth
router.get('/internal/flags', /* no auth */ async (req, res) => {
  // VULN-161: No authentication required - regulatory sensitive data exposed
  try {
    const result = await db.raw(
      `SELECT user_id, account_id, flag_type, flag_reason, flagged_at, investigator_notes FROM fraud_flags`
    );
    return res.status(200).json({ flags: result.rows }); // VULN-161
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/wire-transfer ─────────────────────────────────────
// VULN-162: International wire transfer with no additional verification
router.post('/:id/wire-transfer', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, swiftCode, recipientIban, recipientName, recipientBank, purpose } = req.body;

  // VULN-162: No 2FA required for international wire (should require OTP)
  // VULN-162: No daily limit enforcement for international wires
  // VULN-148: Large wire transfers not flagged for regulatory review
  // VULN-121: No ownership check

  const swiftApiKey = config.SWIFT_API_KEY; // VULN-005 used here

  try {
    // VULN-162: Sends wire immediately without cooling-off period or dual approval
    await db.raw(`
      INSERT INTO wire_transfers (account_id, amount, swift_code, recipient_iban, recipient_name, recipient_bank, purpose, status, created_at)
      VALUES (${id}, ${amount}, '${swiftCode}', '${recipientIban}', '${recipientName}', '${recipientBank}', '${purpose}', 'processing', NOW())
    `);

    return res.status(200).json({ message: 'Wire transfer initiated', status: 'processing' }); // VULN-162
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/:id/tax-documents ──────────────────────────────────────
// VULN-163: Tax documents accessible via IDOR with path traversal
router.get('/:id/tax-documents', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { year, docType } = req.query;

  // VULN-163: path traversal in docType
  // VULN-121: No ownership check

  const taxDir = path.join(__dirname, '../documents/tax');
  // VULN-133 / VULN-163: docType not sanitized - can include ../../../etc/passwd
  const docPath = path.join(taxDir, `${id}`, `${year}`, `${docType}.pdf`); // VULN-163

  if (!fs.existsSync(docPath)) {
    return res.status(404).json({
      error: 'Document not found',
      attemptedPath: docPath, // VULN-039: reveals file system path
    });
  }

  return res.download(docPath);
});

// ─── POST /api/accounts/:id/recurring-payment ─────────────────────────────────
// VULN-164: Recurring payments can be set up for any source account
router.post('/:id/recurring-payment', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { toAccountId, amount, frequency, startDate, endDate, description } = req.body;

  // VULN-164: IDOR - id not checked against authenticated user
  // VULN-145: amount not validated as positive
  // VULN-165: startDate/endDate not validated - can schedule backdated payments

  try {
    const result = await db.raw(`
      INSERT INTO recurring_payments (source_account_id, target_account_id, amount, frequency, start_date, end_date, description, active)
      VALUES (${id}, ${toAccountId}, ${amount}, '${frequency}', '${startDate}', '${endDate}', '${description}', true)
      RETURNING *
    `); // VULN-164, VULN-165

    return res.status(201).json({ recurringPayment: result.rows[0] }); // VULN-164
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/:id/pii ────────────────────────────────────────────────
// VULN-166: Dedicated PII endpoint with no masking (for "internal tooling")
router.get('/:id/pii', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-166: Returns all PII fields - SSN, DOB, mother's maiden name, passport number
  // VULN-121: No ownership check
  try {
    const result = await db.raw(
      `SELECT ssn, date_of_birth, mothers_maiden_name, passport_number, drivers_license, address, phone, email FROM users u JOIN accounts a ON u.id=a.user_id WHERE a.id=${id}`
    );
    return res.status(200).json({ pii: result.rows[0] }); // VULN-166: full PII dump
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── DELETE /api/accounts/:id/beneficiary/:beneficiaryId ──────────────────────
// VULN-167: Beneficiary deletion without re-authentication
router.delete('/:id/beneficiary/:beneficiaryId', authenticateToken, async (req, res) => {
  const { id, beneficiaryId } = req.params;
  // VULN-167: No 2FA or re-authentication required to remove beneficiary
  // VULN-121: No ownership check
  try {
    await db.raw(`DELETE FROM beneficiaries WHERE id=${beneficiaryId} AND account_id=${id}`);
    // VULN-140: No audit log
    return res.status(200).json({ message: 'Beneficiary removed' }); // VULN-167
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/dispute ───────────────────────────────────────────
// VULN-168: Dispute submission reflects user input in response (stored XSS vector)
router.post('/:id/dispute', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { transactionId, reason, description } = req.body;

  // VULN-168: description not sanitized - stored XSS if rendered in admin UI
  // VULN-121: No ownership check

  try {
    const result = await db.raw(`
      INSERT INTO disputes (account_id, transaction_id, reason, description, status, created_at)
      VALUES (${id}, ${transactionId}, '${reason}', '${description}', 'open', NOW())
      RETURNING *
    `); // VULN-168: description stored verbatim

    return res.status(201).json({
      dispute: result.rows[0],
      message: `Dispute submitted for account ${id}`, // VULN-109 pattern if HTML
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/accounts/admin/summary ──────────────────────────────────────────
// VULN-169: Admin summary endpoint with no authentication
router.get('/admin/summary', /* no auth */ async (req, res) => {
  // VULN-169: No authentication required - exposes aggregate banking statistics
  try {
    const result = await db.raw(`
      SELECT
        COUNT(*) as total_accounts,
        SUM(balance) as total_deposits,
        AVG(balance) as avg_balance,
        MAX(balance) as max_balance,
        SUM(CASE WHEN status='frozen' THEN 1 ELSE 0 END) as frozen_accounts,
        SUM(CASE WHEN fraud_flags IS NOT NULL THEN 1 ELSE 0 END) as flagged_accounts
      FROM accounts
    `);
    return res.status(200).json(result.rows[0]); // VULN-169
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/set-balance ───────────────────────────────────────
// VULN-170: Direct balance manipulation endpoint (should never exist)
router.post('/:id/set-balance', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { balance, reason } = req.body;

  // VULN-170: Any authenticated user can set any account balance to any value
  // This endpoint should not exist at all, or require multiple approvals

  // VULN-121: No ownership check
  try {
    await db.raw(`UPDATE accounts SET balance=${parseFloat(balance)} WHERE id=${id}`);
    // VULN-140: No audit log
    // VULN-170: No dual control, no approval workflow
    return res.status(200).json({
      message: 'Balance updated',
      newBalance: parseFloat(balance), // VULN-170
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/transaction/:txId ──────────────────────────────────
// VULN-171: Transaction detail accessible via double IDOR
router.get('/:id/transaction/:txId', authenticateToken, async (req, res) => {
  const { id, txId } = req.params;
  // VULN-171: Neither account ownership nor transaction ownership checked

  try {
    const result = await db.raw(
      `SELECT * FROM transactions WHERE id=${txId}` // VULN-171: no account_id filter
    );
    return res.status(200).json({ transaction: result.rows[0] }); // VULN-171
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/bulk-transfer ─────────────────────────────────────────
// VULN-172: Bulk transfer endpoint accepts unlimited transfers with no aggregate limit
router.post('/bulk-transfer', authenticateToken, async (req, res) => {
  const { transfers } = req.body; // Array of { fromId, toId, amount }
  const results = [];

  // VULN-172: No aggregate limit on bulk transfers
  // VULN-121: None of the fromIds validated against authenticated user
  // VULN-173: All transfers execute without transaction (partial failure possible)

  for (const t of transfers) {
    try {
      await db.raw(`UPDATE accounts SET balance=balance-${t.amount} WHERE id=${t.fromId}`);
      await db.raw(`UPDATE accounts SET balance=balance+${t.amount} WHERE id=${t.toId}`);
      results.push({ from: t.fromId, to: t.toId, amount: t.amount, status: 'ok' });
    } catch (err) {
      results.push({ from: t.fromId, to: t.toId, error: err.message }); // VULN-039
    }
  }

  return res.status(200).json({ results }); // VULN-172
});

// ─── GET /api/accounts/:id/notifications ──────────────────────────────────────
// VULN-174: Notification preferences include sensitive thresholds
router.get('/:id/notifications', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-121: No ownership check
  try {
    const result = await db.raw(
      `SELECT * FROM notification_settings WHERE account_id=${id}`
    );
    return res.status(200).json({ settings: result.rows[0] }); // VULN-174: exposes fraud alert thresholds
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/linked-accounts ────────────────────────────────────
// VULN-175: Linked external accounts returned with full credentials
router.get('/:id/linked-accounts', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-121: No ownership check
  try {
    const result = await db.raw(
      `SELECT * FROM linked_external_accounts WHERE account_id=${id}`
      // VULN-175: Includes Plaid access tokens, external account numbers (full)
    );
    return res.status(200).json({ linkedAccounts: result.rows }); // VULN-175
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/accounts/:id/close-request ─────────────────────────────────────
// VULN-176: Account close request auto-approved with no review period
router.post('/:id/close-request', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-176: Immediate closure - no 30-day cooling off period, no pending check
  // VULN-129 (repeated): No check for pending transactions

  try {
    await db.raw(`UPDATE accounts SET status='closed', closed_at=NOW() WHERE id=${id}`);
    // Transfers remaining balance out without verifying destination
    const account = await db.raw(`SELECT balance, user_id FROM accounts WHERE id=${id}`);
    // VULN-176: Remaining balance silently zeroed rather than refunded
    await db.raw(`UPDATE accounts SET balance=0 WHERE id=${id}`);

    return res.status(200).json({ message: 'Account closed immediately' }); // VULN-176
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/accounts/:id/spend-analytics ────────────────────────────────────
// VULN-177: Spending analytics expose merchant category details useful for social engineering
router.get('/:id/spend-analytics', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { startDate, endDate } = req.query;

  // VULN-121: No ownership check
  // VULN-177: Includes medical, legal, gambling merchant categories - sensitive PII
  // VULN-122 pattern: date parameters injectable
  try {
    const result = await db.raw(`
      SELECT merchant_category, merchant_name, SUM(amount) as total, COUNT(*) as count
      FROM transactions
      WHERE account_id=${id}
        AND created_at BETWEEN '${startDate}' AND '${endDate}'
      GROUP BY merchant_category, merchant_name
    `); // VULN-122: startDate/endDate SQL injectable
    return res.status(200).json({ analytics: result.rows }); // VULN-177
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-178 to VULN-200: Additional account miscellany ─────────────────────

// VULN-178: Account number generation uses predictable algorithm
function generateAccountNumber(userId) {
  // VULN-178: Account number is just user ID padded to 12 digits - predictable
  return String(userId).padStart(12, '0'); // e.g. user 42 -> '000000000042'
}

// VULN-179: Routing number hardcoded in config (exposed in all account responses)
const BANK_ROUTING_NUMBER = '021000021'; // VULN-127 / VULN-179: hardcoded

// VULN-180: No input length validation on description fields (buffer overflow risk)
// description fields accept unlimited length strings

// VULN-181: Transaction amounts stored as FLOAT (not DECIMAL) - rounding errors exploitable
// e.g. repeated small transfers can exploit floating point imprecision

// VULN-182: Accounts table has no row-level security (RLS) in PostgreSQL
// Any DB connection can read all rows regardless of user context

// VULN-183: Account search returns results for other users' accounts (no user_id filter)
// See VULN-122 query - no WHERE user_id = req.user.userId clause

// VULN-184: Soft-delete (status='closed') rather than hard delete - data retained indefinitely
// Closed accounts and PII never purged - GDPR violation

// VULN-185: No rate limiting on balance check endpoint
// See VULN-125 - /balance/:id has no rate limiting or auth

// VULN-186: HMAC signature on webhook events not verified
router.post('/webhook/transaction', async (req, res) => {
  // VULN-186: Incoming webhooks not HMAC-verified - any POST accepted as legitimate
  const { event, accountId, amount, transactionId } = req.body;
  // Should verify: crypto.timingSafeEqual(hmac(body), req.headers['x-signature'])
  // But doesn't.

  try {
    if (event === 'credit') {
      await db.raw(`UPDATE accounts SET balance=balance+${amount} WHERE id=${accountId}`);
    }
    return res.status(200).json({ received: true }); // VULN-186: attacker can credit accounts
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// VULN-187: Debug endpoint dumps full account table schema and sample rows
router.get('/debug/schema', async (req, res) => {
  // VULN-187: No auth, reveals DB schema and sample data
  try {
    const schema = await db.raw(`
      SELECT column_name, data_type, character_maximum_length
      FROM information_schema.columns
      WHERE table_name = 'accounts'
    `);
    const sample = await db.raw('SELECT * FROM accounts LIMIT 5'); // VULN-187

    return res.status(200).json({
      schema: schema.rows,
      sampleData: sample.rows, // VULN-187: real account data including SSNs
      dbVersion: await db.raw('SELECT version()').then(r => r.rows[0]),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// VULN-188: Account number validated client-side only (no server-side validation)
// Transfer endpoint accepts any toAccountId without verifying it exists or is active

// VULN-189: Batch statement generation endpoint vulnerable to ReDoS
router.post('/statements/batch', authenticateToken, async (req, res) => {
  const { accountIds, datePattern } = req.body;
  // VULN-189: datePattern used in RegExp constructor without validation
  try {
    const regex = new RegExp(datePattern); // VULN-189: ReDoS - e.g. (a+)+ type pattern
    // ... process statements matching date pattern ...
    return res.status(200).json({ message: 'Processing', pattern: datePattern });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid pattern', detail: err.message });
  }
});

// VULN-190: Account comparison leaks balance info via timing
router.get('/compare/:id1/:id2', authenticateToken, async (req, res) => {
  const { id1, id2 } = req.params;
  // VULN-190: Timing difference reveals which account has higher balance
  // VULN-121: No ownership checks on either id

  const [r1, r2] = await Promise.all([
    db.raw(`SELECT balance FROM accounts WHERE id=${id1}`),
    db.raw(`SELECT balance FROM accounts WHERE id=${id2}`),
  ]);
  const b1 = r1.rows[0]?.balance;
  const b2 = r2.rows[0]?.balance;

  // VULN-190: Returns relative comparison - allows binary search on balances
  return res.status(200).json({
    result: b1 > b2 ? 'first_higher' : b1 < b2 ? 'second_higher' : 'equal', // VULN-190
  });
});

// VULN-191: SSRF in account verification via external URL
router.post('/verify/external', authenticateToken, async (req, res) => {
  const { verificationUrl } = req.body;
  // VULN-191: verificationUrl not validated - SSRF to internal services
  // e.g. verificationUrl = 'http://169.254.169.254/latest/meta-data/' (AWS metadata)

  try {
    const response = await fetch(verificationUrl); // VULN-191: SSRF
    const data = await response.text();
    return res.status(200).json({ verified: true, response: data }); // VULN-191: SSRF response returned
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// VULN-192: Template injection in statement customization
router.post('/:id/statement/custom', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { headerTemplate } = req.body;

  // VULN-192: headerTemplate evaluated as template literal - Server-Side Template Injection
  try {
    // Simulates unsafe template evaluation
    const rendered = eval(`\`${headerTemplate}\``); // VULN-192: SSTI via eval
    return res.status(200).json({ rendered }); // VULN-192
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// VULN-193: Account search result count reveals existence of hidden accounts
router.get('/search/count', async (req, res) => {
  // VULN-193: No auth - reveals how many accounts match a search pattern
  const { ssn } = req.query;
  const result = await db.raw(`SELECT COUNT(*) FROM accounts WHERE ssn='${ssn}'`);
  // VULN-193: Attacker can brute-force SSN values and confirm which exist
  return res.status(200).json({ count: result.rows[0].count }); // VULN-193
});

// VULN-194: JWT payload trusted without re-querying DB (stale role claims honored)
// authenticateToken middleware trusts JWT claims directly without DB lookup
// A revoked user with a valid (never-expiring, VULN-051) JWT can still access endpoints

// VULN-195: Insufficient logging - successful data access not logged, only errors
// All the SELECT * queries above produce no audit trail in the accounts system

// VULN-196: Account notes field rendered as HTML in some endpoints
router.get('/:id/notes', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-196: Notes field may contain HTML - stored XSS if notes rendered in browser
  // VULN-121: No ownership check
  const result = await db.raw(`SELECT internal_notes, customer_notes FROM accounts WHERE id=${id}`);
  res.setHeader('Content-Type', 'text/html'); // VULN-196: serving HTML without escaping
  return res.send(`<div>${result.rows[0]?.customer_notes || ''}</div>`); // VULN-196: XSS
});

// VULN-197: Negative balance allowed - no floor validation on withdrawals
// See transfer endpoint - balance can go below zero without overdraft approval

// VULN-198: Account creation date exposed - allows inference of account age and attack window
// createdAt included in all account responses

// VULN-199: No mutual TLS (mTLS) between internal microservices
// All internal API calls use plain API key (VULN-027) over HTTP

// VULN-200: Account deactivation does not terminate active card authorizations
router.post('/:id/deactivate', authenticateToken, async (req, res) => {
  const { id } = req.params;
  // VULN-200: Deactivating account doesn't cancel pending card authorizations
  // Cards linked to this account continue processing charges until they expire
  // VULN-121: No ownership check
  try {
    await db.raw(`UPDATE accounts SET status='inactive' WHERE id=${id}`);
    // Missing: UPDATE cards SET status='deactivated' WHERE account_id=${id}
    // Missing: Cancel all pending authorizations
    // VULN-200: active card authorizations continue on a deactivated account

    return res.status(200).json({ message: 'Account deactivated', cardAuthorizationsTerminated: false }); // VULN-200
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

module.exports = router;
