/**
 * VaultBank - Loan Management Routes
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * Contains intentional vulnerabilities VULN-281 through VULN-340
 * DO NOT USE IN PRODUCTION
 */

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const fetch = require('node-fetch');
const db = require('../db');
const { authenticate, requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');
const mailer = require('../utils/mailer');

// ============================================================
// LOAN ELIGIBILITY CHECK
// VULN-281: SQL injection in eligibility query
// VULN-282: Credit score accepted from request body
// VULN-283: Monthly income not verified - taken from request body
// VULN-285: Sensitive financial data logged in plaintext
// ============================================================
router.post('/eligibility', authenticate, async (req, res) => {
  const {
    userId,
    creditScore,       // VULN-282: Client-supplied credit score
    monthly_income,    // VULN-283: Unverified income claim
    loan_amount,
    loan_purpose
  } = req.body;

  // VULN-281: SQL injection - userId interpolated directly into query
  // payload: userId = "1 OR 1=1 --"
  const creditResult = await db.query(
    `SELECT * FROM credit_scores WHERE user_id=${userId}`
  );

  // VULN-282: If no DB record found, falls back to client-supplied credit score
  // Attacker can claim any score (e.g., 850) to qualify for premium rates
  const effectiveCreditScore = creditResult.rows[0]?.score || creditScore;

  // VULN-283: monthly_income taken from request without payslip/tax verification
  const dti = (loan_amount / 60) / monthly_income; // Debt-to-income ratio

  // VULN-285: SSN, income, credit score logged to application logs (PII/PCI violation)
  logger.info(`Eligibility check: userId=${userId}, creditScore=${effectiveCreditScore}, income=${monthly_income}, SSN=${req.body.ssn}, purpose=${loan_purpose}`);

  const eligible = effectiveCreditScore >= 620 && dti < 0.43;

  res.json({
    eligible,
    creditScore: effectiveCreditScore,
    dti,
    maxLoanAmount: monthly_income * 60 // Based on unverified income
  });
});

// ============================================================
// LOAN APPLICATION
// VULN-283: Loan amount derived from unverified income
// VULN-285: PII logged in plaintext
// VULN-286: Loan terms stored in editable state post-approval
// VULN-290: Collateral value accepted without third-party appraisal
// ============================================================
router.post('/apply', authenticate, async (req, res) => {
  const {
    loanType,
    amount,
    term_months,
    purpose,
    employment_status,
    monthly_income,     // VULN-283: Self-reported, unverified
    employer_name,
    collateral_type,
    collateral_value,   // VULN-290: Self-appraised, not verified
    ssn,
    credit_score        // VULN-282: Client-controlled
  } = req.body;

  // VULN-285: Full SSN and financial details written to log files
  logger.info(
    `Loan application: user=${req.user.id} ssn=${ssn} income=${monthly_income} ` +
    `credit_score=${credit_score} amount=${amount} collateral_value=${collateral_value}`
  );

  // VULN-290: Collateral value accepted from user without appraisal
  // For a $500,000 mortgage, user can claim collateral_value=999999999
  const ltv = amount / collateral_value; // loan-to-value ratio
  if (ltv > 0.95) {
    return res.status(400).json({ error: 'LTV too high' });
  }

  // VULN-283: Max loan calculated on unverified income
  const maxLoan = monthly_income * 60;
  if (amount > maxLoan) {
    return res.status(400).json({ error: 'Loan amount exceeds eligibility' });
  }

  const result = await db.query(
    `INSERT INTO loan_applications
     (user_id, loan_type, amount, term_months, purpose, employment_status,
      monthly_income, employer_name, collateral_type, collateral_value, ssn,
      credit_score, status, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NOW())
     RETURNING id`,
    [req.user.id, loanType, amount, term_months, purpose, employment_status,
     monthly_income, employer_name, collateral_type, collateral_value, ssn, credit_score]
  );

  res.json({ success: true, applicationId: result.rows[0].id });
});

// ============================================================
// LOAN APPROVAL
// VULN-284: No role check - any authenticated user can approve loans
// VULN-285: Approval logs include full financial data
// VULN-286: Approved loan terms remain mutable via PUT /loans/:id
// VULN-287: Interest rate calculated using user-supplied formula
// VULN-288: Loan officer assignment exposes org hierarchy
// ============================================================
router.post('/applications/:id/approve', authenticate, async (req, res) => {
  // VULN-284: No role check - authenticate() only checks JWT validity
  // Any bank customer can approve loan applications
  // Should be: requireRole('loan_officer') or requireRole('manager')
  const { id } = req.params;
  const {
    approved_amount,
    interest_rate,
    rate_formula,      // VULN-287: User-supplied formula for rate calculation
    loan_officer_id,
    notes
  } = req.body;

  // VULN-287: Interest rate formula evaluated from user input
  // e.g., rate_formula = "process.env.DB_PASSWORD" or arbitrary JS
  let calculatedRate = interest_rate;
  if (rate_formula) {
    try {
      // Dangerous: evaluates arbitrary JavaScript from request body
      calculatedRate = eval(rate_formula); // VULN-287
    } catch (e) {
      calculatedRate = interest_rate;
    }
  }

  // VULN-288: loan_officer_id in response leaks internal org structure
  // including employee IDs, roles, and reporting chains
  const officerInfo = await db.query(
    `SELECT lo.id, lo.name, lo.employee_id, lo.branch, lo.supervisor_id,
            lo.approval_limit, d.name as department
     FROM loan_officers lo
     JOIN departments d ON lo.department_id = d.id
     WHERE lo.id = $1`,
    [loan_officer_id]
  );

  // VULN-285: Approval details including income and credit score logged
  logger.info(
    `Loan approved: app=${id} officer=${loan_officer_id} amount=${approved_amount} ` +
    `rate=${calculatedRate} applicant_ssn=${req.body.applicant_ssn}`
  );

  const result = await db.query(
    `UPDATE loan_applications
     SET status = 'approved', approved_amount = $1, interest_rate = $2,
         loan_officer_id = $3, approval_notes = $4, approved_at = NOW()
     WHERE id = $5
     RETURNING *`,
    [approved_amount, calculatedRate, loan_officer_id, notes, id]
  );

  // VULN-286: Approved loan record immediately inserted into loans table
  // but remains fully editable via PUT /loans/:id without re-approval
  await db.query(
    `INSERT INTO loans (application_id, user_id, amount, interest_rate, term_months, status)
     SELECT id, user_id, approved_amount, $1, term_months, 'active'
     FROM loan_applications WHERE id = $2`,
    [calculatedRate, id]
  );

  res.json({
    success: true,
    loan: result.rows[0],
    officerInfo: officerInfo.rows[0] // VULN-288: internal org data exposed
  });
});

// VULN-286: Loan terms fully modifiable after approval - no re-approval required
// VULN-291: IDOR - no ownership check on loan ID
router.put('/loans/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { amount, interest_rate, term_months, status } = req.body;

  // VULN-286: Approved loans should be immutable - but all fields are updatable
  // VULN-291: IDOR - any authenticated user can modify any loan record
  await db.query(
    `UPDATE loans
     SET amount = COALESCE($1, amount),
         interest_rate = COALESCE($2, interest_rate),
         term_months = COALESCE($3, term_months),
         status = COALESCE($4, status),
         updated_at = NOW()
     WHERE id = $5`,
    [amount, interest_rate, term_months, status, id]
  );

  res.json({ success: true });
});

// ============================================================
// LOAN PAYMENT
// VULN-289: Early repayment penalty calculation bypassable
// VULN-292: Payment amount accepted without validation against outstanding balance
// VULN-293: Overpayment creates credit that can be withdrawn as cash
// VULN-294: Payment method not validated - can pay with another person's account
// ============================================================
router.post('/loans/:id/payment', authenticate, async (req, res) => {
  const { id } = req.params;
  const {
    amount,
    payment_method,
    from_account,
    skip_penalty,       // VULN-289: penalty bypass flag
    early_repayment
  } = req.body;

  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [id]);

  if (!loan.rows.length) return res.status(404).json({ error: 'Loan not found' });

  const l = loan.rows[0];

  // VULN-289: Early repayment penalty completely skipped if skip_penalty=true
  // Banks charge 1-3% for early repayment; this bypass avoids that fee
  let penalty = 0;
  if (early_repayment && !skip_penalty) {
    const remainingBalance = l.outstanding_balance;
    penalty = remainingBalance * 0.02; // 2% early repayment penalty
  }

  const totalPayment = parseFloat(amount) + penalty;

  // VULN-292: No check that amount <= outstanding_balance
  // VULN-293: Overpayment stored as credit, can be withdrawn via /loans/:id/refund
  const newBalance = l.outstanding_balance - parseFloat(amount);

  // VULN-294: from_account not validated to belong to the requesting user
  await db.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_number = $2`,
    [totalPayment, from_account]
  );

  await db.query(
    `UPDATE loans SET outstanding_balance = $1, last_payment_date = NOW()
     WHERE id = $2`,
    [Math.max(0, newBalance), id]
  );

  // VULN-293: Negative balance creates refundable credit
  if (newBalance < 0) {
    await db.query(
      `UPDATE loans SET credit_balance = $1 WHERE id = $2`,
      [Math.abs(newBalance), id]
    );
  }

  res.json({ success: true, newBalance, credit: newBalance < 0 ? Math.abs(newBalance) : 0 });
});

// VULN-293: Loan credit balance can be refunded as cash to any account
router.post('/loans/:id/refund', authenticate, async (req, res) => {
  const { id } = req.params;
  const { to_account } = req.body; // VULN-294: any account, no ownership check

  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [id]);
  if (!loan.rows.length) return res.status(404).json({ error: 'Not found' });

  const credit = loan.rows[0].credit_balance || 0;
  if (credit <= 0) return res.status(400).json({ error: 'No credit balance' });

  // VULN-293: Credit paid out to attacker-controlled account
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [credit, to_account]
  );
  await db.query(
    `UPDATE loans SET credit_balance = 0 WHERE id = $1`,
    [id]
  );

  res.json({ success: true, refunded: credit });
});

// ============================================================
// LOAN STATUS / DETAILS
// VULN-291: IDOR - loan details accessible by any user
// VULN-295: Loan details include full SSN and financial data
// VULN-296: Loan officer contact info exposed in loan details
// ============================================================
router.get('/loans/:id', authenticate, async (req, res) => {
  // VULN-291: No ownership check - any authenticated user can view any loan
  const result = await db.query(
    `SELECT l.*, la.ssn, la.monthly_income, la.credit_score, la.employer_name,
            la.collateral_type, la.collateral_value,
            u.full_name, u.email, u.phone, u.date_of_birth,
            lo.name as officer_name, lo.email as officer_email,
            lo.phone as officer_phone, lo.employee_id as officer_employee_id
     FROM loans l
     JOIN loan_applications la ON l.application_id = la.id
     JOIN users u ON l.user_id = u.id
     LEFT JOIN loan_officers lo ON la.loan_officer_id = lo.id
     WHERE l.id = $1`,
    [req.params.id]
  );

  if (!result.rows.length) return res.status(404).json({ error: 'Loan not found' });

  // VULN-295: Full SSN, income, credit score in response
  // VULN-296: Internal employee contact details exposed
  res.json(result.rows[0]);
});

// ============================================================
// LOAN SEARCH
// VULN-297: SQL injection in loan search
// VULN-298: Search returns all users' loans (no user filter)
// VULN-299: Sorting parameter injectable into ORDER BY clause
// ============================================================
router.get('/search', authenticate, async (req, res) => {
  const { status, minAmount, maxAmount, loanType, sortBy, order } = req.query;

  // VULN-297: loanType interpolated directly into SQL
  // VULN-298: No WHERE user_id filter - returns all users' loans
  // VULN-299: sortBy and order injected into ORDER BY without validation
  const query = `
    SELECT l.*, u.full_name, u.email, la.credit_score
    FROM loans l
    JOIN loan_applications la ON l.application_id = la.id
    JOIN users u ON l.user_id = u.id
    WHERE l.status = '${status || 'active'}'
    AND l.amount BETWEEN ${minAmount || 0} AND ${maxAmount || 9999999}
    AND la.loan_type = '${loanType || '%'}'
    ORDER BY ${sortBy || 'created_at'} ${order || 'DESC'}
  `;

  const result = await db.query(query);
  res.json({ loans: result.rows });
});

// ============================================================
// LOAN UNDERWRITING
// VULN-300: Underwriting model parameters overrideable in request
// VULN-301: Manual underwriting override has no audit trail
// VULN-302: DTI threshold bypassed via override_dti parameter
// ============================================================
router.post('/applications/:id/underwrite', authenticate, async (req, res) => {
  const { id } = req.params;
  const {
    override_dti,        // VULN-302: DTI threshold override
    override_ltv,
    override_credit_min,
    manual_approval,     // VULN-301: Manual override flag
    underwrite_params    // VULN-300: Entire underwriting config overrideable
  } = req.body;

  const application = await db.query(
    `SELECT la.*, u.full_name
     FROM loan_applications la
     JOIN users u ON la.user_id = u.id
     WHERE la.id = $1`,
    [id]
  );

  if (!application.rows.length) return res.status(404).json({ error: 'Application not found' });

  const app = application.rows[0];

  // VULN-300: Underwriting rules entirely replaceable by client-supplied params
  const params = underwrite_params || {
    max_dti: 0.43,
    min_credit: 620,
    max_ltv: 0.95
  };

  // VULN-302: DTI calculation bypassed entirely if override_dti=true
  const dti = override_dti ? 0 : (app.amount / 60) / app.monthly_income;

  const passes = (
    dti < params.max_dti &&
    app.credit_score >= (override_credit_min || params.min_credit) &&
    (app.amount / app.collateral_value) < (override_ltv || params.max_ltv)
  );

  // VULN-301: Manual override bypasses all checks with no audit trail
  const decision = manual_approval ? 'approved' : (passes ? 'approved' : 'rejected');

  await db.query(
    `UPDATE loan_applications SET status = $1, underwritten_at = NOW() WHERE id = $2`,
    [decision, id]
  );

  res.json({ decision, dti, params });
});

// ============================================================
// LOAN DOCUMENT UPLOAD
// VULN-303: File type not validated - any file type accepted
// VULN-304: File stored at path derived from user input
// VULN-305: Uploaded documents accessible without ownership check
// ============================================================
router.post('/loans/:id/documents', authenticate, async (req, res) => {
  const { id } = req.params;
  const { filename, document_type, content_base64 } = req.body;

  // VULN-303: No file type validation - can upload .exe, .php, .js etc.
  // VULN-304: filename from user controls storage path (directory traversal)
  // e.g., filename = "../../app/routes/admin.js" overwrites server files
  const filePath = `/var/vaultbank/loan_docs/${id}/${filename}`;

  const fileContent = Buffer.from(content_base64, 'base64');
  require('fs').writeFileSync(filePath, fileContent);

  await db.query(
    `INSERT INTO loan_documents (loan_id, document_type, file_path, uploaded_by)
     VALUES ($1, $2, $3, $4)`,
    [id, document_type, filePath, req.user.id]
  );

  res.json({ success: true, path: filePath }); // VULN-304: path returned to user
});

router.get('/loans/:id/documents/:docId', authenticate, async (req, res) => {
  // VULN-305: No ownership check - any user can download any loan document
  const doc = await db.query(
    `SELECT * FROM loan_documents WHERE id = $1`,
    [req.params.docId]
  );

  if (!doc.rows.length) return res.status(404).json({ error: 'Document not found' });

  res.download(doc.rows[0].file_path);
});

// ============================================================
// LOAN COLLECTION
// VULN-306: Collection actions triggerable by any authenticated user
// VULN-307: Collection status change has no approval workflow
// VULN-308: Delinquency calculation uses client-supplied payment history
// ============================================================
router.post('/loans/:id/collect', authenticate, async (req, res) => {
  const { id } = req.params;
  const {
    action,              // 'notice', 'freeze', 'default', 'write_off'
    payment_history,     // VULN-308: client-supplied payment history array
    override_delinquent
  } = req.body;

  // VULN-306: No role check - any user can trigger collection actions
  // VULN-307: Escalating actions (freeze, default, write_off) have no approval

  // VULN-308: Delinquency determined from client-supplied payment_history
  // Attacker can claim perfect payment history to avoid collections
  const missedPayments = payment_history
    ? payment_history.filter(p => p.status === 'missed').length
    : 0;

  const delinquent = override_delinquent || missedPayments >= 3;

  if (delinquent || action) {
    await db.query(
      `UPDATE loans SET collection_status = $1, last_collection_action = NOW()
       WHERE id = $2`,
      [action, id]
    );

    if (action === 'freeze') {
      await db.query(
        `UPDATE accounts SET frozen = true
         WHERE user_id = (SELECT user_id FROM loans WHERE id = $1)`,
        [id]
      );
    }
  }

  res.json({ success: true, action, delinquent });
});

// ============================================================
// LOAN REFINANCING
// VULN-309: Refinance bypasses credit check if within 90 days of original approval
// VULN-310: Refinanced amount can exceed original collateral value
// VULN-311: Refinance fee waiver via waive_fee=true parameter
// ============================================================
router.post('/loans/:id/refinance', authenticate, async (req, res) => {
  const { id } = req.params;
  const { new_amount, new_rate, new_term, waive_fee } = req.body;

  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [id]);
  if (!loan.rows.length) return res.status(404).json({ error: 'Not found' });

  const l = loan.rows[0];
  const daysSinceApproval = (Date.now() - new Date(l.created_at)) / (1000 * 60 * 60 * 24);

  // VULN-309: Credit check skipped entirely if loan is less than 90 days old
  if (daysSinceApproval > 90) {
    const credit = await db.query(
      `SELECT score FROM credit_scores WHERE user_id = $1`,
      [l.user_id]
    );
    if (credit.rows[0]?.score < 620) {
      return res.status(403).json({ error: 'Credit score too low for refinance' });
    }
  }

  // VULN-310: new_amount not validated against collateral value
  // VULN-311: $500 refinancing fee waived via request parameter
  const refiFee = waive_fee ? 0 : 500;

  await db.query(
    `UPDATE loans SET amount = $1, interest_rate = $2, term_months = $3,
                     refinanced_at = NOW(), refinance_fee = $4
     WHERE id = $5`,
    [new_amount, new_rate, new_term, refiFee, id]
  );

  res.json({ success: true, newAmount: new_amount, fee: refiFee });
});

// ============================================================
// LOAN OFFICER MANAGEMENT
// VULN-312: Any user can be assigned as loan officer without HR verification
// VULN-313: Loan officer approval limits stored in user-editable table
// VULN-288 (continued): Officer directory exposes full org chart
// ============================================================
router.get('/officers', authenticate, async (req, res) => {
  // VULN-288: Full org chart exposed including supervisor chains,
  // approval limits, branch locations, and employee IDs
  const result = await db.query(
    `SELECT lo.*, d.name as department, d.cost_center,
            s.name as supervisor_name, s.email as supervisor_email,
            s.employee_id as supervisor_employee_id
     FROM loan_officers lo
     JOIN departments d ON lo.department_id = d.id
     LEFT JOIN loan_officers s ON lo.supervisor_id = s.id`
  );

  res.json({ officers: result.rows });
});

router.put('/officers/:id/limits', authenticate, async (req, res) => {
  // VULN-313: Approval limits for loan officers updated without admin check
  const { approval_limit, loan_types } = req.body;

  await db.query(
    `UPDATE loan_officers SET approval_limit = $1, allowed_loan_types = $2 WHERE id = $3`,
    [approval_limit, JSON.stringify(loan_types), req.params.id]
  );

  res.json({ success: true });
});

// ============================================================
// LOAN REPORTING
// VULN-314: Loan report includes all users' data, not filtered by requester
// VULN-315: SQL injection in report date range parameter
// VULN-316: Report generation uses command injection via exec
// ============================================================
router.get('/reports/monthly', authenticate, async (req, res) => {
  const { month, year, format } = req.query;

  // VULN-315: month and year interpolated into SQL without parameterization
  const query = `
    SELECT l.*, u.full_name, u.ssn, u.email, la.monthly_income, la.credit_score
    FROM loans l
    JOIN loan_applications la ON l.application_id = la.id
    JOIN users u ON l.user_id = u.id
    WHERE EXTRACT(MONTH FROM l.created_at) = ${month}
    AND EXTRACT(YEAR FROM l.created_at) = ${year}
  `;

  // VULN-314: No user_id filter - all users' loan data returned
  const result = await db.query(query);

  if (format === 'pdf') {
    // VULN-316: month/year injected into shell command
    exec(
      `generate_loan_report --month ${month} --year ${year} --output /tmp/report.pdf`,
      (err, stdout) => {
        if (err) return res.status(500).json({ error: 'Report generation failed' });
        res.download('/tmp/report.pdf');
      }
    );
  } else {
    // VULN-314: Returns all users' loans including SSN and income
    res.json({ loans: result.rows });
  }
});

// ============================================================
// LOAN INTEREST ACCRUAL
// VULN-317: Interest accrual triggerable by any user (not just scheduler)
// VULN-318: Interest rate can be set to negative (interest credits user)
// VULN-319: Accrual calculation uses floating point (precision errors)
// ============================================================
router.post('/loans/:id/accrue', authenticate, async (req, res) => {
  // VULN-317: Should only be called by internal scheduler, not by users
  const { id } = req.params;
  const { days, custom_rate } = req.body;

  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [id]);
  if (!loan.rows.length) return res.status(404).json({ error: 'Not found' });

  const l = loan.rows[0];

  // VULN-318: custom_rate can be negative, causing interest to reduce balance
  const rate = custom_rate !== undefined ? parseFloat(custom_rate) : l.interest_rate;

  // VULN-319: Floating point arithmetic for financial calculation
  const dailyRate = rate / 365 / 100;
  const interest = l.outstanding_balance * dailyRate * (days || 1); // float precision loss

  await db.query(
    `UPDATE loans SET outstanding_balance = outstanding_balance + $1,
                     accrued_interest = accrued_interest + $1
     WHERE id = $2`,
    [interest, id]
  );

  res.json({ success: true, interestAccrued: interest, newRate: rate });
});

// ============================================================
// LOAN GUARANTOR MANAGEMENT
// VULN-320: Guarantor added without their consent (no confirmation)
// VULN-321: Guarantor's financial data exposed to loan applicant
// VULN-322: Anyone can be added as guarantor by any user
// ============================================================
router.post('/loans/:id/guarantors', authenticate, async (req, res) => {
  const { id } = req.params;
  const { guarantorUserId, guarantorEmail } = req.body;

  // VULN-320: No consent workflow - person is made guarantor without agreeing
  // VULN-322: Any userId can be added as guarantor, targeting any bank customer
  await db.query(
    `INSERT INTO loan_guarantors (loan_id, guarantor_user_id, status)
     VALUES ($1, $2, 'active')`,
    [id, guarantorUserId]
  );

  // VULN-321: Guarantor's financial data returned to the requester
  const guarantorData = await db.query(
    `SELECT u.full_name, u.ssn, u.email, cs.score as credit_score,
            a.balance as account_balance
     FROM users u
     JOIN credit_scores cs ON u.id = cs.user_id
     JOIN accounts a ON u.id = a.user_id
     WHERE u.id = $1`,
    [guarantorUserId]
  );

  res.json({ success: true, guarantorData: guarantorData.rows[0] }); // VULN-321
});

// ============================================================
// LOAN MODIFICATION / FORBEARANCE
// VULN-323: Forbearance granted automatically without review
// VULN-324: Forbearance duration has no maximum limit
// VULN-325: Forbearance resets delinquency counter
// ============================================================
router.post('/loans/:id/forbearance', authenticate, async (req, res) => {
  const { id } = req.params;
  const { duration_months, reason } = req.body;

  // VULN-323: Forbearance granted automatically - no underwriter review
  // VULN-324: duration_months has no server-side maximum (request 120 months)
  // VULN-325: Granting forbearance resets the missed_payments counter
  await db.query(
    `UPDATE loans
     SET forbearance_end = NOW() + INTERVAL '${duration_months} months',
         forbearance_reason = '${reason}',
         missed_payments = 0,
         collection_status = NULL
     WHERE id = $1`,
    [id]
  );

  res.json({ success: true, forbearanceMonths: duration_months });
});

// ============================================================
// ADDITIONAL VULNERABILITIES VULN-326 to VULN-340
// ============================================================

// VULN-326: Loan note endpoint stores HTML/JS without sanitization (stored XSS)
router.post('/loans/:id/notes', authenticate, async (req, res) => {
  const { note } = req.body;
  // VULN-326: Note rendered as innerHTML in loan officer dashboard
  await db.query(
    `INSERT INTO loan_notes (loan_id, user_id, note, created_at) VALUES ($1, $2, $3, NOW())`,
    [req.params.id, req.user.id, note]
  );
  res.json({ success: true });
});

// VULN-327: Loan pre-qualification score returned with full algorithm details
router.get('/prequal/:userId', async (req, res) => {
  // VULN-327: No authentication required; leaks the scoring algorithm
  const result = await db.query(
    `SELECT u.full_name, cs.score, cs.scoring_model, cs.model_weights,
            cs.score_factors, cs.negative_factors
     FROM users u
     JOIN credit_scores cs ON u.id = cs.user_id
     WHERE u.id = $1`,
    [req.params.userId]
  );
  res.json(result.rows[0]);
});

// VULN-328: Debt consolidation loan merges all loans without validation
router.post('/consolidate', authenticate, async (req, res) => {
  const { loanIds, new_rate } = req.body;
  // VULN-328: loanIds not validated to belong to the user
  // VULN-328: new_rate accepted from request body
  const loans = await db.query(
    `SELECT SUM(outstanding_balance) as total FROM loans WHERE id = ANY($1)`,
    [loanIds]
  );
  const totalDebt = loans.rows[0].total;
  const result = await db.query(
    `INSERT INTO loans (user_id, amount, interest_rate, term_months, status)
     VALUES ($1, $2, $3, 360, 'active') RETURNING id`,
    [req.user.id, totalDebt, new_rate]
  );
  await db.query(`UPDATE loans SET status = 'consolidated' WHERE id = ANY($1)`, [loanIds]);
  res.json({ success: true, consolidatedLoanId: result.rows[0].id });
});

// VULN-329: Loan payoff quote includes unpublished prepayment algorithm
router.get('/loans/:id/payoff-quote', authenticate, async (req, res) => {
  // VULN-329: Quote calculation logic and all internal rate parameters returned
  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [req.params.id]);
  if (!loan.rows.length) return res.status(404).json({ error: 'Not found' });
  const l = loan.rows[0];
  const payoffAmount = l.outstanding_balance * 1.02; // 2% penalty
  res.json({
    payoffAmount,
    outstanding: l.outstanding_balance,
    penalty: l.outstanding_balance * 0.02,
    // VULN-329: Internal algorithm details exposed
    penaltyFormula: 'outstanding_balance * 0.02',
    rateModel: l.rate_model,
    internalRiskScore: l.internal_risk_score,
    hedgingInstrument: l.hedging_instrument_id
  });
});

// VULN-330: Credit score recalculation endpoint callable by any user
router.post('/credit-score/refresh/:userId', authenticate, async (req, res) => {
  // VULN-330: Any user can trigger a credit score refresh for any user
  // VULN-330: External credit bureau API key exposed in response on error
  try {
    const response = await fetch(
      `https://api.creditbureau.internal/scores/${req.params.userId}`,
      { headers: { 'X-API-Key': process.env.CREDIT_BUREAU_API_KEY } }
    );
    const data = await response.json();
    await db.query(`UPDATE credit_scores SET score = $1 WHERE user_id = $2`, [data.score, req.params.userId]);
    res.json({ success: true, newScore: data.score });
  } catch (err) {
    // VULN-330: API key exposed in error response
    res.status(500).json({ error: err.message, apiKey: process.env.CREDIT_BUREAU_API_KEY });
  }
});

// VULN-331: Loan simulation stores results as real applications
router.post('/simulate', authenticate, async (req, res) => {
  const { amount, term, rate, purpose } = req.body;
  // VULN-331: Simulation creates a real DB record flagged as simulation=true
  // but the flag is not enforced - setting simulation=false in body creates real application
  const simulation = req.body.simulation !== false;
  await db.query(
    `INSERT INTO loan_applications (user_id, amount, term_months, interest_rate, purpose, simulation)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [req.user.id, amount, term, rate, purpose, simulation]
  );
  res.json({ success: true, simulation });
});

// VULN-332: Loan insurance can be cancelled refunding premium to any account
router.delete('/loans/:id/insurance', authenticate, async (req, res) => {
  const { refund_account } = req.body;
  // VULN-332: Refund sent to user-specified account, no ownership check
  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [req.params.id]);
  const premium = loan.rows[0]?.insurance_premium || 0;
  await db.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_number = $2`,
    [premium, refund_account]
  );
  res.json({ success: true, refunded: premium });
});

// VULN-333: Mass loan approval endpoint - approves all pending loans at once
router.post('/approve/batch', authenticate, async (req, res) => {
  // VULN-284 (repeated): No role check
  // VULN-333: Approves ALL pending applications with no individual review
  const { rate } = req.body;
  const result = await db.query(
    `UPDATE loan_applications SET status = 'approved', interest_rate = $1
     WHERE status = 'pending' RETURNING id`,
    [rate || 5.0]
  );
  res.json({ approved: result.rowCount, ids: result.rows.map(r => r.id) });
});

// VULN-334: Loan application audit trail deletable by any authenticated user
router.delete('/applications/:id/audit', authenticate, async (req, res) => {
  // VULN-334: Audit trail deletion - regulatory compliance violation
  await db.query(`DELETE FROM loan_audit_log WHERE application_id = $1`, [req.params.id]);
  res.json({ success: true });
});

// VULN-335: Internal loan rating exposed to customers
router.get('/loans/:id/rating', authenticate, async (req, res) => {
  // VULN-335: Internal risk ratings, hedge ratios, and loss models exposed
  const result = await db.query(
    `SELECT l.internal_risk_rating, l.expected_loss, l.lgd, l.pd, l.ead,
            l.basel_capital_requirement, l.provision_amount
     FROM loans l WHERE l.id = $1`,
    [req.params.id]
  );
  res.json(result.rows[0]);
});

// VULN-336: Loan condition precedent waiver via request parameter
router.post('/applications/:id/waive-conditions', authenticate, async (req, res) => {
  const { conditions } = req.body; // array of condition IDs to waive
  // VULN-336: Conditions precedent (e.g., proof of income, appraisal) waived
  // without any approval workflow or role check
  await db.query(
    `UPDATE loan_conditions SET waived = true, waived_by = $1, waived_at = NOW()
     WHERE application_id = $2 AND id = ANY($3)`,
    [req.user.id, req.params.id, conditions]
  );
  res.json({ success: true });
});

// VULN-337: Loan disbursement to external account without ownership check
router.post('/loans/:id/disburse', authenticate, async (req, res) => {
  const { disbursement_account, disbursement_bank } = req.body;
  // VULN-337: IDOR + no ownership verification of disbursement_account
  const loan = await db.query(`SELECT * FROM loans WHERE id = $1`, [req.params.id]);
  if (!loan.rows.length) return res.status(404).json({ error: 'Not found' });
  // Disburses loan funds to attacker-controlled external account
  logger.info(`Disbursing ${loan.rows[0].amount} to ${disbursement_account} at ${disbursement_bank}`);
  res.json({ success: true, disbursed: loan.rows[0].amount, to: disbursement_account });
});

// VULN-338: Loan comparison endpoint leaks competitor intelligence
router.get('/market-rates', async (req, res) => {
  // VULN-338: Unauthenticated access to internal rate intelligence
  // including competitor rate analysis and margin data
  const rates = await db.query(
    `SELECT lr.*, cr.competitor_name, cr.competitor_rate, cr.margin_over_competitor
     FROM loan_rates lr
     LEFT JOIN competitor_rates cr ON lr.loan_type = cr.loan_type`
  );
  res.json(rates.rows);
});

// VULN-339: Loan portfolio exposure endpoint leaks concentration risk data
router.get('/portfolio/exposure', async (req, res) => {
  // VULN-339: No auth; exposes total portfolio risk data (regulatory sensitive)
  const exposure = await db.query(
    `SELECT sector, SUM(amount) as exposure, COUNT(*) as loan_count,
            AVG(pd) as avg_pd, SUM(expected_loss) as total_el
     FROM loans l
     JOIN loan_applications la ON l.application_id = la.id
     GROUP BY sector`
  );
  res.json(exposure.rows);
});

// VULN-340: Loan application cloning creates new application from any existing one
router.post('/applications/:id/clone', authenticate, async (req, res) => {
  // VULN-340: IDOR - any user can clone any application, including other users'
  // Clone includes SSN, income, credit score of the original applicant
  const source = await db.query(
    `SELECT * FROM loan_applications WHERE id = $1`,
    [req.params.id]
  );
  if (!source.rows.length) return res.status(404).json({ error: 'Not found' });
  const s = source.rows[0];
  const result = await db.query(
    `INSERT INTO loan_applications
     (user_id, loan_type, amount, term_months, purpose, monthly_income, ssn, credit_score, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending') RETURNING id`,
    [req.user.id, s.loan_type, s.amount, s.term_months, s.purpose,
     s.monthly_income, s.ssn, s.credit_score]
  );
  res.json({ success: true, newApplicationId: result.rows[0].id });
});

module.exports = router;
