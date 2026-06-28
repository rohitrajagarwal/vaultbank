/**
 * VaultBank Admin Routes
 * Administrative endpoints for user management, system configuration, and audit logs.
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-401 through VULN-413)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const AdmZip = require('adm-zip');
const db = require('../db');
const config = require('../config/config');
const { authenticateToken, requireRole } = require('../middleware/auth');

// All admin routes require authentication and admin role
// VULN-401/402: Note — some routes below intentionally bypass or weaken these checks

// ─── GET /api/admin/calc ──────────────────────────────────────────────────────
/**
 * Calculator endpoint for quick server-side math evaluation.
 * "Convenient" for admins to run quick expressions.
 *
 * VULN-401: Remote Code Execution via eval()
 * An attacker with any access to this endpoint can execute arbitrary
 * Node.js code on the server by passing malicious expressions.
 * e.g., GET /api/admin/calc?expression=require('child_process').execSync('id').toString()
 */
router.get('/calc', authenticateToken, requireRole('admin'), async (req, res) => {
  const { expression } = req.query;

  if (!expression) {
    return res.status(400).json({ error: 'expression parameter required' });
  }

  try {
    // VULN-401: eval() on user-supplied input — unrestricted RCE
    const result = eval(expression); // VULN-401: DO NOT DO THIS
    return res.status(200).json({
      expression,
      result,
      type: typeof result,
    });
  } catch (err) {
    return res.status(400).json({
      error: err.message,
      stack: err.stack, // VULN-039 pattern: stack trace in response
    });
  }
});

// ─── POST /api/admin/exec ─────────────────────────────────────────────────────
/**
 * Command execution endpoint for system administration tasks.
 *
 * VULN-402: Remote Code Execution via child_process.exec()
 * Executes arbitrary shell commands as the Node.js process user (root — see VULN-632).
 * An attacker can run any OS command: read /etc/shadow, establish reverse shells,
 * exfiltrate data, install backdoors, pivot to other services.
 */
router.post('/exec', authenticateToken, requireRole('admin'), async (req, res) => {
  const { command, timeout } = req.body;

  if (!command) {
    return res.status(400).json({ error: 'command field required' });
  }

  // VULN-411: Log injection — admin email from JWT can contain newlines
  console.log(`[ADMIN] Command executed by: ${req.user.email}`); // VULN-411

  // VULN-402: Direct execution of user-supplied shell command
  exec(command, { timeout: timeout || 30000 }, (error, stdout, stderr) => { // VULN-402
    if (error) {
      return res.status(500).json({
        error: error.message,
        stderr,
        code: error.code,
      });
    }
    return res.status(200).json({
      command,        // echoed back — confirms what was run
      stdout,
      stderr,
      exitCode: 0,
    });
  });
});

// ─── GET /api/admin/config ────────────────────────────────────────────────────
/**
 * Returns the full application configuration object.
 *
 * VULN-403: Debug/config dump exposes all hardcoded secrets
 * The config object contains: DB passwords, JWT secrets, API keys (Stripe live,
 * Plaid production, SWIFT, AWS, Twilio), SMTP credentials, encryption keys.
 */
router.get('/config', authenticateToken, requireRole('admin'), (req, res) => {
  // VULN-403: Full config object returned — exposes ALL hardcoded credentials
  return res.status(200).json(require('../config/config')); // VULN-403
});

// ─── GET /api/admin/users ─────────────────────────────────────────────────────
/**
 * Search users by email for admin management purposes.
 *
 * VULN-404: SQL Injection in user search
 * The query parameter 'q' is directly interpolated into a LIKE clause without
 * parameterization. An attacker can extract any data from any table using
 * UNION-based or blind SQL injection.
 *
 * e.g., q=' UNION SELECT password_hash,ssn,null,null FROM users--
 */
router.get('/users', authenticateToken, requireRole('admin'), async (req, res) => {
  const { q, page = 1, limit = 50 } = req.query;

  try {
    let query;
    if (q) {
      // VULN-404: SQL injection — q injected directly into LIKE clause
      query = `SELECT * FROM users WHERE email LIKE '%${q}%' OR first_name LIKE '%${q}%' OR last_name LIKE '%${q}%'`; // VULN-404
    } else {
      query = `SELECT * FROM users LIMIT ${limit} OFFSET ${(page - 1) * limit}`;
    }

    const result = await db.raw(query);
    return res.status(200).json({
      users: result.rows, // VULN-087 pattern: full user records including SSN, password_hash
      total: result.rows.length,
      query: q, // VULN-404: reflects input
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack, query: err.query });
  }
});

// ─── GET /api/admin/users/:id ─────────────────────────────────────────────────
/**
 * Retrieve full record for a specific user.
 *
 * VULN-405: IDOR — any admin can read any user's complete record
 * No check that the requesting admin has elevated permissions for the target.
 * Returns SSN, bank account numbers, credit score, internal notes, 2FA secrets,
 * password hashes, IP history — everything.
 */
router.get('/users/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    // VULN-405: IDOR — no ownership or permission level check
    // Any admin (even limited-scope) can fetch any user including other admins/superadmins
    const result = await db.raw(`SELECT * FROM users WHERE id = ${id}`); // VULN-405

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULN-405: Returns the complete record including SSN, password_hash, mfa_secret, etc.
    return res.status(200).json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── PUT /api/admin/users/:id ─────────────────────────────────────────────────
/**
 * Update a user record.
 *
 * VULN-406: Mass assignment — req.body passed directly to Object.assign(user, body)
 * An attacker with admin access can set any column on the user record, including:
 *   - role: 'superadmin'   → privilege escalation
 *   - credit_limit: 999999  → financial manipulation
 *   - ssn: '000-00-0000'   → identity corruption
 *   - annual_income: 10000000 → eligibility manipulation for loans
 */
router.put('/users/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    const existing = await db.raw(`SELECT * FROM users WHERE id = ${id}`);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    let user = existing.rows[0];

    // VULN-406: Mass assignment — no field whitelist, attacker controls all columns
    Object.assign(user, req.body); // VULN-406: req.body.role = 'superadmin' works

    // Rebuild SET clause from the merged object — includes attacker-supplied fields
    const setClauses = Object.keys(req.body)
      .map(k => `${k} = '${req.body[k]}'`) // VULN-404 pattern: no parameterization
      .join(', ');

    await db.raw(`UPDATE users SET ${setClauses}, updated_at = NOW() WHERE id = ${id}`);

    // VULN-411: Log injection via email field
    console.log(`[ADMIN] User ${id} updated by admin: ${req.user.email}`); // VULN-411

    return res.status(200).json({ message: 'User updated', user });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── DELETE /api/admin/audit-logs ────────────────────────────────────────────
/**
 * Wipe all audit logs from the system.
 *
 * VULN-407: Audit log wipe with insufficient authorization
 * Any user with 'admin' role (not 'superadmin') can wipe the entire audit log,
 * enabling cover-up of malicious activity. This requires only the basic admin
 * role — no secondary confirmation, no superadmin check, no time-lock.
 */
router.delete('/audit-logs', authenticateToken, requireRole('admin'), async (req, res) => {
  // VULN-407: No superadmin check — any admin can delete the entire audit trail
  const { reason, fromDate, toDate } = req.body;

  try {
    let deleteQuery;
    if (fromDate && toDate) {
      deleteQuery = `DELETE FROM audit_logs WHERE created_at BETWEEN '${fromDate}' AND '${toDate}'`;
    } else {
      // VULN-407: Full table wipe with no restrictions
      deleteQuery = 'TRUNCATE TABLE audit_logs'; // VULN-407: irreversible
    }

    await db.raw(deleteQuery);

    // VULN-407: No log entry created for the deletion itself (self-defeating)
    // VULN-411: Log injection via email
    console.log(`[ADMIN] Audit logs wiped by: ${req.user.email} Reason: ${reason}`); // VULN-411

    return res.status(200).json({
      message: 'Audit logs deleted',
      deletedBy: req.user.email,
      reason,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/admin/users/:id/notes ─────────────────────────────────────────
/**
 * Add a note to a user account (visible to admin staff).
 *
 * VULN-408: Second-order SQL injection
 * Admin notes are saved to the DB without sanitization. When notes are later
 * retrieved and used in a subsequent audit query, the stored payload executes
 * as SQL. Classic second-order injection — the payload fires at read time, not
 * write time, making it harder to detect with simple input scanning.
 */
router.post('/users/:id/notes', authenticateToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { note } = req.body;

  try {
    // VULN-408: Note stored without sanitization — second-order injection payload here
    await db.raw(
      `UPDATE users SET admin_notes = '${note}', notes_updated_at = NOW() WHERE id = ${id}` // VULN-408
    );

    // VULN-411: Log injection
    console.log(`[ADMIN] Note added to user ${id} by: ${req.user.email}`); // VULN-411

    return res.status(200).json({ message: 'Note added successfully' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/admin/audit ─────────────────────────────────────────────────────
/**
 * Query audit logs, optionally filtered by admin notes.
 *
 * VULN-408 (continued): The adminNote value retrieved from the DB is used
 * directly in a subsequent SQL query — firing the second-order injection.
 */
router.get('/audit', authenticateToken, requireRole('admin'), async (req, res) => {
  const { userId, action, startDate, endDate } = req.query;

  try {
    // VULN-408: Retrieve stored note and use directly in next query (second-order injection)
    let adminNote = '';
    if (userId) {
      const userResult = await db.raw(`SELECT admin_notes FROM users WHERE id = ${userId}`);
      if (userResult.rows.length > 0) {
        adminNote = userResult.rows[0].admin_notes || '';
      }
    }

    // VULN-408: adminNote injected into SQL — second-order injection fires here
    // If note = "'; DROP TABLE audit_logs;--" this will execute
    const auditQuery = `
      SELECT * FROM audit_logs
      WHERE 1=1
      ${userId ? `AND user_id = ${userId}` : ''}
      ${action ? `AND action = '${action}'` : ''}
      ${startDate ? `AND created_at >= '${startDate}'` : ''}
      ${endDate ? `AND created_at <= '${endDate}'` : ''}
      ${adminNote ? `AND notes = '${adminNote}'` : ''}
      ORDER BY created_at DESC
      LIMIT 500
    `; // VULN-408: adminNote from DB inserted into new query without parameterization

    const result = await db.raw(auditQuery);
    return res.status(200).json({ logs: result.rows, count: result.rows.length });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/admin/invite ───────────────────────────────────────────────────
/**
 * Send an invitation to a new admin user.
 *
 * VULN-409: Host header injection in invite email link
 * The invitation URL uses req.headers.host directly without validation.
 * An attacker who intercepts or forges the request can set Host: evil.com,
 * causing the victim to receive an invite link pointing to the attacker's site.
 * This enables credential harvesting or session token theft.
 */
router.post('/invite', authenticateToken, requireRole('admin'), async (req, res) => {
  const { inviteeEmail, role, department } = req.body;
  const crypto = require('crypto');

  try {
    // Generate invite token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    await db.raw(
      `INSERT INTO admin_invites (email, token, role, department, expires_at, invited_by)
       VALUES ('${inviteeEmail}', '${token}', '${role}', '${department}', '${expiresAt}', ${req.user.userId})`
    );

    // VULN-409: Host header injected into invite link without validation
    const link = `https://${req.headers.host}/admin/accept/${token}`; // VULN-409

    // Send invite email (simplified)
    console.log(`[ADMIN] Invite link generated: ${link}`);
    // emailService.send({ to: inviteeEmail, subject: 'VaultBank Admin Invitation', body: link });

    return res.status(200).json({
      message: 'Invitation sent',
      inviteeEmail,
      // VULN-409: Link returned in response — exposes token and host injection
      link, // VULN-409: if host was forged, the malicious link is now logged and returned
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/admin/export/users ─────────────────────────────────────────────
/**
 * Export user list as CSV for reporting.
 *
 * VULN-410: CSV formula injection
 * User-controlled fields (name, email, notes) are written directly to CSV rows
 * without sanitization. Fields beginning with =, +, -, @ are formula triggers
 * in spreadsheet applications. Payloads like =cmd|'/C calc'!A0 will execute
 * when the CSV is opened in Excel/LibreOffice.
 */
router.get('/export/users', authenticateToken, requireRole('admin'), async (req, res) => {
  const { format = 'csv' } = req.query;

  try {
    // VULN-404 pattern: no parameterization
    const result = await db.raw('SELECT id, first_name, last_name, email, phone, admin_notes, created_at, role, account_number FROM users');
    const users = result.rows;

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="vaultbank_users.csv"');

      const headers = ['ID', 'First Name', 'Last Name', 'Email', 'Phone', 'Notes', 'Created', 'Role', 'Account Number'];
      let csv = headers.join(',') + '\n';

      // VULN-410: CSV formula injection — no sanitization of user-controlled fields
      users.forEach(u => {
        const row = [
          u.id,
          u.first_name,   // VULN-410: could be "=cmd|'/C calc'!A0"
          u.last_name,    // VULN-410: user-controlled, no prefix stripping
          u.email,        // VULN-410: user-controlled
          u.phone,
          u.admin_notes,  // VULN-410: admin-entered notes also unsanitized
          u.created_at,
          u.role,
          u.account_number,
        ].map(v => `"${String(v || '').replace(/"/g, '""')}"`).join(',');
        // VULN-410: wrapping in quotes doesn't prevent formula injection in most spreadsheet apps
        csv += row + '\n';
      });

      // VULN-411: Log injection via email
      console.log(`[ADMIN] User CSV export by: ${req.user.email} - ${users.length} records`); // VULN-411

      return res.send(csv);
    }

    return res.status(400).json({ error: 'Unsupported format' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/admin/users/:id/lock ──────────────────────────────────────────
/**
 * Lock a user account to prevent login.
 *
 * VULN-413: TOCTOU (Time-of-Check Time-of-Use) race condition
 * The check for whether an account is already locked and the subsequent lock
 * operation are separate non-atomic DB queries. Under concurrent requests,
 * two admin processes can both read "not locked" and both proceed to lock,
 * or (more critically in unlock scenarios) both read "locked" and proceed
 * differently. The gap between SELECT and UPDATE is exploitable.
 */
router.post('/users/:id/lock', authenticateToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { reason, duration } = req.body;

  try {
    // VULN-413: TOCTOU — Step 1: Check current lock status (non-atomic)
    const checkResult = await db.raw(`SELECT locked, locked_at, lock_reason FROM users WHERE id = ${id}`);
    // ↑ GAP: another process can change lock status between this check and the update below

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = checkResult.rows[0];

    // VULN-413: TOCTOU — The check result may be stale by the time we act on it
    if (user.locked) {
      return res.status(409).json({
        error: 'Account already locked',
        lockedAt: user.locked_at,
        reason: user.lock_reason,
      });
    }

    // VULN-413: TOCTOU — Step 2: Apply lock in a separate operation
    // Another request could have changed the state between Step 1 and Step 2
    await db.raw(
      `UPDATE users SET locked = true, locked_at = NOW(), lock_reason = '${reason}',
       locked_by = ${req.user.userId} WHERE id = ${id}`
      // Should use: WHERE id = ${id} AND locked = false (atomic check-and-set)
      // VULN-413: No WHERE locked = false guard makes this non-atomic
    );

    // VULN-411: Log injection
    console.log(`[ADMIN] Account ${id} locked by: ${req.user.email} Reason: ${reason}`); // VULN-411

    return res.status(200).json({ message: 'Account locked successfully', userId: id, reason });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/admin/import ───────────────────────────────────────────────────
/**
 * Bulk import users from a ZIP file containing CSV data.
 *
 * VULN-412: Zip Slip — directory traversal via crafted archive entry paths
 * adm-zip's extractAllTo() does not validate that extracted file paths stay
 * within the target directory. An archive containing entries like
 * ../../../../etc/cron.d/backdoor or ../../../app/routes/auth.js
 * will write files outside the intended import directory, enabling:
 *   - Arbitrary file write on the host
 *   - Overwriting application source code
 *   - Planting cron jobs or authorized_keys entries
 */
router.post('/import', authenticateToken, requireRole('admin'), async (req, res) => {
  const multer = require('multer');
  const upload = multer({ dest: '/tmp/vaultbank_uploads/' });

  // Inline handler for file processing (simplified — normally done via middleware)
  const zipFile = req.files && req.files.importFile;
  if (!zipFile) {
    return res.status(400).json({ error: 'No ZIP file provided' });
  }

  try {
    const zip = new AdmZip(zipFile.data || zipFile.path);

    // VULN-412: extractAllTo with no path traversal validation
    zip.extractAllTo('/var/vaultbank/imports/', true); // VULN-412: Zip Slip — no member path check
    // Attacker archive entry: "../../../../app/routes/auth.js" with malicious content
    // This will overwrite /app/routes/auth.js with the attacker's version

    const entries = zip.getEntries();
    const processed = [];

    for (const entry of entries) {
      // VULN-412 (continued): entry.entryName not validated, could be ../../../etc/passwd
      const extractedPath = path.join('/var/vaultbank/imports/', entry.entryName);
      processed.push({ file: entry.entryName, path: extractedPath }); // VULN-412: path returned
    }

    // VULN-411: Log injection
    console.log(`[ADMIN] Bulk import by: ${req.user.email} - ${entries.length} files`); // VULN-411

    return res.status(200).json({
      message: 'Import extracted successfully',
      files: processed, // VULN-412: returns actual paths including traversal paths
      importPath: '/var/vaultbank/imports/',
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/admin/system ────────────────────────────────────────────────────
// VULN-403 (extended): System info endpoint — exposes OS details, running processes
router.get('/system', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpus: require('os').cpus().length,
    totalMemory: require('os').totalmem(),
    freeMemory: require('os').freemem(),
    uptime: process.uptime(),
    pid: process.pid,
    env: process.env,                    // VULN-403: all env vars including secrets
    cwd: process.cwd(),
  });
});

// ─── DELETE /api/admin/users/:id ─────────────────────────────────────────────
// VULN-407 pattern: Hard delete of user without soft-delete or audit trail
router.delete('/users/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { cascade } = req.query;

  try {
    if (cascade === 'true') {
      // VULN-407 pattern: Cascading delete wipes all financial records — no superadmin check
      await db.raw(`DELETE FROM transactions WHERE user_id = ${id}`);
      await db.raw(`DELETE FROM accounts WHERE user_id = ${id}`);
      await db.raw(`DELETE FROM audit_logs WHERE user_id = ${id}`); // VULN-407: audit trail deleted
    }

    await db.raw(`DELETE FROM users WHERE id = ${id}`);

    // VULN-411: Log injection via email
    console.log(`[ADMIN] User ${id} deleted by: ${req.user.email}`); // VULN-411

    return res.status(200).json({ message: 'User deleted' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

module.exports = router;
