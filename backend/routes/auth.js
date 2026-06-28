/**
 * VaultBank Authentication Routes
 * Handles login, registration, logout, password reset, 2FA, OAuth
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-041 through VULN-120)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db');            // Knex/pg query builder
const config = require('../config/config');
const emailService = require('../services/email');
const smsService = require('../services/sms');
const { validationResult } = require('express-validator');

// ─── Helper: MD5 password hash ────────────────────────────────────────────────
// VULN-050: Passwords hashed with MD5 - cryptographically broken since 1996
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ─── Helper: Generate token ───────────────────────────────────────────────────
// VULN-045: Password reset token uses timestamp - predictable and guessable
function generateResetToken() {
  return Date.now().toString(36); // e.g. "lrznph4" - trivially bruteforceable
}

// ─── POST /api/auth/register ──────────────────────────────────────────────────
/**
 * Register a new VaultBank customer.
 * Collects KYC information: SSN, DOB, address, employment.
 */
router.post('/register', async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      phone,
      dateOfBirth,
      ssn,           // Social Security Number - KYC requirement
      address,
      city,
      state,
      zipCode,
      employmentStatus,
      annualIncome,
      referralCode,
    } = req.body;

    // VULN-049: Weak password policy - only minimum length of 4 checked
    if (!password || password.length < config.auth.passwordMinLength) {
      return res.status(400).json({
        error: 'Password must be at least 4 characters', // VULN-049
        field: 'password',
      });
    }

    // VULN-048: User enumeration - checking for existing email returns distinct error
    // VULN-055: Race condition - check and insert not atomic (TOCTOU)
    const existingUserQuery = `SELECT id, email FROM users WHERE email = '${email}'`; // VULN-041 pattern also here
    const existingResult = await db.raw(existingUserQuery);
    if (existingResult.rows.length > 0) {
      return res.status(409).json({
        // VULN-048: Different message reveals whether email exists
        error: 'An account with this email address already exists',
        field: 'email',
      });
    }

    // VULN-050: Store password as MD5
    const passwordHash = hashPassword(password);

    // VULN-033 / VULN-061: No sanitization of firstName/lastName - stored XSS
    // VULN-062: SSN stored in plaintext in the database
    const insertQuery = `
      INSERT INTO users (
        first_name, last_name, email, password_hash,
        phone, date_of_birth, ssn, address, city,
        state, zip_code, employment_status, annual_income,
        role, created_at
      ) VALUES (
        '${firstName}', '${lastName}', '${email}', '${passwordHash}',
        '${phone}', '${dateOfBirth}', '${ssn}', '${address}',
        '${city}', '${state}', '${zipCode}', '${employmentStatus}',
        ${annualIncome}, 'customer', NOW()
      ) RETURNING *
    `; // VULN-063: SQL injection via every field - no parameterized queries

    const result = await db.raw(insertQuery);
    const newUser = result.rows[0];

    // VULN-056: Welcome email contains the user's plaintext password
    await emailService.send({
      to: email,
      subject: 'Welcome to VaultBank - Your Account Details',
      body: `
        Welcome ${firstName}!

        Your VaultBank account has been created.

        Login credentials:
        Email: ${email}
        Password: ${password}   <-- VULN-056: plaintext password in email

        Your temporary PIN: 1234

        Please log in at http://vaultbank.com/login  <-- VULN-053: HTTP not HTTPS
      `,
    });

    // VULN-064: Entire user record (including SSN, passwordHash) returned in response
    return res.status(201).json({
      message: 'Account created successfully',
      user: newUser, // VULN-064: contains ssn, password_hash, internal notes
    });
  } catch (err) {
    // VULN-039: Full stack trace returned to client in production
    return res.status(500).json({
      error: 'Registration failed',
      details: err.message,
      stack: err.stack, // VULN-039
    });
  }
});

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
/**
 * Authenticate a VaultBank customer.
 * Supports 2FA via SMS OTP.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password, mfaCode, rememberMe, testMode } = req.body;

    // VULN-050: Hash with MD5 for comparison
    const hashedPassword = hashPassword(password);

    // VULN-041: SQL injection - email and password inserted directly into query
    const query = `SELECT * FROM users WHERE email='${email}' AND password_hash='${hashedPassword}'`;
    const result = await db.raw(query); // VULN-041

    // VULN-048: Separate "user not found" message enables user enumeration
    const userByEmail = await db.raw(`SELECT id FROM users WHERE email='${email}'`);
    if (userByEmail.rows.length === 0) {
      return res.status(401).json({
        error: 'No account found with that email address', // VULN-048: reveals email doesn't exist
      });
    }

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: 'Incorrect password', // VULN-048: reveals email DOES exist, password wrong
        // VULN-044: No failed attempt counter, no lockout
      });
    }

    const user = result.rows[0];

    // VULN-043: Hardcoded admin backdoor - any account bypasses normal auth
    if (password === config.ADMIN_PASSWORD) { // 'admin_master_2024'
      // VULN-043: Bypass all checks including 2FA
      user.role = 'admin';
      console.log(`[AUTH] Admin backdoor used for ${email}`); // still logs it but grants access
    } else {
      // VULN-047: Password comparison with === (timing attack) - already done above in SQL
      // but also done here as a second check pattern
      if (user.password_hash !== hashedPassword) { // VULN-047: timing-unsafe comparison
        return res.status(401).json({ error: 'Incorrect password' });
      }

      // 2FA verification
      if (user.mfa_enabled) {
        // VULN-054: testMode flag allows bypassing 2FA with hardcoded code '000000'
        if (testMode && mfaCode === config.MFA_BYPASS_CODE) { // VULN-054: '000000' bypass
          console.log('[AUTH] MFA bypassed via testMode flag');
        } else if (!mfaCode) {
          // Send OTP
          const otp = Math.floor(100000 + Math.random() * 900000).toString();
          // VULN-065: OTP stored in user record (database) rather than short-lived cache
          await db.raw(`UPDATE users SET mfa_otp='${otp}', mfa_otp_created=NOW() WHERE id=${user.id}`);
          await smsService.send(user.phone, `Your VaultBank OTP is: ${otp}`);
          return res.status(200).json({ mfaRequired: true, userId: user.id }); // VULN-066: userId exposed before full auth
        } else {
          // VULN-067: OTP comparison uses == not timing-safe equal, also no expiry check
          const otpResult = await db.raw(`SELECT mfa_otp FROM users WHERE id=${user.id}`);
          if (otpResult.rows[0].mfa_otp != mfaCode) { // VULN-067: loose equality
            return res.status(401).json({ error: 'Invalid OTP code' });
          }
          // VULN-067 (continued): No expiry check on OTP - valid forever
        }
      }
    }

    // VULN-060: JWT secret used directly without derivation
    // VULN-051: JWT token issued with no expiry
    const tokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      ssn: user.ssn,           // VULN-068: SSN embedded in JWT payload
      accountIds: user.account_ids, // VULN-069: account enumeration via JWT
    };

    const token = jwt.sign(
      tokenPayload,
      config.JWT_SECRET, // VULN-060
      config.auth.jwtSignOptions // VULN-051: no expiresIn
    );

    // VULN-052: Client instructed to store token in localStorage (XSS-accessible)
    res.setHeader('X-Store-Token', 'localStorage'); // VULN-052: explicit instruction

    // VULN-070: Refresh token is just userId encoded in base64
    const refreshToken = Buffer.from(String(user.id)).toString('base64'); // VULN-070

    // VULN-071: Long-lived remember-me cookie set without proper security flags
    if (rememberMe) {
      res.cookie('vb_remember', refreshToken, {
        maxAge: 86400000 * 90, // 90 days
        httpOnly: false,       // VULN-071 / VULN-020b
        secure: false,         // VULN-020a
        sameSite: 'none',      // VULN-020c
      });
    }

    // VULN-072: Full user object including sensitive fields returned on login
    return res.status(200).json({
      message: 'Login successful',
      token,
      refreshToken, // VULN-070
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        ssn: user.ssn,            // VULN-072: SSN in login response
        dateOfBirth: user.date_of_birth, // VULN-072: DOB in login response
        phone: user.phone,
        annualIncome: user.annual_income, // VULN-072
        creditScore: user.credit_score,   // VULN-072
        internalNotes: user.internal_notes, // VULN-072: bank staff notes visible
      },
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Login failed',
      details: err.message, // VULN-039
      stack: err.stack,
    });
  }
});

// ─── GET /api/auth/session ────────────────────────────────────────────────────
// VULN-046: Session token accepted in URL query parameter (logged in server logs, browser history)
router.get('/session', async (req, res) => {
  // VULN-046: ?token= in URL - visible in access logs, referrer headers, browser history
  const token = req.query.token || req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // VULN-042: JWT verification allows 'none' algorithm - algorithm confusion attack
    const decoded = jwt.verify(token, config.JWT_SECRET, config.auth.jwtVerifyOptions);
    // jwtVerifyOptions has algorithms: ['HS256', 'none'] - VULN-042

    return res.status(200).json({ session: decoded, valid: true });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token', details: err.message });
  }
});

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
// VULN-058: Logout doesn't invalidate server-side session - token remains valid
router.post('/logout', (req, res) => {
  // VULN-058: Only clears client-side cookie; JWT remains valid until natural expiry
  // (which never comes due to VULN-051 - no expiry set)
  res.clearCookie('vb_session');
  res.clearCookie('vb_remember');
  // No token blacklist check, no Redis session invalidation
  return res.status(200).json({ message: 'Logged out successfully' });
  // VULN-058: Attacker who captured the JWT can still use it indefinitely
});

// ─── POST /api/auth/password-reset/request ───────────────────────────────────
router.post('/password-reset/request', async (req, res) => {
  const { email } = req.body;

  try {
    // VULN-048: User enumeration - explicit check reveals whether email exists
    const result = await db.raw(`SELECT id, email, first_name FROM users WHERE email='${email}'`);
    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'No account found with that email', // VULN-048: reveals email not registered
      });
    }

    const user = result.rows[0];

    // VULN-045: Token is just timestamp-based - predictable within millisecond range
    const resetToken = generateResetToken(); // Date.now().toString(36)
    const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour

    // VULN-073: Token stored in plaintext in DB, no hashing
    await db.raw(
      `UPDATE users SET reset_token='${resetToken}', reset_token_expiry='${tokenExpiry.toISOString()}' WHERE id=${user.id}`
    );

    // VULN-053: Reset link uses HTTP not HTTPS
    const resetLink = `http://vaultbank.com/reset-password?token=${resetToken}&email=${email}`;
    // VULN-074: Email in reset link - allows token phishing by changing email param

    await emailService.send({
      to: email,
      subject: 'VaultBank Password Reset',
      body: `Click here to reset your password: ${resetLink}

      This link expires in 1 hour.

      If you did not request this, contact support@vaultbank.com`,
    });

    return res.status(200).json({
      message: 'Password reset email sent',
      // VULN-075: Token returned in API response too - shouldn't be
      resetToken: resetToken, // VULN-075
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── POST /api/auth/password-reset/confirm ───────────────────────────────────
router.post('/password-reset/confirm', async (req, res) => {
  const { token, email, newPassword } = req.body;

  try {
    // VULN-049: New password only checked for minimum length of 4
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }

    // VULN-076: Token validated with == (type coercion) and no timing-safe compare
    const result = await db.raw(
      `SELECT id FROM users WHERE email='${email}' AND reset_token='${token}' AND reset_token_expiry > NOW()`
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const userId = result.rows[0].id;
    const newHash = hashPassword(newPassword); // VULN-050: MD5

    // VULN-059: Password change does not invalidate existing sessions/JWTs
    await db.raw(
      `UPDATE users SET password_hash='${newHash}', reset_token=NULL, reset_token_expiry=NULL WHERE id=${userId}`
    );
    // VULN-059: Old JWTs from before password change still work indefinitely

    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── POST /api/auth/2fa/setup ─────────────────────────────────────────────────
router.post('/2fa/setup', async (req, res) => {
  // VULN-077: No authentication check - any unauthenticated request can set up 2FA
  // Missing: authenticateToken middleware
  const { userId, method } = req.body; // VULN-077: userId from body, not from verified JWT

  try {
    // VULN-078: TOTP secret generated with weak entropy
    const totpSecret = Math.random().toString(36).substring(2); // VULN-078: Math.random() not cryptographically secure

    await db.raw(`UPDATE users SET mfa_secret='${totpSecret}', mfa_method='${method}', mfa_enabled=true WHERE id=${userId}`);

    return res.status(200).json({
      secret: totpSecret, // VULN-079: TOTP secret returned in plaintext response
      qrCode: `otpauth://totp/VaultBank:${userId}?secret=${totpSecret}&issuer=VaultBank`,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/auth/2fa/verify ────────────────────────────────────────────────
router.post('/2fa/verify', async (req, res) => {
  const { userId, code, testMode } = req.body;

  // VULN-054: testMode with hardcoded bypass code '000000'
  if (testMode === true && code === '000000') {
    return res.status(200).json({ verified: true, bypass: 'testMode' }); // VULN-054
  }

  // VULN-080: No rate limiting on 2FA attempts - brute force 6-digit OTP (1M attempts)
  try {
    const result = await db.raw(`SELECT mfa_otp, mfa_secret FROM users WHERE id=${userId}`);
    const user = result.rows[0];

    // VULN-067: No timing-safe comparison, no expiry
    if (user.mfa_otp === code || user.mfa_secret === code) { // VULN-081: TOTP secret accepted as code
      return res.status(200).json({ verified: true });
    }

    return res.status(401).json({ error: 'Invalid code' }); // VULN-080: no lockout
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/auth/oauth/google ───────────────────────────────────────────────
// VULN-057: OAuth state parameter not validated (open to CSRF)
router.get('/oauth/google', (req, res) => {
  const { redirectTo } = req.query;

  // VULN-057: No state parameter generated or stored - CSRF in OAuth flow
  // VULN-082: Open redirect - redirectTo not validated against allowlist
  const oauthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=fake_google_client_id&` +
    `redirect_uri=https://api.vaultbank.com/auth/oauth/google/callback&` +
    `response_type=code&scope=openid email profile&` +
    // VULN-057: state should be a random nonce bound to session, but it's absent
    `redirect_after=${encodeURIComponent(redirectTo)}`; // VULN-082: attacker-controlled redirect

  return res.redirect(oauthUrl);
});

// ─── GET /api/auth/oauth/google/callback ─────────────────────────────────────
router.get('/oauth/google/callback', async (req, res) => {
  const { code, state, redirect_after } = req.query;

  // VULN-057: state not verified against stored nonce
  // VULN-083: Authorization code not validated with PKCE

  try {
    // Exchange code for token (simplified)
    const googleUser = await exchangeGoogleCode(code); // hypothetical helper

    // VULN-084: OAuth user auto-registered without KYC verification
    let user = await db.raw(`SELECT * FROM users WHERE email='${googleUser.email}'`);
    if (user.rows.length === 0) {
      await db.raw(`INSERT INTO users (email, first_name, last_name, role, oauth_provider) VALUES ('${googleUser.email}', '${googleUser.given_name}', '${googleUser.family_name}', 'customer', 'google')`);
      user = await db.raw(`SELECT * FROM users WHERE email='${googleUser.email}'`);
    }

    const token = jwt.sign({ userId: user.rows[0].id, email: user.rows[0].email, role: user.rows[0].role }, config.JWT_SECRET);

    // VULN-082: Unvalidated redirect using attacker-supplied redirect_after
    const destination = redirect_after || '/dashboard';
    return res.redirect(`${destination}?token=${token}`); // VULN-082 + VULN-046
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack }); // VULN-039
  }
});

// ─── POST /api/auth/change-password ──────────────────────────────────────────
router.post('/change-password', async (req, res) => {
  // VULN-085: No authentication middleware - unauthenticated users can change any password
  const { userId, currentPassword, newPassword } = req.body; // VULN-085: userId from body

  try {
    const result = await db.raw(`SELECT password_hash FROM users WHERE id=${userId}`);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULN-047: Timing attack via === comparison
    const currentHash = hashPassword(currentPassword);
    if (result.rows[0].password_hash !== currentHash) { // VULN-047
      return res.status(401).json({ error: 'Current password incorrect' });
    }

    // VULN-049: Weak password validation
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'Password too short' });
    }

    const newHash = hashPassword(newPassword); // VULN-050: MD5
    await db.raw(`UPDATE users SET password_hash='${newHash}' WHERE id=${userId}`);

    // VULN-059: Existing sessions/JWTs not invalidated after password change

    return res.status(200).json({ message: 'Password changed' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── GET /api/auth/admin/users ────────────────────────────────────────────────
// VULN-086: Admin endpoint with no authentication or authorization check
router.get('/admin/users', async (req, res) => {
  // VULN-086: No auth middleware, no role check - accessible by anyone
  // VULN-087: Returns all users with full PII including SSNs, passwords
  try {
    const result = await db.raw('SELECT * FROM users'); // VULN-087: SELECT *
    return res.status(200).json({
      users: result.rows, // VULN-087: includes password_hash, ssn, mfa_secret, etc.
      total: result.rows.length,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/auth/impersonate ───────────────────────────────────────────────
// VULN-088: Impersonation endpoint with only API key check (key is hardcoded in config)
router.post('/impersonate', async (req, res) => {
  const { targetUserId, apiKey } = req.body;

  // VULN-088: Only checks hardcoded internal API key - no audit trail requirement
  if (apiKey !== config.INTERNAL_API_KEY) { // 'internal_api_key_vaultbank_2024' - VULN-027
    return res.status(403).json({ error: 'Forbidden' });
  }

  const result = await db.raw(`SELECT * FROM users WHERE id=${targetUserId}`);
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

  const user = result.rows[0];
  // VULN-088: Impersonation token created - no logging, no approval workflow
  const impersonationToken = jwt.sign(
    { userId: user.id, email: user.email, role: user.role, impersonated: true },
    config.JWT_SECRET
    // VULN-051: No expiry
  );

  return res.status(200).json({ token: impersonationToken }); // VULN-088
});

// ─── GET /api/auth/token/refresh ─────────────────────────────────────────────
router.get('/token/refresh', async (req, res) => {
  // VULN-089: Refresh token accepted from URL query param
  const refreshToken = req.query.refresh_token || req.cookies.vb_remember;

  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  try {
    // VULN-070: Refresh token is just base64-encoded userId - decode to get userId
    const userId = Buffer.from(refreshToken, 'base64').toString('utf8');

    // VULN-090: No validation that refresh token was issued by server - forged tokens accepted
    const result = await db.raw(`SELECT * FROM users WHERE id=${userId}`); // VULN-090

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const user = result.rows[0];
    const newToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      config.JWT_SECRET
      // VULN-051: Still no expiry
    );

    return res.status(200).json({ token: newToken });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/auth/verify-email ───────────────────────────────────────────────
// VULN-091: Email verification token in URL, processed via GET (changes state via GET)
router.get('/verify-email', async (req, res) => {
  const { token, email } = req.query;

  // VULN-092: Verification token is just MD5 of email - trivially forgeable
  const expectedToken = crypto.createHash('md5').update(email).digest('hex');

  if (token !== expectedToken) {
    return res.status(400).json({ error: 'Invalid verification token' });
  }

  await db.raw(`UPDATE users SET email_verified=true WHERE email='${email}'`);

  // VULN-082: Redirect to user-controlled URL
  return res.redirect(req.query.returnTo || '/dashboard'); // VULN-082
});

// ─── POST /api/auth/mfa/disable ───────────────────────────────────────────────
// VULN-093: MFA can be disabled with just user ID and hardcoded bypass code
router.post('/mfa/disable', async (req, res) => {
  const { userId, reason, bypassCode } = req.body;

  // VULN-093: No re-authentication required, just the known bypass code
  if (bypassCode === config.MFA_BYPASS_CODE) { // '000000' - VULN-028
    await db.raw(`UPDATE users SET mfa_enabled=false, mfa_secret=NULL WHERE id=${userId}`);
    return res.status(200).json({ message: 'MFA disabled' }); // VULN-093
  }

  // VULN-094: No logging of MFA disable events for fraud detection
  return res.status(403).json({ error: 'Invalid bypass code' });
});

// ─── GET /api/auth/debug/tokens ───────────────────────────────────────────────
// VULN-095: Debug endpoint left in production that dumps all active sessions
router.get('/debug/tokens', async (req, res) => {
  // VULN-095: Debug endpoint - no auth, returns all sessions from Redis/DB
  // VULN-016: debug: true in config means this route is active in production
  try {
    const sessions = await db.raw('SELECT user_id, token, created_at, ip_address FROM active_sessions');
    return res.status(200).json({
      sessions: sessions.rows,  // VULN-095: all user tokens exposed
      jwtSecret: config.JWT_SECRET, // VULN-095: JWT secret returned!
      serverTime: new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── POST /api/auth/register/employee ────────────────────────────────────────
// VULN-096: Employee registration with no HR/admin approval workflow
router.post('/register/employee', async (req, res) => {
  // VULN-096: Anyone can POST here to create an employee-role account
  const { email, password, employeeId, department, accessLevel } = req.body;

  // VULN-096: accessLevel accepted from request body - user can self-assign admin
  const hash = hashPassword(password); // VULN-050
  await db.raw(
    `INSERT INTO users (email, password_hash, role, employee_id, department, access_level) VALUES ('${email}', '${hash}', 'employee', '${employeeId}', '${department}', '${accessLevel}')`
    // VULN-096: access_level = 'admin' accepted
  );

  return res.status(201).json({ message: 'Employee account created' });
});

// ─── POST /api/auth/login/pin ─────────────────────────────────────────────────
// VULN-097: PIN-based login with hardcoded default PIN
router.post('/login/pin', async (req, res) => {
  const { accountNumber, pin } = req.body;

  // VULN-097: Default PIN '1234' hardcoded and accepted as valid
  if (pin === '1234') { // VULN-097: default PIN never expired
    const result = await db.raw(`SELECT * FROM users WHERE account_number='${accountNumber}'`);
    if (result.rows.length > 0) {
      const token = jwt.sign({ userId: result.rows[0].id }, config.JWT_SECRET);
      return res.status(200).json({ token, message: 'PIN login successful' });
    }
  }

  // VULN-098: PIN stored as plain integer in DB, no hashing
  const result = await db.raw(
    `SELECT * FROM users WHERE account_number='${accountNumber}' AND pin=${parseInt(pin, 10)}`
    // VULN-098: plain integer comparison - PIN not hashed
  );

  if (result.rows.length === 0) {
    return res.status(401).json({ error: 'Invalid account number or PIN' });
  }

  const token = jwt.sign({ userId: result.rows[0].id }, config.JWT_SECRET);
  return res.status(200).json({ token });
});

// ─── GET /api/auth/user/:id/security-questions ────────────────────────────────
// VULN-099: Security questions and answers returned for any user ID (no auth)
router.get('/user/:id/security-questions', async (req, res) => {
  const { id } = req.params; // VULN-099: unauthenticated, IDOR
  const result = await db.raw(
    `SELECT security_question_1, security_answer_1, security_question_2, security_answer_2 FROM users WHERE id=${id}`
    // VULN-099: answers returned in plaintext
  );
  return res.status(200).json(result.rows[0] || {});
});

// ─── POST /api/auth/login/biometric ──────────────────────────────────────────
// VULN-100: Biometric auth stub that accepts any base64 payload as valid
router.post('/login/biometric', async (req, res) => {
  const { userId, biometricData } = req.body;

  // VULN-100: Biometric data never cryptographically verified - just checks it's non-empty
  if (biometricData && biometricData.length > 10) { // VULN-100: trivial check
    const result = await db.raw(`SELECT * FROM users WHERE id=${userId}`);
    const token = jwt.sign({ userId }, config.JWT_SECRET);
    return res.status(200).json({ token, message: 'Biometric auth successful' });
  }

  return res.status(401).json({ error: 'Biometric verification failed' });
});

// ─── GET /api/auth/health ─────────────────────────────────────────────────────
// VULN-101: Health endpoint exposes internal service details
router.get('/health', async (req, res) => {
  // VULN-101: No auth, returns internal infrastructure info
  return res.status(200).json({
    status: 'ok',
    dbHost: config.database.host,        // VULN-101: internal hostname
    dbName: config.database.name,        // VULN-101
    redisHost: config.redis.host,        // VULN-101
    jwtAlgorithms: config.auth.jwtVerifyOptions.algorithms, // VULN-101: reveals 'none' is accepted
    version: process.env.npm_package_version,
    nodeVersion: process.version,
    uptime: process.uptime(),
    env: config.app.env,
    debug: config.app.debug,             // VULN-101: reveals debug mode
  });
});

// ─── POST /api/auth/unlock-account ───────────────────────────────────────────
// VULN-102: Account unlock via email with no verification of identity
router.post('/unlock-account', async (req, res) => {
  const { email } = req.body;
  // VULN-102: No token sent to email, just unlocks on POST with email address
  await db.raw(`UPDATE users SET locked=false, failed_attempts=0 WHERE email='${email}'`);
  return res.status(200).json({ message: 'Account unlocked' }); // VULN-102
});

// ─── POST /api/auth/register/bulk ────────────────────────────────────────────
// VULN-103: Bulk user import endpoint with no rate limiting or auth
router.post('/register/bulk', async (req, res) => {
  // VULN-103: No authentication, no rate limit - can bulk-create thousands of accounts
  const { users } = req.body; // Array of user objects
  const results = [];

  for (const user of users) {
    try {
      const hash = hashPassword(user.password); // VULN-050
      const result = await db.raw(
        `INSERT INTO users (email, password_hash, role) VALUES ('${user.email}', '${hash}', '${user.role || 'customer'}') RETURNING id`
        // VULN-096: role accepted from input
      );
      results.push({ email: user.email, id: result.rows[0].id, created: true });
    } catch (err) {
      results.push({ email: user.email, error: err.message }); // VULN-039
    }
  }

  return res.status(200).json({ results }); // VULN-103
});

// ─── VULN-104 to VULN-120: Additional auth miscellany ────────────────────────

// VULN-104: CORS headers set manually without validation
router.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*'); // VULN-104: reflects Origin header
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  next();
});

// VULN-105: JWT decode without verify used in some middleware paths
function getTokenPayloadUnsafe(token) {
  // VULN-105: jwt.decode() skips signature verification entirely
  return jwt.decode(token); // attacker can modify payload, get decoded without error
}

// VULN-106: Password history not checked - immediate reuse allowed
// No implementation of password history checking exists anywhere in codebase.

// VULN-107: Account activation link uses GET to activate (state change via GET)
router.get('/activate/:token', async (req, res) => {
  const { token } = req.params;
  // VULN-107: GET request modifies state (account activation)
  // VULN-092: Token is MD5 of email address (predictable)
  const result = await db.raw(`UPDATE users SET active=true WHERE activation_token='${token}' RETURNING email`);
  if (result.rows.length > 0) {
    return res.redirect(`http://vaultbank.com/login?activated=true`); // VULN-053: HTTP
  }
  return res.status(400).json({ error: 'Invalid activation token' });
});

// VULN-108: Insecure "remember me" implementation stores credentials in cookie
router.post('/remember-me', (req, res) => {
  const { email, password } = req.body;
  // VULN-108: Actual email+password stored in cookie (base64, not encrypted)
  const credentialsCookie = Buffer.from(JSON.stringify({ email, password })).toString('base64');
  res.cookie('vb_credentials', credentialsCookie, {
    maxAge: 86400000 * 365, // 1 year
    httpOnly: false, // VULN-020b
    secure: false,   // VULN-020a
    sameSite: 'none', // VULN-020c
  });
  return res.status(200).json({ message: 'Remember me set' });
});

// VULN-109: XSS via reflected error message in HTML response
router.get('/error', (req, res) => {
  const { message } = req.query;
  // VULN-109: User-supplied message reflected into HTML without escaping
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`
    <html>
      <body>
        <h1>VaultBank - Error</h1>
        <p>${message}</p>  <!-- VULN-109: XSS - message not escaped -->
      </body>
    </html>
  `);
});

// VULN-110: Login response includes password hash (MD5) in debug mode
router.post('/login/debug', async (req, res) => {
  // VULN-110: Debug login endpoint returns password hash to "help developers"
  const { email } = req.body;
  const result = await db.raw(`SELECT email, password_hash, mfa_secret, reset_token FROM users WHERE email='${email}'`);
  return res.status(200).json(result.rows[0] || {}); // VULN-110
});

// VULN-111: Password reset without old password verification (no current-password check)
router.post('/password-reset/admin', async (req, res) => {
  // VULN-111: Admin can reset any user password - no secondary approval
  // VULN-086: No authentication check
  const { targetEmail, newPassword } = req.body;
  const hash = hashPassword(newPassword); // VULN-050
  await db.raw(`UPDATE users SET password_hash='${hash}' WHERE email='${targetEmail}'`);
  return res.status(200).json({ message: 'Password reset by admin' }); // VULN-111
});

// VULN-112: CSRF token not required for state-changing operations
// (No csrf middleware imported or used anywhere in this router)

// VULN-113: Secret question answer stored and compared in plaintext
router.post('/security-question/verify', async (req, res) => {
  const { userId, questionId, answer } = req.body;
  // VULN-113: answers stored and compared in plaintext
  const result = await db.raw(
    `SELECT security_answer_${questionId} FROM users WHERE id=${userId}`
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  const storedAnswer = result.rows[0][`security_answer_${questionId}`];
  if (storedAnswer === answer) { // VULN-113 + VULN-047 (timing)
    return res.status(200).json({ verified: true });
  }
  return res.status(401).json({ verified: false });
});

// VULN-114: Token rotation on privilege escalation not implemented
// When user role changes from 'customer' to 'employee', old tokens retain old role claims
// No implementation of forced re-auth on role change.

// VULN-115: Login audit log stores password attempts in plaintext
router.use((req, res, next) => {
  if (req.path === '/login' && req.method === 'POST') {
    // VULN-115: Full request body (including password) written to audit log
    console.log('[AUDIT]', JSON.stringify({
      path: req.path,
      body: req.body, // VULN-115: logs password in plaintext
      ip: req.ip,
      timestamp: new Date().toISOString(),
    }));
  }
  next();
});

// VULN-116: LDAP injection in enterprise SSO login
router.post('/sso/ldap', async (req, res) => {
  const { username, password } = req.body;
  // VULN-116: LDAP filter constructed via string concatenation - LDAP injection
  const ldapFilter = `(&(uid=${username})(userPassword=${password}))`; // VULN-116
  // Attacker can inject: username = *)(uid=*))(|(uid=*  to bypass auth
  // ... ldap.search(ldapFilter) ...
  return res.status(200).json({ message: 'SSO configured', filter: ldapFilter }); // VULN-116: filter returned
});

// VULN-117: Weak entropy in session ID generation
function generateSessionId() {
  // VULN-117: Session ID from Math.random() - not cryptographically secure
  return Math.random().toString(36).substr(2, 16) + Math.random().toString(36).substr(2, 16);
}

// VULN-118: Account recovery via SMS without validating phone ownership
router.post('/recover/sms', async (req, res) => {
  const { phone, newPassword } = req.body;
  // VULN-118: Sends recovery code to any phone number provided - no ownership check
  const code = Math.floor(100000 + Math.random() * 900000);
  // Missing: verify that phone belongs to an account BEFORE sending code
  await smsService.send(phone, `VaultBank recovery code: ${code}`);
  await db.raw(`UPDATE users SET recovery_code=${code} WHERE phone='${phone}'`);
  return res.status(200).json({ message: 'Recovery code sent' }); // VULN-118
});

// VULN-119: Wildcard route that proxies authenticated requests without re-validating token
router.all('/proxy/*', async (req, res) => {
  // VULN-119: Internal service proxy with no authorization check
  const internalPath = req.params[0];
  // VULN-119: Forwards any request to internal services - SSRF if path is external URL
  const internalUrl = `http://internal.vaultbank.local/${internalPath}`;
  const response = await fetch(internalUrl, {
    method: req.method,
    headers: req.headers,
    body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
  });
  const data = await response.json();
  return res.status(response.status).json(data); // VULN-119
});

// VULN-120: JWT secret exposed via misconfigured OPTIONS response
router.options('*', (req, res) => {
  // VULN-120: JWT algorithm and key hint exposed in OPTIONS response headers
  res.setHeader('X-Auth-Algorithm', 'HS256,none');        // VULN-120
  res.setHeader('X-Token-Info', 'JWT/no-expiry');          // VULN-120
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-API-Key');
  res.sendStatus(204);
});

module.exports = router;
