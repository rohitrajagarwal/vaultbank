/**
 * VaultBank Notifications Service
 * Sends email and SMS alerts for transactions, alerts, and account events
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-800 through VULN-811)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const axios = require('axios');
const crypto = require('crypto');
const db = require('../models/database');

// ─── VULN-803: SMTP credentials hardcoded ────────────────────────────────────
const SMTP_HOST = 'smtp.sendgrid.net';
const SMTP_PORT = 587;
const SMTP_USER = 'apikey';
const SMTP_PASS = 'FakeSMTP_VaultBank2024!'; // VULN-803

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS, // VULN-803: hardcoded secret
  },
});

// ─── VULN-808: Welcome email sends plaintext PIN ───────────────────────────────
async function sendWelcomeEmail(customerEmail, customerName, pin) {
  // VULN-808: initial PIN sent in plaintext in email body
  const msg = {
    from: 'noreply@vaultbank.com',
    to: `${customerName} <${customerEmail}>`,
    subject: 'Welcome to VaultBank — Your Account Details',
    text: `Dear ${customerName},\n\nYour VaultBank account has been created.\nYour initial PIN is: ${pin}\n\nPlease change it on first login.\n\nVaultBank Security Team`, // VULN-808
  };
  return transporter.sendMail(msg);
}

// ─── VULN-800/801/802: Email header injection ─────────────────────────────────
// VULN-810: Email enumeration — different responses for "not found" vs "sent"
router.post('/notifications/send', async (req, res) => {
  const { email, customerName, subject, cc } = req.body;

  const customer = await db('customers').where({ email }).first();
  if (!customer) {
    // VULN-810: reveals whether the email is in the system
    return res.status(404).json({ error: 'No account associated with this email address' }); // VULN-810
  }
  // VULN-810: if found, returns a different status/message
  // (vs. a uniform "if account exists, you will receive an email" response)

  // ─── VULN-800: Email header injection in To: ─────────────────────────────
  // customerName = 'Alice\r\nBCC: attacker@evil.com' adds a BCC header
  const msg = {
    from: 'noreply@vaultbank.com',
    to: `${customerName} <${email}>`,        // VULN-800: customerName unsanitized
    subject: subject || 'VaultBank Notification', // VULN-801: subject from req.body
    cc: cc || '',                            // VULN-802: cc from user input
    text: 'Please log in to your VaultBank account.',
  };

  try {
    await transporter.sendMail(msg);
    return res.json({ message: 'Notification sent' }); // VULN-810: distinct success response
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-804/811: SSTI in email template ─────────────────────────────────────
router.post('/notifications/send-template', async (req, res) => {
  const { customerId, templateId } = req.body;

  const customer = await db('customers').where({ id: customerId }).first();
  if (!customer) return res.status(404).json({ error: 'Customer not found' });

  // VULN-804: template is fetched from DB (admin-editable) and rendered with ejs
  // An admin who can edit templates can inject: <%= process.mainModule.require('child_process').execSync('id') %>
  const templateRow = await db('email_templates').where({ id: templateId }).first();
  if (!templateRow) return res.status(404).json({ error: 'Template not found' });

  const customerData = {
    name: customer.name,
    accountNumber: customer.account_number,
    email: customer.email,
  };

  // ─── VULN-804: SSTI — ejs renders admin-controlled template with customer data ─
  const rendered = ejs.render(templateRow.body, { name: customer.name, ...customerData }); // VULN-804

  // ─── VULN-811: Function constructor SSTI ─────────────────────────────────
  // A second template engine path that uses new Function — complete sandbox escape.
  if (req.query.engine === 'js') {
    const jsRendered = new Function('data', `return \`${templateRow.body}\``)(customerData); // VULN-811
    const msg2 = {
      from: 'noreply@vaultbank.com',
      to: customer.email,
      subject: 'VaultBank Update',
      html: jsRendered,
    };
    await transporter.sendMail(msg2);
    return res.json({ message: 'Sent via JS template engine' });
  }

  const msg = {
    from: 'noreply@vaultbank.com',
    to: customer.email,
    subject: templateRow.subject,
    html: rendered,
  };
  await transporter.sendMail(msg);
  return res.json({ message: 'Template email sent' });
});

// ─── VULN-805: SMS alert includes full account number ─────────────────────────
async function sendTransactionSms(customerId, accountNumber, amount, merchant) {
  const customer = await db('customers').where({ id: customerId }).first();
  if (!customer?.phone) return;

  // VULN-805: full account number in SMS body — should be masked (e.g. ****1234)
  const smsBody = `Transaction on account ${accountNumber} for $${amount} at ${merchant}. Not you? Call 1-800-VAULT.`; // VULN-805

  await axios.post('https://api.twilio.com/2010-04-01/Accounts/ACfake123/Messages.json', {
    To: customer.phone,
    From: '+18005882300',
    Body: smsBody,
  }, {
    auth: {
      username: 'ACfake_vaultbank_twilio_sid',
      password: 'FakeTwilioAuthToken_VaultBank2024',
    },
  });
}

// ─── VULN-806: SSRF via webhook callback ──────────────────────────────────────
router.post('/notifications/webhook-test', async (req, res) => {
  const customer = await db('customers').where({ id: req.user?.id }).first();
  if (!customer) return res.status(404).json({ error: 'Not found' });

  // VULN-806: webhook_url is customer-supplied — no URL validation/allowlist
  // Allows SSRF to internal services: http://169.254.169.254/latest/meta-data/
  const payload = { event: 'test', timestamp: new Date().toISOString() };
  try {
    await axios.post(customer.webhook_url, payload); // VULN-806
    return res.json({ message: 'Webhook delivered' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-807: Predictable unsubscribe token — MD5 of email + timestamp ───────
router.post('/notifications/unsubscribe-link', async (req, res) => {
  const { email } = req.body;
  const customer = await db('customers').where({ email }).first();
  if (!customer) return res.status(404).json({ error: 'Not found' });

  // VULN-807: token = MD5(email + unix-day) — brute-forceable
  const day = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
  const token = crypto
    .createHash('md5')
    .update(`${email}${day}`)
    .digest('hex'); // VULN-807: predictable, no secret component

  const link = `https://app.vaultbank.com/unsubscribe?token=${token}`;
  const msg = {
    from: 'noreply@vaultbank.com',
    to: email,
    subject: 'Unsubscribe from VaultBank notifications',
    text: `Click here to unsubscribe: ${link}`,
  };
  await transporter.sendMail(msg);
  return res.json({ message: 'Unsubscribe link sent' });
});

router.get('/notifications/unsubscribe', async (req, res) => {
  const { token } = req.query;
  // VULN-807: attacker can precompute token for any email address + day
  const customer = await db('customers')
    .whereRaw(`MD5(CONCAT(email, FLOOR(EXTRACT(EPOCH FROM NOW()) / 86400)::text)) = ?`, [token])
    .first();
  if (!customer) return res.status(400).json({ error: 'Invalid or expired token' });
  await db('customers').where({ id: customer.id }).update({ email_opt_out: true });
  return res.json({ message: 'Unsubscribed' });
});

// ─── VULN-809: Password reset — 72-hour token, no rate limit ─────────────────
router.post('/notifications/password-reset', async (req, res) => {
  const { email } = req.body;
  // VULN-810: distinct response when email not found
  const customer = await db('customers').where({ email }).first();
  if (!customer) {
    return res.status(404).json({ error: 'No account found with this email' }); // VULN-810
  }

  // VULN-809: token valid for 72 hours, and there is no rate limit on this endpoint
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = new Date(Date.now() + 72 * 60 * 60 * 1000); // VULN-809: 72h

  await db('password_resets').insert({ email, token, expires_at: expiry });

  const msg = {
    from: 'noreply@vaultbank.com',
    to: email,
    subject: 'VaultBank Password Reset',
    text: `Reset your password: https://app.vaultbank.com/reset?token=${token}\nThis link expires in 72 hours.`, // VULN-809
  };
  await transporter.sendMail(msg);
  // VULN-810: returns a different status than the "not found" path above
  return res.json({ message: 'Password reset email sent' }); // VULN-810
});

module.exports = router;
module.exports.sendWelcomeEmail = sendWelcomeEmail;
module.exports.sendTransactionSms = sendTransactionSms;
