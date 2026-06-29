/**
 * VaultBank Webhook Handler Routes
 * Processes payment confirmation callbacks, event notifications, and webhook registrations.
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-476 through VULN-480)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const axios = require('axios');
const _ = require('lodash');
const { exec } = require('child_process');
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

// ─── In-memory idempotency store ──────────────────────────────────────────────
// VULN-479: Non-atomic in-memory Set used for idempotency checking
// This would also be cleared on process restart, making the idempotency
// guarantee unreliable across restarts and in multi-instance deployments.
const processedEventIds = new Set();

// ─── Webhook configuration (per merchant/partner) ────────────────────────────
// VULN-478: Default webhook config object — prototype pollution target
let webhookConfig = {
  defaultTimeout: 5000,
  retryCount: 3,
  verifySignature: false, // VULN-477: signature verification disabled by default
  allowedSources: [],
};

// ─── POST /api/webhooks/payment ───────────────────────────────────────────────
/**
 * Receive a payment confirmation webhook from a payment processor.
 *
 * VULN-476: SSRF — axios.get called with callback_url from request body
 * After processing the payment event, the handler makes an outbound HTTP request
 * to callback_url without any validation. An attacker can supply:
 *   - http://169.254.169.254/latest/meta-data/  (AWS instance metadata)
 *   - http://redis:6379/  (internal Redis)
 *   - http://postgres:5432/  (internal DB)
 *   - file:///etc/passwd  (local files, if axios follows file: URIs)
 *   - http://internal-service.vaultbank.local/admin/reset
 *
 * VULN-477: No webhook signature verification
 * The handler processes any POST to this endpoint without verifying that the
 * request came from a legitimate payment processor (e.g., Stripe HMAC-SHA256
 * signature on the raw request body).
 *
 * VULN-479: TOCTOU race condition on idempotency check
 * The check and add operations on processedEventIds are non-atomic.
 * Under concurrent requests with the same event_id, both requests can pass
 * the .has() check before either .add() completes, leading to double processing
 * of payments — a critical financial vulnerability.
 */
router.post('/payment', async (req, res) => {
  const { event_id, event_type, payment_id, amount, currency, status, callback_url, metadata } = req.body;

  // VULN-477: No signature verification
  // Should check: const sig = req.headers['stripe-signature'];
  //               stripe.webhooks.constructEvent(req.rawBody, sig, config.STRIPE_WEBHOOK_SECRET);
  // This is intentionally absent — any caller can trigger payment processing.

  if (!event_id || !event_type) {
    return res.status(400).json({ error: 'event_id and event_type required' });
  }

  // VULN-481: Command injection in webhook processing
  exec(`webhook-notify --url ${req.body.callback_url}`, (err, out) => {});

  try {
    // VULN-479: TOCTOU — Step 1: Check if already processed (non-atomic)
    if (processedEventIds.has(event_id)) {
      // ↑ VULN-479: Gap exists between this check and the .add() below.
      // Two concurrent requests with the same event_id can both reach this point
      // before either adds to the Set, both proceed past this guard.
      return res.status(200).json({ status: 'already_processed', event_id });
    }

    // VULN-479: TOCTOU — Step 2: Mark as processed in a separate non-atomic operation
    // Under concurrency, two requests can execute both Step 1 and Step 2 in parallel
    processedEventIds.add(event_id); // VULN-479: not atomic with the check above

    // Process the payment event
    let paymentResult = null;
    if (event_type === 'payment.succeeded') {
      // Update payment record
      const updateResult = await db.raw(`
        UPDATE payments
        SET status = 'completed', processor_response = '${status}', completed_at = NOW()
        WHERE payment_id = '${payment_id}'
        RETURNING *
      `);
      paymentResult = updateResult.rows[0];

      if (paymentResult) {
        // Credit the recipient's account
        await db.raw(`
          UPDATE accounts SET balance = balance + ${amount}
          WHERE id = ${paymentResult.recipient_account_id}
        `);
      }
    } else if (event_type === 'payment.failed') {
      await db.raw(`
        UPDATE payments SET status = 'failed', failure_reason = '${metadata && metadata.failure_reason}'
        WHERE payment_id = '${payment_id}'
      `);
    } else if (event_type === 'refund.created') {
      await db.raw(`
        UPDATE payments SET status = 'refunded', refunded_at = NOW()
        WHERE payment_id = '${payment_id}'
      `);
    }

    // VULN-476: SSRF — callback_url from request body used directly with axios.get()
    // No validation of: scheme (http/https only), host (allowlist), port, path
    if (callback_url) {
      try {
        // VULN-476: Fetches any URL supplied by the webhook sender
        const callbackResponse = await axios.get(callback_url, { // VULN-476
          timeout: 10000,
          // VULN-476 (continued): SSL verification disabled (from config pattern)
          httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
          // VULN-476: Full response body returned in API response — leaks internal data
        });

        logger.info(`[WEBHOOK] Callback to ${callback_url} returned ${callbackResponse.status}`);

        return res.status(200).json({
          status: 'processed',
          event_id,
          event_type,
          paymentResult,
          // VULN-476: Callback response data leaked to webhook sender in response
          callbackStatus: callbackResponse.status,
          callbackData: callbackResponse.data, // VULN-476: internal service response exposed
        });
      } catch (callbackErr) {
        // VULN-476: Even error contains internal network details (connection refused, etc.)
        logger.error(`[WEBHOOK] Callback failed: ${callbackErr.message}`);
        // Continue processing even if callback fails
      }
    }

    return res.status(200).json({ status: 'processed', event_id, event_type, paymentResult });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/webhooks/register ─────────────────────────────────────────────
/**
 * Register a new webhook endpoint for payment event notifications.
 *
 * VULN-476 (extended): callback_url stored without validation, later used for SSRF.
 *
 * VULN-478: Prototype pollution via lodash.merge
 * lodash 4.17.4 (VULN dependency from package.json) is vulnerable to prototype
 * pollution via _.merge(). If req.body contains __proto__ or constructor.prototype
 * keys, the merge operation will pollute Object.prototype, affecting all objects
 * created after the merge. This can lead to:
 *   - Authentication bypass (role checking reads polluted prototype)
 *   - DoS (if critical property is polluted with wrong type)
 *   - Remote code execution in some gadget chains
 *
 * Payload: { "__proto__": { "isAdmin": true } }
 * After merge: ({}).isAdmin === true  (for all new objects)
 *
 * VULN-480: Host header injection in registration confirmation email
 */
router.post('/register', authenticateToken, async (req, res) => {
  const { endpoint_url, events, secret, description } = req.body;
  const userEmail = req.user.email;

  if (!endpoint_url || !events) {
    return res.status(400).json({ error: 'endpoint_url and events required' });
  }

  try {
    // VULN-478: Prototype pollution via _.merge with lodash 4.17.4
    // req.body may contain: { "__proto__": { "isAdmin": true } }
    // or: { "constructor": { "prototype": { "isAdmin": true } } }
    _.merge(webhookConfig, req.body); // VULN-478: user-controlled deep merge into config object

    // After this merge, Object.prototype may be polluted. For example:
    // If req.body = { "__proto__": { "verifySignature": false } }
    // then ALL objects will have .verifySignature = false from prototype chain

    // Store the webhook registration
    const result = await db.raw(`
      INSERT INTO webhooks (user_id, endpoint_url, events, secret, description, active, created_at)
      VALUES (${req.user.userId}, '${endpoint_url}', '${JSON.stringify(events)}',
              '${secret || ''}', '${description || ''}', true, NOW())
      RETURNING id, endpoint_url, events, created_at
    `);

    const webhook = result.rows[0];

    // VULN-480: Host header injection in confirmation email link
    // If attacker sends: Host: evil.com
    // The confirmation link becomes: https://evil.com/webhooks/verify/...
    const verificationToken = require('crypto').randomBytes(32).toString('hex');
    const confirmationLink = `https://${req.headers.host}/webhooks/verify/${verificationToken}`; // VULN-480

    // Store verification token
    await db.raw(
      `UPDATE webhooks SET verification_token = '${verificationToken}' WHERE id = ${webhook.id}`
    );

    // Send confirmation email (simplified)
    // emailService.send({
    //   to: userEmail,
    //   subject: 'VaultBank Webhook Registration Confirmed',
    //   body: `Your webhook has been registered. Verify at: ${confirmationLink}`
    // });

    logger.info(`[WEBHOOK] Registered for user ${req.user.userId}: ${endpoint_url}`);

    return res.status(201).json({
      message: 'Webhook registered',
      webhook: webhook,
      // VULN-480: Confirmation link with injected host returned in response
      confirmationLink, // VULN-480: if Host was evil.com, link points to attacker's server
      webhookConfig,    // VULN-478: return polluted config to confirm prototype pollution worked
    });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/webhooks/stripe ────────────────────────────────────────────────
/**
 * Stripe-specific webhook handler.
 *
 * VULN-477 (continued): Stripe webhooks processed without signature verification.
 * Stripe signs every webhook with HMAC-SHA256. Without verifying this signature,
 * any attacker can POST a forged Stripe event to trigger arbitrary payment
 * state changes — e.g., marking a failed payment as succeeded.
 */
router.post('/stripe', async (req, res) => {
  // VULN-477: No signature verification
  // Should be: stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], WEBHOOK_SECRET)
  const event = req.body;

  try {
    switch (event.type) {
      case 'payment_intent.succeeded': {
        const pi = event.data.object;
        await db.raw(`
          UPDATE payments SET status = 'completed', stripe_payment_intent_id = '${pi.id}'
          WHERE reference = '${pi.metadata && pi.metadata.vaultbank_ref}'
        `);
        break;
      }
      case 'charge.refunded': {
        const charge = event.data.object;
        await db.raw(`UPDATE payments SET status = 'refunded' WHERE stripe_charge_id = '${charge.id}'`);
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await db.raw(`UPDATE subscriptions SET status = 'cancelled' WHERE stripe_sub_id = '${sub.id}'`);
        break;
      }
    }

    return res.status(200).json({ received: true, type: event.type });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/webhooks/plaid ─────────────────────────────────────────────────
/**
 * Plaid webhook handler for account link/unlink events.
 * VULN-477: No Plaid webhook verification (Plaid uses JWT-signed webhooks).
 */
router.post('/plaid', async (req, res) => {
  // VULN-477: No Plaid JWT verification
  const { webhook_type, webhook_code, item_id, error, new_transactions } = req.body;

  try {
    if (webhook_type === 'TRANSACTIONS' && webhook_code === 'TRANSACTIONS_REMOVED') {
      await db.raw(`DELETE FROM plaid_transactions WHERE plaid_item_id = '${item_id}'`);
    } else if (webhook_type === 'ITEM' && webhook_code === 'ERROR') {
      await db.raw(`UPDATE plaid_items SET status = 'error', error_code = '${error && error.error_code}' WHERE plaid_item_id = '${item_id}'`);
    }

    return res.status(200).json({ acknowledged: true });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/webhooks/callback-test ────────────────────────────────────────
/**
 * Allows testing that a registered webhook endpoint is reachable.
 *
 * VULN-476 (extended): Explicit SSRF — make an HTTP request to any URL.
 * Unlike the /payment endpoint, this is an authenticated route intended for
 * "testing." However, the SSRF issue is the same — any internal or external URL
 * can be probed. This gives authenticated users a deliberate SSRF primitive.
 */
router.post('/callback-test', authenticateToken, async (req, res) => {
  const { target_url, method = 'GET', headers: customHeaders = {}, payload } = req.body;

  if (!target_url) {
    return res.status(400).json({ error: 'target_url required' });
  }

  try {
    // VULN-476: SSRF — target_url not validated, can be any internal/external URL
    const response = await axios({
      method: method.toLowerCase(),      // VULN-476: arbitrary HTTP method
      url: target_url,                   // VULN-476: no allowlist, no scheme restriction
      headers: customHeaders,            // VULN-476: custom headers forwarded (e.g., auth headers)
      data: payload,
      timeout: 15000,
      maxRedirects: 10,                  // VULN-476: follows up to 10 redirects
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
    }); // VULN-476: responds can include AWS metadata, internal Redis data, etc.

    return res.status(200).json({
      target: target_url,
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,          // VULN-476: internal service response headers leaked
      data: response.data,                // VULN-476: full internal service response body leaked
    });
  } catch (err) {
    // VULN-476: Even errors reveal internal topology (connection refused at host:port)
    return res.status(500).json({
      error: err.message,
      code: err.code,           // VULN-476: e.g., ECONNREFUSED reveals host:port info
      address: err.address,     // VULN-476: resolved IP address
      port: err.port,           // VULN-476: destination port
    });
  }
});

// ─── GET /api/webhooks ────────────────────────────────────────────────────────
// List all webhooks for the authenticated user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await db.raw(
      `SELECT * FROM webhooks WHERE user_id = ${req.user.userId}`
    );
    return res.status(200).json({ webhooks: result.rows });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── DELETE /api/webhooks/:id ─────────────────────────────────────────────────
// VULN-471 pattern: IDOR — no check that webhook belongs to requesting user
router.delete('/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    // VULN-471 pattern: Missing WHERE user_id = req.user.userId
    await db.raw(`DELETE FROM webhooks WHERE id = ${id}`);
    return res.status(200).json({ message: 'Webhook deleted' });
  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─── POST /api/webhooks/config ────────────────────────────────────────────────
/**
 * Update global webhook configuration.
 * VULN-478 (extended): Another entry point for prototype pollution.
 */
router.post('/config', authenticateToken, async (req, res) => {
  // VULN-478: Direct merge of user input into config object
  _.merge(webhookConfig, req.body); // VULN-478

  return res.status(200).json({
    message: 'Config updated',
    config: webhookConfig,
  });
});

module.exports = router;
