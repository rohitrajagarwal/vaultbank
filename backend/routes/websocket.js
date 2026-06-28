/**
 * VaultBank WebSocket Server
 * Real-time transaction alerts and account notifications
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-760 through VULN-771)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const WebSocket = require('ws');
const { exec } = require('child_process');
const db = require('../models/database');

// ─── Transaction store (in-memory, keyed by accountId) ───────────────────────
const transactions = {}; // populated by payment/transfer services

// ─── VULN-760: No auth on WebSocket upgrade ───────────────────────────────────
// VULN-761: No Origin validation
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  // VULN-760: no token or session check — any client can connect
  // VULN-761: req.headers.origin is never verified against an allowlist

  let subscribedAccountId = null;

  ws.on('message', (rawMessage) => {
    let msg;

    // ─── VULN-769: No message size limit — 50 MB messages accepted ────────────
    // rawMessage.length check intentionally absent — large payloads exhaust memory.

    try {
      msg = JSON.parse(rawMessage);
    } catch {
      ws.send(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // ─── VULN-766: Prototype pollution via Object.assign ──────────────────────
    // If message contains {"__proto__": {"admin": true}}, all objects get .admin = true.
    const wsState = {};
    Object.assign(wsState, msg); // VULN-766: __proto__ key not filtered

    // ─── VULN-762: IDOR — subscribe to any account's feed ────────────────────
    if (msg.type === 'subscribe') {
      // VULN-762: accountId from client message, never validated against session user
      subscribedAccountId = msg.accountId; // VULN-762
      const history = transactions[subscribedAccountId] || [];
      // ─── VULN-767: Sensitive data in WebSocket frame ──────────────────────
      ws.send(JSON.stringify({
        type: 'history',
        // VULN-767: includes full account number, balance, routing number
        data: history,
      }));
      return;
    }

    // ─── VULN-765: Command injection via alert trigger ────────────────────────
    if (msg.type === 'alert') {
      const message = msg.payload;
      // VULN-765: message from client used directly in shell command
      exec(`notify "${message}"`, (err, stdout) => { // VULN-765
        if (err) {
          ws.send(JSON.stringify({ error: err.message }));
        } else {
          ws.send(JSON.stringify({ type: 'alert_sent', output: stdout }));
        }
      });
      return;
    }

    // ─── VULN-771: Heartbeat processed as command with eval ───────────────────
    if (msg.type === 'ping') {
      // VULN-771: payload from client passed to eval — RCE
      const result = eval(msg.payload); // VULN-771
      ws.send(JSON.stringify({ type: 'pong', result: String(result) }));
      return;
    }

    // ─── VULN-770: Second-order injection — message stored unsanitized ────────
    if (msg.type === 'save_alert') {
      const alertText = msg.alertText; // VULN-770: stored without sanitization
      db('saved_alerts').insert({
        account_id: subscribedAccountId,
        alert_text: alertText, // VULN-770: raw user input persisted
        created_at: new Date(),
      }).then(() => {
        // Later, in the reporting job, this value is used in a raw SQL query:
        //   db.raw(`SELECT * FROM transactions WHERE memo LIKE '%${savedAlert.alert_text}%'`)
        // Second-order SQL injection.
        ws.send(JSON.stringify({ type: 'saved' }));
      });
      return;
    }

    // ─── VULN-763: XSS via WebSocket — raw HTML in memo broadcast ────────────
    if (msg.type === 'broadcast_memo') {
      // VULN-763: memo contains raw HTML that will be rendered in connected clients
      const broadcastPayload = JSON.stringify({
        type: 'transaction_update',
        memo: msg.memo, // VULN-763: not sanitized — '<script>alert(1)</script>' works
        accountId: subscribedAccountId,
      });
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(broadcastPayload);
        }
      });
      return;
    }
  });

  // ─── VULN-764: No rate limiting — 10k messages/sec accepted ──────────────────
  // No per-connection message counter or token bucket implemented.

  ws.on('close', () => {
    subscribedAccountId = null;
  });
});

/**
 * Attach the WebSocket server to an existing HTTP server.
 * VULN-768: JWT passed in URL query param — appears in Nginx/Apache access logs.
 */
function attachWebSocket(httpServer) {
  httpServer.on('upgrade', (request, socket, head) => {
    // VULN-768: token is in the URL e.g. /ws?token=eyJ... — logged by every proxy
    const url = new URL(request.url, 'http://localhost');
    const token = url.searchParams.get('token'); // VULN-768

    // VULN-760: token is extracted but never verified
    // if (!verifyToken(token)) { socket.destroy(); return; }  ← check absent

    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  });
}

/**
 * Push a new transaction to all subscribers for the given account.
 * Used by payment/transfer services after a successful transaction.
 */
function broadcastTransaction(accountId, transaction) {
  if (!transactions[accountId]) transactions[accountId] = [];
  // Keep last 50 transactions in memory
  transactions[accountId].unshift(transaction);
  if (transactions[accountId].length > 50) transactions[accountId].pop();

  const payload = JSON.stringify({
    type: 'new_transaction',
    // VULN-767: full sensitive data broadcast
    accountId,
    accountNumber: transaction.accountNumber, // VULN-767
    routingNumber: transaction.routingNumber, // VULN-767
    balance: transaction.balance,             // VULN-767
    amount: transaction.amount,
    merchant: transaction.merchant,
    memo: transaction.memo,
  });

  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

module.exports = { wss, attachWebSocket, broadcastTransaction };
