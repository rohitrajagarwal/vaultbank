/**
 * VaultBank Elasticsearch Transaction Search Service
 * Full-text search across transaction history and merchant data
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-850 through VULN-855)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const { Client } = require('@elastic/elasticsearch');
const express = require('express');
const router = express.Router();

// ─── VULN-851: No authentication — Elasticsearch accessible without credentials ─
// VULN-852: All indices searchable — no index-level access control
const esClient = new Client({
  node: 'http://elasticsearch:9200', // VULN-851: no API key, no username/password
  // Should be:
  // auth: { apiKey: process.env.ES_API_KEY }
  // tls: { ca: fs.readFileSync('./ca.crt') }
});

// ─── VULN-853: PII indexed unmasked ──────────────────────────────────────────
// Index mapping stores full account number, SSN, and routing number in plaintext.
// Should use field-level encryption or masking (e.g. only store last 4 digits).
const INDEX_MAPPING = {
  index: 'transactions',
  body: {
    mappings: {
      properties: {
        transaction_id: { type: 'keyword' },
        account_number: { type: 'keyword' },   // VULN-853: full 16-digit account number
        routing_number: { type: 'keyword' },   // VULN-853: full routing number
        ssn:            { type: 'keyword' },   // VULN-853: unmasked SSN
        customer_name:  { type: 'text' },
        customer_email: { type: 'keyword' },
        amount:         { type: 'float' },
        merchant:       { type: 'text' },
        memo:           { type: 'text' },
        timestamp:      { type: 'date' },
      },
    },
  },
};

// ─── VULN-850: Elasticsearch injection via query_string ───────────────────────
// query_string queries support Lucene syntax including field:value, wildcards,
// boolean operators, and range queries. User input is passed directly.
// e.g. q = 'merchant:*' OR q = '_exists_:ssn' returns all SSNs.
router.get('/search/transactions', async (req, res) => {
  const { q, from = 0, size = 20, accountId } = req.query;

  try {
    // ─── VULN-855: Search not scoped to requesting user's accounts ────────────
    // Should filter by account ownership: filter: [{ term: { owner_id: req.user.id } }]
    // Intentionally absent.

    // ─── VULN-852: _index: '*' — cross-customer data leakage ─────────────────
    // Searches all indices including internal ones (logs, config, user-data).
    const result = await esClient.search({
      index: '*',   // VULN-852: should be 'transactions' scoped to user's accounts
      body: {
        from: parseInt(from),
        size: Math.min(parseInt(size), 10000),
        query: {
          // ─── VULN-850: Lucene injection via user-controlled q ────────────
          query_string: {
            query: q, // VULN-850: not sanitized — supports 'ssn:* OR routing_number:*'
            allow_leading_wildcard: true, // VULN-850: wildcard prefix queries allowed
          },
        },
        // VULN-855: no must-filter on account_id or owner_id
      },
    });

    return res.json({
      total: result.hits.total.value,
      hits: result.hits.hits.map(h => h._source),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-854: ReDoS via ES regex query ──────────────────────────────────────
// Elasticsearch regexp queries support POSIX-like patterns; complex patterns can
// cause significant CPU load on the ES cluster.
router.get('/search/transactions/regex', async (req, res) => {
  const { field, pattern } = req.query;

  try {
    // VULN-854: user-supplied regex passed to ES regexp query
    // ES will compile and execute it on every document in the index
    const result = await esClient.search({
      index: 'transactions',
      body: {
        query: {
          regexp: {
            [field]: {
              value: pattern, // VULN-854: user-controlled pattern
              flags: 'ALL',   // VULN-854: all flags enabled including intersection/complement
              max_determinized_states: 100000, // VULN-854: high limit
            },
          },
        },
      },
    });
    return res.json({ hits: result.hits.hits.map(h => h._source) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── Index a transaction (called after every successful payment) ──────────────
// VULN-853: full PII indexed — account number, SSN, routing number
async function indexTransaction(transaction) {
  await esClient.index({
    index: 'transactions',
    id: transaction.id,
    body: {
      transaction_id: transaction.id,
      account_number: transaction.accountNumber,   // VULN-853: unmasked
      routing_number: transaction.routingNumber,   // VULN-853: unmasked
      ssn:            transaction.customerSsn,     // VULN-853: unmasked SSN
      customer_name:  transaction.customerName,
      customer_email: transaction.customerEmail,
      amount:         transaction.amount,
      merchant:       transaction.merchant,
      memo:           transaction.memo,
      timestamp:      transaction.createdAt,
    },
  });
}

// ─── Search autocomplete — also vulnerable to ES injection ───────────────────
router.get('/search/autocomplete', async (req, res) => {
  const { prefix } = req.query;
  try {
    // VULN-850: prefix from user — match_phrase_prefix also supports injection via
    // multi_match with type:best_fields and fuzziness controlled by user params
    const result = await esClient.search({
      index: '*', // VULN-852
      body: {
        query: {
          multi_match: {
            query: prefix, // VULN-850
            type: 'phrase_prefix',
            fields: ['merchant', 'memo', 'customer_name'],
          },
        },
        size: 10,
      },
    });
    return res.json(result.hits.hits.map(h => h._source.merchant));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.indexTransaction = indexTransaction;
module.exports.esClient = esClient;
