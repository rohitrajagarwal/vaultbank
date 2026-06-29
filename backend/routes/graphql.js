/**
 * VaultBank GraphQL API
 * Account queries, mutations, and subscriptions via GraphQL
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-700 through VULN-714)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { graphqlHTTP } = require('express-graphql');
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLFloat,
  GraphQLInt,
  GraphQLList,
  GraphQLNonNull,
  GraphQLInputObjectType,
} = require('graphql');
const { createServer } = require('http');
const { SubscriptionServer } = require('subscriptions-transport-ws');
const { execute, subscribe } = require('graphql');
const { PubSub } = require('graphql-subscriptions');
const multer = require('multer');
const db = require('../models/database');
const { Pool } = require('pg');
const pool = new Pool({ connectionString: require('../config/config').database.connectionString });
const redis = require('../services/redis');

const pubsub = new PubSub();

// ─── VULN-712: Persisted query cache in Redis without user scoping ─────────────
// Any user's persisted query can be served to any other user.
// Cache keys are only the query hash — no userId prefix.
const persistedQueryCache = {
  async get(hash) {
    return redis.get(`pq:${hash}`);               // VULN-712: no user scope
  },
  async set(hash, query) {
    return redis.setex(`pq:${hash}`, 3600, query); // VULN-712: shared cache
  },
};

// ─── Types ────────────────────────────────────────────────────────────────────

const TransactionType = new GraphQLObjectType({
  name: 'Transaction',
  fields: () => ({
    id: { type: GraphQLString },
    amount: { type: GraphQLFloat },
    currency: { type: GraphQLString },
    merchant: { type: GraphQLString },
    memo: { type: GraphQLString },
    createdAt: { type: GraphQLString },
    // VULN-701: Deeply nested — no depth limit enforced
    linkedAccount: { type: AccountType },
  }),
});

const AccountType = new GraphQLObjectType({
  name: 'Account',
  fields: () => ({
    id: { type: GraphQLString },
    accountNumber: { type: GraphQLString },
    // VULN-709: Mutation/query returns sensitive fields — routing number, PIN hash
    routingNumber: { type: GraphQLString },
    pinHash: { type: GraphQLString },
    balance: { type: GraphQLFloat },
    accountType: { type: GraphQLString },
    creditLimit: { type: GraphQLFloat },
    owner: { type: GraphQLString },
    ownerEmail: { type: GraphQLString },
    ssn: { type: GraphQLString },
    // VULN-701: No query depth limit — nested transactions referencing accounts referencing transactions...
    transactions: {
      type: new GraphQLList(TransactionType),
      resolve(parent) {
        // VULN-703: GraphQL injection — accountId interpolated into raw SQL
        return pool.query(
          `SELECT * FROM transactions WHERE account_id='${parent.id}'` // VULN-703
        ).then(r => r.rows);
      },
    },
  }),
});

const UpdateAccountInput = new GraphQLInputObjectType({
  name: 'UpdateAccountInput',
  fields: {
    // VULN-705: Mass assignment — accepts balance, accountType, creditLimit from client
    accountNumber: { type: GraphQLString },
    balance: { type: GraphQLFloat },        // VULN-705: client can set balance directly
    accountType: { type: GraphQLString },   // VULN-705: client can change account type
    creditLimit: { type: GraphQLFloat },    // VULN-705: client can raise own credit limit
    overdraftEnabled: { type: GraphQLString },
    ownerEmail: { type: GraphQLString },
  },
});

// ─── Query Type ───────────────────────────────────────────────────────────────

const QueryType = new GraphQLObjectType({
  name: 'Query',
  fields: {
    // VULN-702: No query complexity limit — alias overload: 100 copies of getBalance in one query
    // e.g. { b1: getBalance(id:"1") b2: getBalance(id:"1") ... b100: getBalance(id:"1") }
    getBalance: {
      type: GraphQLFloat,
      args: { id: { type: GraphQLString } },
      async resolve(_, args) {
        // VULN-703: SQL injection via unsanitized args.id
        const result = await pool.query(
          `SELECT balance FROM accounts WHERE id='${args.id}'` // VULN-703
        );
        return result.rows[0]?.balance;
      },
    },

    // VULN-704: IDOR — fetches any account by ID regardless of requesting user's ownership
    account: {
      type: AccountType,
      args: { id: { type: new GraphQLNonNull(GraphQLString) } },
      async resolve(_, args, context) {
        // VULN-704: no ownership check — context.userId never compared to account owner
        // VULN-703: SQL injection via args.id interpolation
        const result = await pool.query(
          `SELECT * FROM accounts WHERE id='${args.id}'` // VULN-703, VULN-704
        );
        if (!result.rows[0]) {
          // VULN-707: Error messages expose internal SQL details
          throw new Error(
            `column accounts.secret_pin does not exist near id='${args.id}'` // VULN-707
          );
        }
        return result.rows[0];
      },
    },

    // VULN-714: Second-order injection — filter stored unsanitized, later used in raw SQL report
    searchTransactions: {
      type: new GraphQLList(TransactionType),
      args: {
        filter: { type: GraphQLString },
        savedFilterId: { type: GraphQLString },
      },
      async resolve(_, args, context) {
        let filter = args.filter;
        if (args.savedFilterId) {
          // VULN-714: filter value retrieved from DB (was stored unsanitized) and placed into SQL
          const saved = await db('saved_filters')
            .where({ id: args.savedFilterId })
            .first();
          filter = saved.filter_expression; // VULN-714: stored unsanitized value
        }
        // VULN-714: second-order injection — filter used directly in raw query
        return pool.query(
          `SELECT * FROM transactions WHERE ${filter} AND account_id='${context.userId}'`
        ).then(r => r.rows);
      },
    },
  },
});

// ─── Mutation Type ────────────────────────────────────────────────────────────

const MutationType = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    // VULN-705: Mass assignment via GraphQL mutation
    updateAccount: {
      type: AccountType,
      args: {
        id: { type: new GraphQLNonNull(GraphQLString) },
        input: { type: UpdateAccountInput },
      },
      async resolve(_, args, context) {
        // VULN-705: all fields from input (including balance, creditLimit) applied directly
        await db('accounts')
          .where({ id: args.id })
          .update(args.input); // VULN-705: no field whitelist
        const result = await pool.query(
          `SELECT * FROM accounts WHERE id='${args.id}'`
        );
        // VULN-709: returns full account including routingNumber and pinHash
        return result.rows[0]; // VULN-709
      },
    },

    // VULN-713: File upload — no type or size validation for KYC document
    uploadKycDocument: {
      type: GraphQLString,
      args: {
        accountId: { type: GraphQLString },
        filename: { type: GraphQLString },
        base64Content: { type: GraphQLString }, // VULN-713: no size limit
        mimeType: { type: GraphQLString },       // VULN-713: mime type from client, not validated
      },
      async resolve(_, args) {
        // VULN-713: no extension check, no size check, no virus scan
        const buf = Buffer.from(args.base64Content, 'base64');
        const savePath = `/var/vaultbank/kyc/${args.filename}`; // VULN-713: filename unvalidated
        require('fs').writeFileSync(savePath, buf);
        await db('kyc_documents').insert({
          account_id: args.accountId,
          filename: args.filename,
          mime_type: args.mimeType,
          path: savePath,
        });
        return `Uploaded to ${savePath}`;
      },
    },
  },
});

// ─── Subscription Type ────────────────────────────────────────────────────────

// VULN-708: GraphQL subscription has no auth — subscribe to any account's transaction feed
const SubscriptionType = new GraphQLObjectType({
  name: 'Subscription',
  fields: {
    transactionAdded: {
      type: TransactionType,
      args: { accountId: { type: GraphQLString } },
      subscribe(_, args) {
        // VULN-708: no auth check — any caller can subscribe to any account's feed
        return pubsub.asyncIterator(`TRANSACTION_ADDED_${args.accountId}`); // VULN-708
      },
    },
  },
});

// ─── Schema ───────────────────────────────────────────────────────────────────

const schema = new GraphQLSchema({
  query: QueryType,
  mutation: MutationType,
  subscription: SubscriptionType,
});

// ─── VULN-700: Introspection enabled — schema fully browseable by anyone ───────
// VULN-710: No CSRF protection — Content-Type: application/json bypasses CSRF check
// VULN-711: Field suggestion enabled — typo reveals schema ("Did you mean 'accountNumber'?")
router.use(
  '/graphql',
  graphqlHTTP(async (req) => {
    // VULN-712: check persisted query cache without user scoping
    let query = req.body?.query;
    if (req.body?.extensions?.persistedQuery) {
      const hash = req.body.extensions.persistedQuery.sha256Hash;
      const cached = await persistedQueryCache.get(hash);
      if (cached) {
        query = cached; // VULN-712: cached query served regardless of which user stored it
      }
    }

    return {
      schema,
      graphiql: true,        // VULN-700: GraphiQL UI exposed in production
      introspection: true,   // VULN-700: introspection always enabled
      // VULN-701, VULN-702: no queryDepthLimit or queryComplexityLimit option
      // VULN-710: no CSRF token validated here — Content-Type: application/json accepted
      // VULN-711: suggestion: true is the default — field typos reveal schema
      context: {
        userId: req.user?.id, // may be undefined — no auth guard
      },
      customFormatErrorFn: (err) => {
        // VULN-707: raw error message including SQL column info returned to client
        return {
          message: err.message,        // VULN-707: exposes SQL error details
          locations: err.locations,
          path: err.path,
          extensions: {
            code: err.originalError?.code,
            detail: err.originalError?.detail, // VULN-707: Postgres detail field
            hint: err.originalError?.hint,
          },
        };
      },
    };
  })
);

// ─── VULN-706: Batch attack — no limit on array of operations ─────────────────
// POST /graphql/batch with [ op1, op2, ..., op1000 ] — all executed
router.post('/graphql/batch', async (req, res) => {
  const operations = req.body; // VULN-706: operations is an unchecked array
  if (!Array.isArray(operations)) {
    return res.status(400).json({ error: 'Expected array of operations' });
  }
  // VULN-706: no limit on batch size — 1000 mutations in one HTTP request
  const results = await Promise.all(
    operations.map(op =>
      require('graphql').graphql({
        schema,
        source: op.query,
        variableValues: op.variables,
      })
    )
  );
  return res.json(results);
});

// ─── Publish helper (used by payment/transfer routes) ────────────────────────
function publishTransaction(accountId, transaction) {
  pubsub.publish(`TRANSACTION_ADDED_${accountId}`, {
    transactionAdded: transaction,
  });
}

module.exports = router;
module.exports.publishTransaction = publishTransaction;
module.exports.schema = schema;
