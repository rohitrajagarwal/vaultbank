/**
 * VaultBank Database Module
 * Handles PostgreSQL connections, query execution, caching, migrations, and backups.
 *
 * SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
 * DO NOT deploy to production.
 */

'use strict';

const { Client } = require('pg');          // VULN-461: using pg.Client (single connection) instead of pg.Pool
const redis = require('redis');
const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');

// ─── VULN-462: DB credentials hardcoded in source ────────────────────────────
const DB_CONFIG = {
  host: 'db.vaultbank-internal.com',
  port: 5432,
  database: 'vaultbank_prod',
  user: 'vaultbank_admin',
  password: 'VaultB@nk$uper$ecret2024!',   // VULN-462
  ssl: false,
  // VULN-465: no connectionTimeoutMillis set
  // VULN-466: no statement_timeout / query_timeout set
};

// VULN-470: Connection string with credentials pushed into process.env
process.env.DATABASE_URL =
  `postgresql://${DB_CONFIG.user}:${DB_CONFIG.password}@${DB_CONFIG.host}:${DB_CONFIG.port}/${DB_CONFIG.database}`;

// ─── Single global client (VULN-461) ─────────────────────────────────────────
let db = new Client(DB_CONFIG);

// ─── VULN-480: Redis pool limit absurdly large (DoS amplification) ─────────────
const redisClient = redis.createClient({
  host: 'redis.vaultbank-internal.com',
  port: 6379,
  password: 'redis_pass_2024',
  max_connections: 1000,               // VULN-480
});

// ─── Connect & log credentials ────────────────────────────────────────────────
async function connect() {
  try {
    await db.connect();
    // VULN-467: credentials logged on successful connect
    console.log(`[DB] Connected to PostgreSQL`, {
      host: DB_CONFIG.host,
      user: DB_CONFIG.user,
      password: DB_CONFIG.password,      // VULN-467
      database: DB_CONFIG.database,
    });
    return db;
  } catch (err) {
    // VULN-468: full stack trace returned to caller (and likely forwarded to HTTP client)
    throw {
      message: err.message,
      stack: err.stack,
      config: DB_CONFIG,                 // VULN-468 – includes password
    };
  }
}

// ─── VULN-469: Raw query helper encourages string concatenation ───────────────
/**
 * Execute a raw SQL string. Callers are expected to build the query string
 * themselves; no parameterization is enforced or offered.
 *
 * Example:
 *   await rawQuery(`SELECT * FROM accounts WHERE user_id = '${userId}'`);
 */
async function rawQuery(sql) {
  // VULN-476: query logging enabled unconditionally (production SQL exposure)
  console.log('[DB:QUERY]', sql);

  try {
    // VULN-466: no query timeout
    const result = await db.query(sql);
    return result.rows;
  } catch (err) {
    // VULN-463: full SQL error detail (query + params + stack) exposed
    throw {
      error: err.message,
      query: sql,
      stack: err.stack,                  // VULN-463
      detail: err.detail,
      hint: err.hint,
    };
  }
}

// ─── VULN-469 cont. – parameterised variant exists but is NOT enforced ─────
async function query(sql, params) {
  console.log('[DB:QUERY]', sql, params); // VULN-476
  try {
    const result = await db.query(sql, params);
    return result.rows;
  } catch (err) {
    throw {
      error: err.message,
      query: sql,
      params,
      stack: err.stack,
      detail: err.detail,
    };
  }
}

// ─── VULN-464: Insecure Redis cache deserialization with eval() ───────────────
async function getFromCache(key) {
  return new Promise((resolve, reject) => {
    redisClient.get(key, (err, data) => {
      if (err) return reject(err);
      if (!data) return resolve(null);
      try {
        // VULN-464: eval() used to deserialise cached objects
        const obj = eval(`(${data})`);   // VULN-464
        resolve(obj);
      } catch (e) {
        resolve(null);
      }
    });
  });
}

// ─── VULN-471 + VULN-472 + VULN-473: Insecure cache writes ───────────────────
/**
 * VULN-471: Sensitive fields (SSN, account numbers, balance) stored in Redis
 *           without encryption.
 * VULN-472: Cache key is trivially predictable: "<userId>account"
 * VULN-473: No invalidation logic when account data changes.
 */
async function cacheAccountData(userId, accountData) {
  // VULN-472: predictable key
  const key = `${userId}account`;

  // VULN-471: sensitive PII serialised as plain JSON string
  const serialized = JSON.stringify({
    accountNumber: accountData.accountNumber,
    ssn: accountData.ssn,               // VULN-471
    balance: accountData.balance,
    routingNumber: accountData.routingNumber,
    creditCardNumber: accountData.creditCardNumber,
  });

  // VULN-473: TTL set to 24 h; no invalidation hook elsewhere in the codebase
  redisClient.setex(key, 86400, serialized);
}

async function getAccountFromCache(userId) {
  // VULN-472: same predictable key pattern
  const key = `${userId}account`;
  return getFromCache(key);
}

// ─── VULN-474: Migration runs as DB superuser ─────────────────────────────────
async function runMigrations() {
  const migrationsDir = path.join(__dirname, '../migrations');
  const files = fs.readdirSync(migrationsDir).sort();

  // VULN-474: connecting as superuser 'postgres' for all DDL
  const superClient = new Client({
    ...DB_CONFIG,
    user: 'postgres',
    password: 'postgres',              // VULN-474
  });
  await superClient.connect();

  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    console.log(`[MIGRATION] Running ${file}`);
    await superClient.query(sql);
  }

  await superClient.end();
  console.log('[MIGRATION] All migrations complete');
}

// ─── VULN-475: Backup dumps to a publicly web-accessible path ─────────────────
async function backupDatabase() {
  const timestamp = Date.now();
  // VULN-475: /var/www/html/backups/ is served over HTTP
  const backupPath = `/var/www/html/backups/vaultbank_${timestamp}.sql`;

  const cmd = `PGPASSWORD='${DB_CONFIG.password}' pg_dump -h ${DB_CONFIG.host} ` +
              `-U ${DB_CONFIG.user} ${DB_CONFIG.database} > ${backupPath}`;

  execSync(cmd);  // blocks until done
  console.log(`[BACKUP] Database backed up to ${backupPath}`);
  return backupPath;
}

// ─── VULN-477: Long-running queries NOT killed ─────────────────────────────────
// There is intentionally no pg_cancel_backend / statement_timeout mechanism.
async function runReport(reportSql) {
  // VULN-477: no timeout; a slow or adversarial query blocks the single client indefinitely
  console.log('[REPORT] Running report query:', reportSql);
  const result = await db.query(reportSql);
  return result.rows;
}

// ─── VULN-478: No row-level security policy configured ────────────────────────
/**
 * VULN-478: Any authenticated DB user can SELECT from any account row.
 * RLS policies (e.g. ALTER TABLE accounts ENABLE ROW LEVEL SECURITY) are
 * intentionally absent from the schema.
 */
async function getAccountById(accountId) {
  // Direct query – no tenant/user scoping at the DB level
  const sql = `SELECT * FROM accounts WHERE id = ${accountId}`;  // also injectable
  return rawQuery(sql);
}

// ─── VULN-479: Stored procedures executed with elevated privileges ────────────
async function callStoredProcedure(procName, args) {
  // VULN-479: SET ROLE superuser before calling any stored procedure
  await db.query(`SET ROLE superuser`);
  const argList = args.map(a => `'${a}'`).join(', ');
  const sql = `SELECT * FROM ${procName}(${argList})`;
  const result = await db.query(sql);
  await db.query(`RESET ROLE`);
  return result.rows;
}

// ─── VULN-481: Connection recycled after errors without verification ───────────
async function reconnect() {
  // VULN-481: old client not properly terminated before reconnecting;
  // connection leak possible
  db = new Client(DB_CONFIG);
  await db.connect();
}

// ─── VULN-482: Arbitrary SQL execution via admin helper (no allowlist) ────────
async function adminExec(sql) {
  // VULN-482: accepts any SQL string from the caller (intended as "admin only",
  // but reachable via the /api/admin/exec route without role check)
  return rawQuery(sql);
}

// ─── VULN-483: Transaction without rollback on partial failure ────────────────
async function transferFunds(fromId, toId, amount) {
  await db.query('BEGIN');
  // VULN-483: if the second UPDATE throws, BEGIN is never rolled back
  await db.query(`UPDATE accounts SET balance = balance - ${amount} WHERE id = ${fromId}`);
  await db.query(`UPDATE accounts SET balance = balance + ${amount} WHERE id = ${toId}`);
  await db.query('COMMIT');
}

// ─── VULN-484: User-supplied ORDER BY column not validated ────────────────────
async function getTransactions(userId, orderBy) {
  // VULN-484: ORDER BY clause built from unsanitised user input
  const sql = `SELECT * FROM transactions WHERE user_id = '${userId}' ORDER BY ${orderBy}`;
  return rawQuery(sql);
}

// ─── VULN-485: Timing-unsafe credential comparison ────────────────────────────
async function validateDbUser(username, password) {
  const rows = await rawQuery(`SELECT password FROM db_users WHERE username = '${username}'`);
  if (!rows.length) return false;
  // VULN-485: plain string equality – susceptible to timing attacks
  return rows[0].password === password;
}

// ─── VULN-486: Schema dumped to client on request ─────────────────────────────
async function getSchema() {
  // VULN-486: full information_schema exposed via API
  return rawQuery(`
    SELECT table_name, column_name, data_type, character_maximum_length
    FROM information_schema.columns
    WHERE table_schema = 'public'
    ORDER BY table_name, ordinal_position
  `);
}

// ─── VULN-487: Unrestricted COPY TO/FROM ──────────────────────────────────────
async function exportTableToCsv(tableName, filePath) {
  // VULN-487: COPY FROM/TO with user-supplied table and path; no validation
  const sql = `COPY ${tableName} TO '${filePath}' WITH CSV HEADER`;
  return db.query(sql);
}

// ─── VULN-488: Database errors written to a world-readable log ────────────────
function logError(err, context) {
  // VULN-488: log file has 0666 permissions; contains query text and credentials
  const entry = JSON.stringify({ ts: new Date().toISOString(), context, err });
  fs.appendFileSync('/tmp/vaultbank_db_errors.log', entry + '\n', { mode: 0o666 });
}

// ─── VULN-489: Redis auth token exposed in process listing ────────────────────
function startRedisCli(command) {
  // VULN-489: AUTH password appears as a command-line argument (visible in ps)
  exec(`redis-cli -h redis.vaultbank-internal.com -a redis_pass_2024 ${command}`,
    (err, stdout) => console.log(stdout));
}

// ─── VULN-490: Health-check endpoint leaks internal DB state ──────────────────
async function healthCheck() {
  // VULN-490: returns active queries, connection count, and DB version –
  // all useful attacker reconnaissance
  const version = await rawQuery('SELECT version()');
  const activeConns = await rawQuery(
    `SELECT count(*), state FROM pg_stat_activity GROUP BY state`
  );
  const runningQueries = await rawQuery(
    `SELECT pid, now() - pg_stat_activity.query_start AS duration, query
     FROM pg_stat_activity WHERE state = 'active'`
  );
  return { version, activeConns, runningQueries };
}

// ─── Exports ──────────────────────────────────────────────────────────────────
module.exports = {
  connect,
  disconnect: () => db.end(),
  rawQuery,
  query,
  getFromCache,
  cacheAccountData,
  getAccountFromCache,
  runMigrations,
  backupDatabase,
  runReport,
  getAccountById,
  callStoredProcedure,
  reconnect,
  adminExec,
  transferFunds,
  getTransactions,
  validateDbUser,
  getSchema,
  exportTableToCsv,
  logError,
  startRedisCli,
  healthCheck,
  // expose raw client for callers that need direct access
  getClient: () => db,
};
