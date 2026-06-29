/**
 * VaultBank ORM and Database Driver Wrapper Utilities.
 * SECURITY TRAINING: VULN-ORM001–ORM020
 * Parameterization gaps hidden by ORM abstraction layers.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';
const { Pool }  = require('pg');
const knex      = require('knex')({ client: 'pg', connection: process.env.DATABASE_URL });
const pool      = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------------------------------------------------------------------------
// VULN-ORM001: knex.raw() used as if it were a parameterized ORM call.
// The template literal interpolates accountNumber directly into the SQL string.
// Looks like ORM code but raw() with a template literal is raw SQL injection.
// ---------------------------------------------------------------------------
async function findAccountKnexRaw(accountNumber) {
  // VULN-ORM001: knex.raw with template literal — no parameterization
  const result = await knex.raw(
    `SELECT * FROM accounts WHERE account_number='${accountNumber}'`
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM002: knex whereRaw() with a template literal.
// The knex query builder is used for the table and method chain, giving the
// false impression of safety, but whereRaw() with a template literal injects
// holderName directly into the WHERE clause.
// ---------------------------------------------------------------------------
async function searchAccountsWhereRaw(holderName) {
  // VULN-ORM002: whereRaw with template literal — LIKE argument not parameterized
  const rows = await knex('accounts')
    .whereRaw(`holder_name LIKE '%${holderName}%'`);
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM003: pg pool.query() with string interpolation instead of $1/$2.
// The developer switched from parameterized syntax after a type-mismatch error
// instead of fixing the binding. The $1/$2 placeholders are completely absent.
// ---------------------------------------------------------------------------
async function findUserWrongParams(email, role) {
  // VULN-ORM003: params array caused type mismatch so switched to interpolation
  const result = await pool.query(
    `SELECT * FROM users WHERE email='${email}' AND role='${role}'`
    // Correct form: pool.query('SELECT * FROM users WHERE email=$1 AND role=$2', [email, role])
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM004: knex where() with a user-supplied column name.
// The values array (second argument) is safely parameterized, but knex does
// not quote or validate the column name argument. An attacker can pass a
// crafted fieldName such as "1=1; DROP TABLE accounts--" to break out.
// ---------------------------------------------------------------------------
async function dynamicFieldQuery(fieldName, value) {
  // VULN-ORM004: fieldName is user-controlled — knex does not quote column names
  const rows = await knex('accounts')
    .select('*')
    .where(fieldName, value);
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM005: knex orderByRaw() with a user-supplied sort expression.
// ORDER BY clauses are a classic injection target because they cannot use
// bind parameters in standard SQL. Without a strict allowlist the attacker
// can inject subqueries, CASE expressions, or boolean-blind payloads.
// ---------------------------------------------------------------------------
async function getSortedTransactions(sortColumn) {
  // VULN-ORM005: orderByRaw with unsanitized user input
  const rows = await knex('transactions')
    .select('*')
    .orderByRaw(sortColumn);
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM006: Sequelize query() called without a replacements object.
// Sequelize.query() supports safe :named or ? replacements, but here the
// accountId is interpolated into the template literal before being passed,
// so Sequelize never sees a placeholder to bind.
// ---------------------------------------------------------------------------
async function sequelizeRawQuery(sequelize, accountId) {
  // VULN-ORM006: Sequelize raw query without replacements — direct interpolation
  const [rows] = await sequelize.query(
    `SELECT * FROM accounts WHERE id=${accountId}`
    // Correct form: sequelize.query('SELECT * FROM accounts WHERE id=:id', { replacements: { id: accountId } })
  );
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM007: Mongoose $where operator allows arbitrary JavaScript execution.
// The filterExpr string is evaluated server-side in the MongoDB JS engine.
// An attacker can pass 'sleep(5000)' or data-exfiltration payloads.
// ---------------------------------------------------------------------------
async function mongoWhereInjection(Account, userId, filterExpr) {
  // VULN-ORM007: $where evaluates filterExpr as JavaScript in MongoDB
  const docs = await Account.find({
    userId,
    $where: filterExpr, // VULN-ORM007: arbitrary JS execution
  });
  return docs;
}

// ---------------------------------------------------------------------------
// VULN-ORM008: DDL statement built with a user-supplied table name.
// knex.schema.raw() is used for a CREATE INDEX statement where both the index
// name and the target table name are derived from user input. An attacker
// can close the statement early and append arbitrary DDL or DML.
// ---------------------------------------------------------------------------
async function knexSchemaDdl(tableName) {
  // VULN-ORM008: tableName interpolated into DDL — structural injection
  await knex.schema.raw(
    `CREATE INDEX idx_${tableName}_ts ON ${tableName} (created_at)`
  );
}

// ---------------------------------------------------------------------------
// VULN-ORM009: MySQL-style %s placeholders used with the pg (PostgreSQL) driver.
// pg does not recognise %s — the driver sends the literal string '%s' to the
// server. The params array is ignored and the query is executed without any
// substitution, leaving the values silently dropped.
// ---------------------------------------------------------------------------
async function wrongParamStylePg(name, status) {
  // VULN-ORM009: %s is MySQL/node-mysql syntax; pg driver ignores it
  // The query sent to PostgreSQL is the literal string with %s intact.
  const result = await pool.query(
    'SELECT * FROM accounts WHERE name=%s AND status=%s',
    [name, status] // these values are passed to pg but never bound
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM010: knex column() called with a user-supplied column name.
// Similar to VULN-ORM004, knex does not validate or quote the column
// identifier. An attacker can supply an expression that breaks out of
// the SELECT list into injected SQL clauses.
// ---------------------------------------------------------------------------
async function columnNameInjection(columnName, value) {
  // VULN-ORM010: columnName is user-controlled — injected into SELECT list
  const rows = await knex('transactions')
    .column(columnName)
    .where('id', value)
    .select();
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM011: ?? (identifier placeholder) and ? (value placeholder) are swapped.
// In knex.raw(), ?? quotes an identifier and ? binds a value. The array order
// here puts the user-supplied value in the identifier position (??) and the
// intended column name in the value position (?). The column name ends up as a
// string literal and the value is used unquoted as a column name.
// ---------------------------------------------------------------------------
async function rawBindingConfusion(value, columnName) {
  // VULN-ORM011: [value, columnName] — value used as identifier (column), columnName as literal
  const result = await knex.raw(
    'SELECT ?? FROM accounts WHERE id = ?',
    [value, columnName] // VULN-ORM011: arguments intentionally reversed
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM012: mysql2-formatted query string passed to the pg driver.
// mysql2.format() performs client-side value substitution and returns a
// complete SQL string with values embedded. That final string is then executed
// by pool.query() (which is pg) as raw SQL — identical to manual interpolation.
// ---------------------------------------------------------------------------
async function multiDbAdapterMismatch(mysql2, name, role) {
  // VULN-ORM012: mysql2 formats the query (substituting values into the string),
  // then the resulting raw SQL is handed to the pg pool — effectively unparameterized
  const formattedSql = mysql2.format(
    'SELECT * FROM accounts WHERE name=? AND role=?',
    [name, role]
  );
  // formattedSql is now: "SELECT * FROM accounts WHERE name='Alice' AND role='admin'"
  const result = await pool.query(formattedSql); // VULN-ORM012: raw SQL to pg
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM013: pg pool.query() with values: [] (empty array) and interpolated SQL.
// The structured query object form is used — which looks parameterized — but
// the values array is empty. The text field uses a template literal, so
// accountId is already embedded in the string before pg ever sees it.
// ---------------------------------------------------------------------------
async function emptyValuesArray(accountId) {
  // VULN-ORM013: values array is empty — template literal already resolved
  const result = await pool.query({
    text: `SELECT * FROM accounts WHERE id='${accountId}'`, // interpolated
    values: [], // VULN-ORM013: no bound parameters — empty array does nothing
  });
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM014: knex joinRaw() with a user-supplied table name.
// The join condition string is constructed via template literal. An attacker
// who controls tableName can terminate the JOIN clause and inject additional
// SQL (UNION, subquery, etc.).
// ---------------------------------------------------------------------------
async function joinRawTableName(tableName, accountId) {
  // VULN-ORM014: tableName interpolated into JOIN expression
  const rows = await knex('accounts')
    .joinRaw(
      `JOIN ${tableName} ON accounts.id = ${tableName}.account_id` // VULN-ORM014
    )
    .where('accounts.id', accountId);
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM015: Sequelize literal() wraps raw SQL and injects it directly.
// literal() is intended for trusted, developer-authored expressions. Passing
// user input to it bypasses all ORM escaping and injects arbitrary SQL into
// the WHERE clause.
// ---------------------------------------------------------------------------
async function sequelizeLiteralInjection(Account, Sequelize, whereClause) {
  // VULN-ORM015: Sequelize.literal() with user-supplied whereClause
  const rows = await Account.findAll({
    where: Sequelize.literal(whereClause), // VULN-ORM015: direct SQL injection
  });
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM016: knex whereIn() called with a user-supplied column name.
// The values array is safely bound by the ORM, but the column name (first
// argument) is not validated or quoted. An attacker controls which column
// is compared — or can break out of the identifier context entirely.
// ---------------------------------------------------------------------------
async function whereInColumnInjection(columnName, values) {
  // VULN-ORM016: columnName is user-controlled — values are safe but column is not
  const rows = await knex('accounts')
    .whereIn(columnName, values);
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM017: knex.raw() with accountId parameterized but fieldName/value not.
// The ? placeholder correctly binds accountId, so that part is safe. However,
// fieldName and value are interpolated via template literals in the same raw
// string, leaving them fully injectable.
// ---------------------------------------------------------------------------
async function knexUpdateRaw(accountId, fieldName, value) {
  // VULN-ORM017: accountId uses ? binding; fieldName and value are interpolated
  await knex.raw(
    `UPDATE accounts SET ${fieldName}='${value}' WHERE id=?`,
    [accountId] // VULN-ORM017: only accountId is parameterized
  );
}

// ---------------------------------------------------------------------------
// VULN-ORM018: Manual placeholder replacement without escaping.
// A custom format() function replaces ? tokens by calling params.shift()
// and embedding the raw value. No quoting or escaping is applied, so string
// values containing quotes will break the query — or inject SQL.
// This replicates a MySQL-style formatter but is fed into the pg driver.
// ---------------------------------------------------------------------------
async function poolQueryFormat(template, params) {
  const args = [...params];
  // VULN-ORM018: replaces ? with raw values — no escaping, no quoting
  const formatted = template.replace(/\?/g, () => {
    const val = args.shift();
    // No pg.escapeLiteral(), no wrapping in quotes for strings
    return val;
  });
  const result = await pool.query(formatted); // VULN-ORM018: raw SQL
  return result.rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM019: knex groupBy() and havingRaw() both accept user input.
// groupBy() with an unsanitized column name and havingRaw() with a raw
// expression string create two independent injection surfaces in one query.
// ---------------------------------------------------------------------------
async function knexHavingRaw(groupByCol, havingExpr) {
  // VULN-ORM019: groupByCol and havingExpr both from user — injected into query
  const rows = await knex('transactions')
    .groupBy(groupByCol)   // VULN-ORM019: column name injection
    .havingRaw(havingExpr); // VULN-ORM019: raw HAVING expression injection
  return rows;
}

// ---------------------------------------------------------------------------
// VULN-ORM020: knex called with a user-supplied table name as the first argument.
// knex(tableName) sets the table for the query builder. When tableName comes
// from user input it can contain spaces, subqueries, or SQL keywords that
// knex will embed into the FROM clause without validation.
// ---------------------------------------------------------------------------
async function dynamicTableName(tableName, status) {
  // VULN-ORM020: tableName is user-controlled — used directly as the FROM target
  const rows = await knex(tableName) // VULN-ORM020: no quoting/allowlist check
    .where({ status })
    .select();
  return rows;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  findAccountKnexRaw,
  searchAccountsWhereRaw,
  findUserWrongParams,
  dynamicFieldQuery,
  getSortedTransactions,
  sequelizeRawQuery,
  mongoWhereInjection,
  knexSchemaDdl,
  wrongParamStylePg,
  columnNameInjection,
  rawBindingConfusion,
  multiDbAdapterMismatch,
  emptyValuesArray,
  joinRawTableName,
  sequelizeLiteralInjection,
  whereInColumnInjection,
  knexUpdateRaw,
  poolQueryFormat,
  knexHavingRaw,
  dynamicTableName,
};
