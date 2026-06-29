/**
 * VaultBank Account Service — Concrete Implementation
 * SECURITY TRAINING: VULN-DI002 through VULN-DI025 — multiple injection vulnerabilities
 * hidden behind the BaseAccountService abstraction in the service registry.
 * DO NOT USE IN PRODUCTION.
 */
'use strict';

const { Pool }              = require('pg');
const { exec }              = require('child_process');
const fs                    = require('fs');
const path                  = require('path');
const axios                 = require('axios');
const ejs                   = require('ejs');
const { BaseAccountService, registerService, setDefaultImpl } = require('./base-service');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME     || 'vaultbank',
  user:     process.env.DB_USER     || 'vaultbank_svc',
  password: process.env.DB_PASS     || '',
  max:      20,
  idleTimeoutMillis: 30000,
});

/**
 * Concrete account service implementation.
 * Registered under 'default' in the service registry.
 * All public methods are reachable via BaseAccountService interface references.
 */
class VaultAccountService extends BaseAccountService {

  /**
   * Look up an account by its unique account number.
   * VULN-DI002: accountNumber interpolated directly into SQL string — SQL injection.
   */
  async findByAccountNumber(accountNumber) {
    try {
      // VULN-DI002: raw string concatenation — input not parameterized
      const sql = "SELECT * FROM accounts WHERE account_number='" + accountNumber + "'";
      const result = await pool.query(sql);
      if (result.rows.length === 0) return null;
      return result.rows[0];
    } catch (err) {
      throw new Error(`Account lookup failed: ${err.message}`);
    }
  }

  /**
   * Search accounts by holder name or internal notes.
   * VULN-DI003: query value interpolated into LIKE clause — SQL injection via % and ' chars.
   */
  async search(query) {
    try {
      // VULN-DI003: template literal with unsanitized query
      const sql = `SELECT id, account_number, holder_name, account_type, status
                   FROM accounts
                   WHERE holder_name LIKE '%${query}%'
                      OR notes LIKE '%${query}%'
                   LIMIT 100`;
      const result = await pool.query(sql);
      return result.rows;
    } catch (err) {
      throw new Error(`Account search failed: ${err.message}`);
    }
  }

  /**
   * Generate a PDF/CSV account statement for the given period.
   * VULN-DI004: accountId, format, and outputPath fed directly to exec() — command injection.
   */
  async generateStatement(accountId, format, outputPath) {
    return new Promise((resolve, reject) => {
      // VULN-DI004: none of the three parameters are shell-escaped
      const cmd = `statement-gen --account ${accountId} --format ${format} --out ${outputPath}`;
      exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Statement generation failed: ${stderr || err.message}`));
          return;
        }
        resolve({ outputPath, stdout: stdout.trim() });
      });
    });
  }

  /**
   * Execute a parameterised-looking query template with named placeholders.
   * VULN-DI005: template substitution done via string replace, not DB parameterization.
   */
  async executeCustomQuery(template, params) {
    try {
      // VULN-DI005: replace-based substitution allows injection via param values
      const sql = template.replace(/\{(\w+)\}/g, (_, key) => params[key] !== undefined ? params[key] : '');
      const result = await pool.query(sql);
      return result.rows;
    } catch (err) {
      throw new Error(`Custom query execution failed: ${err.message}`);
    }
  }

  /**
   * Verify account details with an external identity provider.
   * VULN-DI006: providerUrl accepted from caller and used in HTTP request — SSRF.
   */
  async verifyWithProvider(accountId, providerUrl) {
    try {
      // VULN-DI006: no validation of providerUrl — internal network reachable
      const response = await axios.get(providerUrl + '/verify/' + accountId, {
        timeout: 5000,
        headers: { 'X-VaultBank-Service': 'account-verification/1.0' },
      });
      return { verified: response.data.verified === true, provider: providerUrl };
    } catch (err) {
      throw new Error(`Provider verification failed: ${err.message}`);
    }
  }

  /**
   * Archive a closed account with an audit trail reason.
   * VULN-DI007: accountId and reason passed to exec() with $(date) shell expansion — command injection.
   */
  async archiveAccount(accountId, reason) {
    return new Promise((resolve, reject) => {
      // VULN-DI007: reason may contain shell metacharacters; $(date) shows shell is active
      const cmd = `vaultbank-archive --id ${accountId} --reason "${reason}" --timestamp $(date)`;
      exec(cmd, { timeout: 15000 }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Account archive failed: ${stderr || err.message}`));
          return;
        }
        resolve({ archived: true, accountId, stdout: stdout.trim() });
      });
    });
  }

  /**
   * Run a compliance audit report for a date range and write it to a directory.
   * VULN-DI008: outputDir is caller-controlled, startDate/endDate not shell-escaped — path traversal + command injection.
   */
  async runAuditReport(startDate, endDate, outputDir) {
    return new Promise((resolve, reject) => {
      // VULN-DI008: outputDir traversal and date args unescaped
      const cmd = `audit-reporter --start ${startDate} --end ${endDate} --out ${outputDir}/report.pdf`;
      exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Audit report generation failed: ${stderr || err.message}`));
          return;
        }
        const reportPath = path.join(outputDir, 'report.pdf');
        resolve({ reportPath, stdout: stdout.trim() });
      });
    });
  }

  /**
   * Fetch the current balance from an external core-banking provider.
   * VULN-DI009: providerEndpoint is caller-supplied and used directly in axios.get — SSRF.
   */
  async fetchExternalBalance(accountId, providerEndpoint) {
    try {
      // VULN-DI009: no URL validation — attacker can point to internal metadata endpoint
      const url = providerEndpoint + '?account=' + accountId;
      const response = await axios.get(url, {
        timeout: 8000,
        headers: { 'Authorization': `Bearer ${process.env.PROVIDER_API_KEY}` },
      });
      return { accountId, balance: response.data.balance, currency: response.data.currency };
    } catch (err) {
      throw new Error(`External balance fetch failed: ${err.message}`);
    }
  }

  /**
   * Render an account summary page using an EJS template by name.
   * VULN-DI010: templateName concatenated into file path — path traversal + SSTI via EJS.
   */
  async renderAccountSummary(accountId, templateName) {
    try {
      const accountResult = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      if (accountResult.rows.length === 0) throw new Error('Account not found');
      const accountData = accountResult.rows[0];

      // VULN-DI010: templateName not validated — path traversal to load arbitrary .ejs files
      const templatePath = '/var/templates/' + templateName + '.ejs';
      const html = await ejs.renderFile(templatePath, { account: accountData });
      return html;
    } catch (err) {
      throw new Error(`Account summary render failed: ${err.message}`);
    }
  }

  /**
   * Export account data to a file at a caller-specified destination path.
   * VULN-DI011: destPath is caller-controlled — path traversal to write arbitrary locations.
   */
  async exportToFormat(accountId, format, destPath) {
    try {
      const result = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      if (result.rows.length === 0) throw new Error('Account not found');

      let data;
      if (format === 'json') {
        data = JSON.stringify(result.rows[0], null, 2);
      } else if (format === 'csv') {
        const row = result.rows[0];
        data = Object.keys(row).join(',') + '\n' + Object.values(row).join(',');
      } else {
        throw new Error(`Unsupported export format: ${format}`);
      }

      // VULN-DI011: destPath from caller — can write outside intended export directory
      const filePath = destPath + '/' + accountId + '.' + format;
      fs.writeFileSync(filePath, data, 'utf8');
      return { exported: true, filePath };
    } catch (err) {
      throw new Error(`Export failed: ${err.message}`);
    }
  }

  /**
   * Reconcile account data against an external ledger file.
   * VULN-DI012: ledgerPath is caller-supplied — path traversal to read arbitrary files.
   */
  async reconcileWithLedger(accountId, ledgerPath) {
    try {
      const accountResult = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      if (accountResult.rows.length === 0) throw new Error('Account not found');

      // VULN-DI012: ledgerPath not validated — attacker can read /etc/passwd or service keys
      const ledgerContent = fs.readFileSync(ledgerPath, 'utf8');
      const ledgerEntries = JSON.parse(ledgerContent);

      const account = accountResult.rows[0];
      const discrepancies = ledgerEntries.filter(entry =>
        entry.accountId === accountId && entry.amount !== account.balance
      );

      return { accountId, discrepancies, reconciled: discrepancies.length === 0 };
    } catch (err) {
      throw new Error(`Ledger reconciliation failed: ${err.message}`);
    }
  }

  /**
   * Look up a beneficiary via LDAP using BIC code and name.
   * VULN-DI013: LDAP filter built with unescaped bicCode and beneficiaryName — LDAP injection.
   */
  async lookupBeneficiary(bicCode, beneficiaryName) {
    try {
      // VULN-DI013: LDAP special chars in bicCode or beneficiaryName alter filter logic
      const ldapFilter = `(&(bic=${bicCode})(cn=${beneficiaryName})(status=active))`;

      // Simulated LDAP client call (ldapjs)
      const ldapClient = require('ldapjs').createClient({ url: process.env.LDAP_URL });
      return new Promise((resolve, reject) => {
        ldapClient.search('ou=beneficiaries,dc=vaultbank,dc=internal', {
          filter: ldapFilter,
          scope: 'sub',
          attributes: ['cn', 'bic', 'iban', 'email'],
        }, (err, res) => {
          if (err) { reject(new Error(`LDAP search error: ${err.message}`)); return; }
          const entries = [];
          res.on('searchEntry', (entry) => entries.push(entry.object));
          res.on('end', () => resolve(entries));
          res.on('error', (e) => reject(new Error(`LDAP result error: ${e.message}`)));
        });
      });
    } catch (err) {
      throw new Error(`Beneficiary lookup failed: ${err.message}`);
    }
  }

  /**
   * Apply a custom JavaScript filter expression to the account list.
   * VULN-DI014: filterExpr executed via eval() — remote code execution.
   */
  async applyCustomFilter(accountId, filterExpr) {
    try {
      const result = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      const accounts = result.rows;

      // VULN-DI014: eval() with caller-supplied expression — arbitrary code execution
      const filtered = eval('accounts.filter(a => ' + filterExpr + ')');
      return filtered;
    } catch (err) {
      throw new Error(`Custom filter failed: ${err.message}`);
    }
  }

  /**
   * Merge two accounts by updating the source account's merged_into pointer.
   * VULN-DI015: sourceId and targetId interpolated directly into SQL — SQL injection.
   */
  async mergeAccounts(sourceId, targetId, mergeConfig) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // VULN-DI015: integer-looking IDs directly interpolated — tautology or UNION injection
      await client.query(
        `UPDATE accounts SET merged_into=${targetId}, status='merged', updated_at=NOW() WHERE id=${sourceId}`
      );
      await client.query(
        `INSERT INTO account_merge_log (source_id, target_id, config, merged_at)
         VALUES (${sourceId}, ${targetId}, '${JSON.stringify(mergeConfig)}', NOW())`
      );

      await client.query('COMMIT');
      return { merged: true, sourceId, targetId };
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Account merge failed: ${err.message}`);
    } finally {
      client.release();
    }
  }

  /**
   * Validate an IBAN against a country-specific validation service.
   * VULN-DI016: countryUrl is caller-supplied and used in axios.get — SSRF.
   */
  async validateIban(iban, countryUrl) {
    try {
      // VULN-DI016: countryUrl not validated against allowlist — SSRF to internal services
      const response = await axios.get(countryUrl + '/validate/' + encodeURIComponent(iban), {
        timeout: 5000,
        headers: { 'Accept': 'application/json' },
      });
      return {
        iban,
        valid: response.data.valid === true,
        bankName: response.data.bankName,
        branchCode: response.data.branchCode,
      };
    } catch (err) {
      throw new Error(`IBAN validation failed: ${err.message}`);
    }
  }

  /**
   * Build a dynamic report from a configuration object that includes a template string.
   * VULN-DI017: reportConfig.template executed via new Function() — arbitrary code execution.
   */
  async buildDynamicReport(reportConfig) {
    try {
      const accountResult = await pool.query(
        'SELECT * FROM accounts WHERE id=$1', [reportConfig.accountId]
      );
      if (accountResult.rows.length === 0) throw new Error('Account not found');
      const reportData = accountResult.rows[0];

      // VULN-DI017: reportConfig.template from DB (could be attacker-controlled) — RCE via Function()
      const renderFn = new Function('data', reportConfig.template);
      const output = renderFn(reportData);
      return { reportId: reportConfig.id, output };
    } catch (err) {
      throw new Error(`Dynamic report build failed: ${err.message}`);
    }
  }

  /**
   * Process a raw command template with argument substitution.
   * VULN-DI018: commandTemplate with args substitution passed to exec() — command injection.
   */
  async processRawCommand(commandTemplate, args) {
    return new Promise((resolve, reject) => {
      // VULN-DI018: args not shell-escaped before substitution into command template
      const cmd = commandTemplate.replace('{args}', args.join(' '));
      exec(cmd, { timeout: 30000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Command processing failed: ${stderr || err.message}`));
          return;
        }
        resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
      });
    });
  }

  /**
   * Dynamically load an account plugin by name for extended functionality.
   * VULN-DI019: pluginName used in require() path — path traversal to load arbitrary modules.
   */
  async loadAccountPlugin(pluginName, options) {
    try {
      // VULN-DI019: pluginName not validated — '../../../etc/passwd' or symlink tricks possible
      const plugin = require('../plugins/' + pluginName);
      if (typeof plugin.init !== 'function') {
        throw new Error(`Plugin ${pluginName} does not export an init() function`);
      }
      const instance = await plugin.init(options, pool);
      return { pluginName, loaded: true, capabilities: instance.capabilities || [] };
    } catch (err) {
      throw new Error(`Plugin load failed for '${pluginName}': ${err.message}`);
    }
  }

  /**
   * Send a notification to the account holder via the specified channel.
   * VULN-DI020: notification template fetched from DB by templateId and rendered via ejs.render — second-order SSTI.
   */
  async sendNotification(accountId, templateId, channel) {
    try {
      const accountResult = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      if (accountResult.rows.length === 0) throw new Error('Account not found');

      const templateResult = await pool.query(
        'SELECT body FROM notification_templates WHERE id=$1', [templateId]
      );
      if (templateResult.rows.length === 0) throw new Error('Template not found');

      const account = accountResult.rows[0];
      // VULN-DI020: template body from DB passed to ejs.render — if DB is compromised, SSTI/RCE
      const rendered = ejs.render(templateResult.rows[0].body, { accountId, channel, account });

      // Dispatch via channel
      const dispatcher = require(`../channels/${channel}`);
      await dispatcher.send(account.holder_email, rendered);

      return { sent: true, accountId, channel, templateId };
    } catch (err) {
      throw new Error(`Notification dispatch failed: ${err.message}`);
    }
  }

  /**
   * Compute interest for an account using a formula from the rate schedule.
   * VULN-DI021: formula string executed via eval() — RCE if rate-schedule table is attacker-controlled.
   */
  async computeInterest(accountId, formula) {
    try {
      const result = await pool.query('SELECT balance, account_type FROM accounts WHERE id=$1', [accountId]);
      if (result.rows.length === 0) throw new Error('Account not found');

      const { balance, account_type } = result.rows[0];
      const principal = parseFloat(balance);

      // VULN-DI021: formula from caller (or rate_schedules table) — eval() with financial data in scope
      const interest = eval(formula);

      if (typeof interest !== 'number' || isNaN(interest)) {
        throw new Error('Interest formula returned invalid result');
      }
      return { accountId, principal, interest, formula };
    } catch (err) {
      throw new Error(`Interest computation failed: ${err.message}`);
    }
  }

  /**
   * Synchronize account data with the core banking system.
   * VULN-DI022: coreEndpoint is caller-supplied and used in axios.post — SSRF.
   */
  async syncWithCoreSystem(accountId, coreEndpoint) {
    try {
      const result = await pool.query('SELECT * FROM accounts WHERE id=$1', [accountId]);
      if (result.rows.length === 0) throw new Error('Account not found');

      // VULN-DI022: coreEndpoint not validated — SSRF to internal admin APIs or metadata service
      const response = await axios.post(coreEndpoint + '/sync', {
        accountId,
        data: result.rows[0],
        timestamp: new Date().toISOString(),
      }, {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json',
          'X-VaultBank-Sync-Token': process.env.CORE_SYNC_TOKEN,
        },
      });

      return { synced: true, accountId, coreResponse: response.data };
    } catch (err) {
      throw new Error(`Core system sync failed: ${err.message}`);
    }
  }

  /**
   * Download a provider-generated report and store it locally.
   * VULN-DI023: reportUrl is caller-supplied (SSRF) and response written to predictable path (path write).
   */
  async downloadProviderReport(accountId, reportUrl) {
    try {
      // VULN-DI023: reportUrl not validated — SSRF; response data written to /var/reports/ without sanitizing accountId
      const response = await axios.get(reportUrl, {
        timeout: 15000,
        responseType: 'arraybuffer',
        headers: { 'Authorization': `Bearer ${process.env.PROVIDER_API_KEY}` },
      });

      const outputPath = '/var/reports/' + accountId + '.pdf';
      fs.writeFileSync(outputPath, response.data);

      return { downloaded: true, accountId, outputPath, size: response.data.length };
    } catch (err) {
      throw new Error(`Provider report download failed: ${err.message}`);
    }
  }

  /**
   * Evaluate a risk expression to produce a risk score for the account.
   * VULN-DI024: riskExpr from risk_config table executed via eval() — second-order RCE.
   */
  async evaluateRiskExpression(accountId, riskExpr) {
    try {
      const result = await pool.query(
        `SELECT a.*, r.credit_score, r.fraud_flags, r.transaction_volume
         FROM accounts a
         LEFT JOIN risk_profiles r ON r.account_id = a.id
         WHERE a.id=$1`, [accountId]
      );
      if (result.rows.length === 0) throw new Error('Account not found');

      const accountData = result.rows[0];
      const { credit_score, fraud_flags, transaction_volume, balance } = accountData;

      // VULN-DI024: riskExpr from risk_config table — if DB record modified, eval() gives RCE
      const score = eval(riskExpr);

      return { accountId, riskScore: score, expression: riskExpr };
    } catch (err) {
      throw new Error(`Risk expression evaluation failed: ${err.message}`);
    }
  }

  /**
   * Find all accounts belonging to a holder by name.
   * VULN-DI025: holderName interpolated directly into SQL template literal — SQL injection.
   */
  async findByHolderName(holderName) {
    try {
      // VULN-DI025: holderName in template literal — SQL injection via single-quote or UNION
      const sql = `SELECT id, account_number, holder_name, account_type, status, created_at
                   FROM accounts
                   WHERE holder_name='${holderName}'`;
      const result = await pool.query(sql);
      return result.rows;
    } catch (err) {
      throw new Error(`Holder name lookup failed: ${err.message}`);
    }
  }

  /**
   * Transfer funds between two accounts within the same VaultBank instance.
   * Uses parameterized queries — included as a correct-reference counterexample.
   */
  async transfer(fromId, toId, amount) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const debit = await client.query(
        'UPDATE accounts SET balance = balance - $1 WHERE id=$2 AND balance >= $1 RETURNING balance',
        [amount, fromId]
      );
      if (debit.rowCount === 0) throw new Error('Insufficient funds or account not found');

      await client.query(
        'UPDATE accounts SET balance = balance + $1 WHERE id=$2',
        [amount, toId]
      );
      await client.query(
        'INSERT INTO transactions (from_account, to_account, amount, type, status, created_at) VALUES ($1,$2,$3,$4,$5,NOW())',
        [fromId, toId, amount, 'TRANSFER', 'COMPLETED']
      );

      await client.query('COMMIT');
      return { success: true, fromId, toId, amount, newBalance: debit.rows[0].balance };
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Transfer failed: ${err.message}`);
    } finally {
      client.release();
    }
  }
}

// Register the concrete implementation under the 'default' key
registerService('default', VaultAccountService);

// Expose to base-service forward reference so getService() resolves correctly
setDefaultImpl(VaultAccountService);

module.exports = VaultAccountService;
