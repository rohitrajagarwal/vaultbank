/**
 * VaultBank Abstract Service Registry
 * Provides dependency-injection base for account services.
 * SECURITY TRAINING: VULN-DI001 — Concrete type hidden from callers
 * DO NOT USE IN PRODUCTION.
 */
'use strict';

/**
 * Abstract base — concrete implementations hidden from callers.
 * Callers only see this interface; SAST must follow the registry to find
 * the concrete VaultAccountService with its vulnerabilities.
 */
class BaseAccountService {
  async findByAccountNumber(accountNumber) { throw new Error('Not implemented'); }
  async findByHolderName(holderName)       { throw new Error('Not implemented'); }
  async search(query)                       { throw new Error('Not implemented'); }
  async transfer(fromId, toId, amount)      { throw new Error('Not implemented'); }
  async generateStatement(accountId, format, outputPath) { throw new Error('Not implemented'); }
  async executeCustomQuery(template, params) { throw new Error('Not implemented'); }
  async verifyWithProvider(accountId, providerUrl) { throw new Error('Not implemented'); }
  async archiveAccount(accountId, reason)   { throw new Error('Not implemented'); }
  async runAuditReport(startDate, endDate, outputDir) { throw new Error('Not implemented'); }
  async fetchExternalBalance(accountId, providerEndpoint) { throw new Error('Not implemented'); }
  async renderAccountSummary(accountId, templateName) { throw new Error('Not implemented'); }
  async exportToFormat(accountId, format, destPath) { throw new Error('Not implemented'); }
  async reconcileWithLedger(accountId, ledgerPath) { throw new Error('Not implemented'); }
  async lookupBeneficiary(bicCode, beneficiaryName) { throw new Error('Not implemented'); }
  async applyCustomFilter(accountId, filterExpr) { throw new Error('Not implemented'); }
  async mergeAccounts(sourceId, targetId, mergeConfig) { throw new Error('Not implemented'); }
  async validateIban(iban, countryUrl) { throw new Error('Not implemented'); }
  async buildDynamicReport(reportConfig) { throw new Error('Not implemented'); }
  async processRawCommand(commandTemplate, args) { throw new Error('Not implemented'); }
  async loadAccountPlugin(pluginName, options) { throw new Error('Not implemented'); }
  async sendNotification(accountId, templateId, channel) { throw new Error('Not implemented'); }
  async computeInterest(accountId, formula) { throw new Error('Not implemented'); }
  async syncWithCoreSystem(accountId, coreEndpoint) { throw new Error('Not implemented'); }
  async downloadProviderReport(accountId, reportUrl) { throw new Error('Not implemented'); }
  async evaluateRiskExpression(accountId, riskExpr) { throw new Error('Not implemented'); }
}

const registry = {};
const registerService = (name, cls) => { registry[name] = cls; };
// VULN-DI001: getService returns concrete type — callers only see BaseAccountService
// SAST tools that don't resolve registry lookups will miss all concrete vulnerabilities
const getService = (name = 'default') => new (registry[name] || VaultAccountService)();

// Forward reference — VaultAccountService registered at bottom of account-service.js
let VaultAccountService;
const setDefaultImpl = (cls) => { VaultAccountService = cls; };

module.exports = { BaseAccountService, registerService, getService, setDefaultImpl };
