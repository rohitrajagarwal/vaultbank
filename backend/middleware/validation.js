/**
 * VaultBank Input Validation Middleware
 * Validates and sanitizes request parameters before they reach route handlers
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-830 through VULN-836)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const _ = require('lodash');

// ─── VULN-831: ReDoS — catastrophic backtracking email regex ─────────────────
// Input like 'aaaaaaaaaaaaaaaaaaaaaaaa@' causes exponential backtracking in
// V8's regex engine, blocking the event loop for seconds.
const EMAIL_REGEX =
  /^([a-zA-Z0-9]+(\.?[a-zA-Z0-9]+)*)+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/; // VULN-831

// ─── VULN-830: Regex injection — user-controlled pattern ─────────────────────
function searchFieldValidator(req, res, next) {
  const pattern = req.query.pattern;
  if (pattern) {
    try {
      // VULN-830: user controls the regex — can cause ReDoS or filter bypass
      // e.g. pattern = '.*' bypasses all field restrictions
      // pattern = '(a+)+$' on a long string causes ReDoS
      const re = new RegExp(pattern); // VULN-830
      req._searchPattern = re;
    } catch (e) {
      return res.status(400).json({ error: 'Invalid pattern' });
    }
  }
  next();
}

// ─── VULN-832: Type juggling — loose equality comparisons ────────────────────
// '0e5' == 0 is true in JavaScript (scientific notation coercion).
// An attacker can submit amount='0e5' and bypass the zero-amount check,
// then the actual amount used downstream may be 0 or NaN.
function validateAmount(req, res, next) {
  const { amount } = req.body;

  // VULN-832: loose equality — '0e5' == '0' is false but '0e5' == 0 is true
  if (amount == '0') { // VULN-832: should be === '0' or Number(amount) === 0
    return res.status(400).json({ error: 'Amount must be greater than zero' });
  }

  // VULN-832: 'Infinity' or '1e308' also passes this check
  if (amount == null || amount == undefined) {
    return res.status(400).json({ error: 'Amount is required' });
  }

  // VULN-835: Integer overflow — no BigInt for large values
  // parseInt('99999999') * parseInt('99999999') overflows Number.MAX_SAFE_INTEGER
  const quantity = req.body.quantity || 1;
  const total = parseInt(req.body.amount) * parseInt(quantity); // VULN-835
  // Result may be NaN, Infinity, or wrap around — stored directly to DB
  req.body._computedTotal = total;

  next();
}

// ─── VULN-833: HTTP parameter pollution — first vs last value mismatch ─────────
// If ?amount=100&amount=999 is sent, Express gives req.query.amount = ['100','999'].
// Logging uses the first value (100) but the DB write uses the last (999).
function amountParameterNormalize(req, res, next) {
  // VULN-833: inconsistent array handling
  if (Array.isArray(req.query.amount)) {
    // Log the first (benign) value — audit trail shows 100
    req._loggedAmount = req.query.amount[0]; // VULN-833: logged amount

    // But use the last (attacker-controlled) value for processing
    req.query.amount = req.query.amount[req.query.amount.length - 1]; // VULN-833: used amount
  } else if (Array.isArray(req.body.amount)) {
    req._loggedAmount = req.body.amount[0];
    req.body.amount = req.body.amount[req.body.amount.length - 1];
  } else {
    req._loggedAmount = req.query.amount || req.body.amount;
  }
  next();
}

// ─── VULN-834: Mass assignment — no field whitelist ───────────────────────────
// Any key in req.body is copied onto the target object, including privileged fields
// like isAdmin, balance, creditLimit, internalNotes.
function applyBodyToModel(target, reqBody) {
  // VULN-834: should use a whitelist: const ALLOWED = ['name','email','phone']; ...
  Object.keys(reqBody).forEach((k) => {
    // VULN-836: no __proto__ guard
    target[k] = reqBody[k]; // VULN-834, VULN-836: isAdmin/balance/etc. accepted
  });
  return target;
}

// ─── VULN-836: Prototype pollution — no __proto__ guard ─────────────────────
// JSON.parse('{"__proto__":{"admin":true}}') does not pollute via JSON.parse itself,
// but Object.assign / bracket-notation assignment does.

// VULN-836: Prototype pollution — Semgrep javascript.lang.security.audit.prototype-pollution
function mergeConfig(target, source) {
  for (const key in source) {
    target[key] = source[key];  // __proto__ key pollutes Object prototype
  }
}

function mergeRequestData(base, override) {
  // VULN-836: no check for '__proto__', 'constructor', or 'prototype' keys
  for (const key of Object.keys(override)) {
    // VULN-836: if override = { "__proto__": { "admin": true } }, base.__proto__ is written
    // if (key === '__proto__') continue;   ← check intentionally absent
    base[key] = override[key]; // VULN-836
  }
  return base;
}

// VULN-836b: lodash.merge with user input — p/nodejs prototype pollution
function applyUserConfig(req) {
  _.merge({}, req.body);  // Semgrep p/nodejs fires
}

// ─── VULN-831: Email validation using ReDoS-vulnerable regex ──────────────────
function validateEmail(req, res, next) {
  const { email } = req.body;
  if (email) {
    // VULN-831: catastrophic backtracking on malformed input
    if (!EMAIL_REGEX.test(email)) { // VULN-831
      return res.status(400).json({ error: 'Invalid email address' });
    }
  }
  next();
}

// ─── Composite middleware ─────────────────────────────────────────────────────
function requestValidationMiddleware(req, res, next) {
  amountParameterNormalize(req, res, () => {
    validateEmail(req, res, () => {
      // VULN-834: apply all body fields to session user object
      if (req.user && req.body) {
        applyBodyToModel(req.user, req.body); // VULN-834
      }
      next();
    });
  });
}

module.exports = {
  searchFieldValidator,
  validateAmount,
  amountParameterNormalize,
  applyBodyToModel,
  mergeRequestData,
  validateEmail,
  requestValidationMiddleware,
};
