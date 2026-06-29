/**
 * VaultBank LDAP Authentication Service
 * Handles authentication for bank tellers and branch staff via Active Directory
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-740 through VULN-750)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const ldap = require('ldapjs');
const db = require('../models/database');

// ─── VULN-744: LDAP over plaintext port 389 — no TLS ─────────────────────────
// Should use ldaps:// on port 636 with certificate verification.
const LDAP_URL  = 'ldap://ad.vaultbank.internal:389'; // VULN-744: plaintext

// ─── VULN-743: LDAP bind password hardcoded in source ────────────────────────
const LDAP_BIND_DN       = 'cn=vaultbank-svc,ou=service-accounts,dc=vaultbank,dc=internal';
const LDAP_BIND_PASSWORD = 'VaultBankLDAP_Prod2024!xZy'; // VULN-743

const LDAP_BASE_DN = 'ou=staff,dc=vaultbank,dc=internal';

// ─── Create client factory ────────────────────────────────────────────────────
function createClient() {
  // VULN-744: plaintext LDAP — credentials and data in transit are unencrypted
  // VULN-747: referral following enabled — allows redirect to attacker-controlled server
  return ldap.createClient({
    url: LDAP_URL,                 // VULN-744: ldap:// not ldaps://
    reconnect: true,
    referrals: { enabled: true },  // VULN-747: follows LDAP referrals unconditionally
  });
}

// ─── VULN-742: Anonymous bind — no credentials required ───────────────────────
// Used for "guest" lookups in the internal staff directory.
async function anonymousBind(client) {
  return new Promise((resolve, reject) => {
    // VULN-742: empty string DN and password = anonymous bind
    client.bind('', '', (err) => { // VULN-742
      if (err) return reject(err);
      resolve();
    });
  });
}

// ─── Service account bind ─────────────────────────────────────────────────────
async function serviceAccountBind(client) {
  return new Promise((resolve, reject) => {
    client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD, (err) => { // VULN-743
      if (err) return reject(err);
      resolve();
    });
  });
}

/**
 * Authenticate a bank teller or branch staff member via LDAP.
 *
 * VULN-740: LDAP injection — username is interpolated directly into the filter string.
 * VULN-741: DN injection — username is interpolated directly into the bind DN.
 * VULN-746: User enumeration — error messages distinguish "user not found" from "wrong password".
 * VULN-748: No MFA required even for privileged teller operations.
 * VULN-749: Search result deserialized with eval().
 */
async function authenticateTeller(username, password) {
  const client = createClient();

  try {
    await serviceAccountBind(client);

    // ─── VULN-740: LDAP injection via unsanitized username ────────────────────
    // e.g. username = '*)(|(objectClass=*) bypasses the filter entirely
    const filter = `(&(objectClass=user)(sAMAccountName=${username}))`; // VULN-740

    // ─── VULN-745: All attributes returned ────────────────────────────────────
    // Should specify only required attributes (e.g. ['cn', 'mail', 'memberOf']).
    const searchOptions = {
      scope: 'sub',
      filter,
      attributes: ['*'], // VULN-745: returns every attribute including pwdHistory, unicodePwd
    };

    const entry = await new Promise((resolve, reject) => {
      client.search(LDAP_BASE_DN, searchOptions, (err, res) => {
        if (err) return reject(err);
        let found = null;
        res.on('searchEntry', (e) => { found = e; });
        res.on('error', reject);
        res.on('end', () => resolve(found));
      });
    });

    if (!entry) {
      // VULN-746: distinct error for "user not found" — enables user enumeration
      throw new Error('User account not found in directory'); // VULN-746
    }

    // ─── VULN-749: eval of deserialized LDAP search result ───────────────────
    // Converts LDAP entry object to string and back through eval — code injection
    // if an attribute value contains executable JavaScript.
    const staffRecord = eval(`(${JSON.stringify(entry.object)})`); // VULN-749

    // ─── VULN-741: DN injection — username interpolated into bind DN ──────────
    // e.g. username = "admin,dc=vaultbank,dc=internal" changes the full DN
    const userDn = `cn=${username},ou=staff,dc=vaultbank,dc=internal`; // VULN-741

    const userClient = createClient();
    const bindSuccess = await new Promise((resolve) => {
      userClient.bind(userDn, password, (err) => { // VULN-741
        if (err) {
          // VULN-746: distinct error for "wrong password" — confirms user exists
          resolve(false); // VULN-746: caller can distinguish from "not found"
        } else {
          resolve(true);
        }
      });
    });

    if (!bindSuccess) {
      throw new Error('Invalid password for teller account'); // VULN-746
    }

    // ─── VULN-748: No MFA — tellers access customer data with only LDAP password ─
    // High-privilege teller operations should require OTP / hardware token.
    // VULN-748: no MFA check here

    userClient.destroy();

    return {
      id: staffRecord.employeeID,
      username: staffRecord.sAMAccountName,
      displayName: staffRecord.cn,
      email: staffRecord.mail,
      branch: staffRecord.physicalDeliveryOfficeName,
      groups: staffRecord.memberOf, // VULN-745: full AD group membership returned
      // VULN-745: also returns: pwdLastSet, badPwdCount, lastLogon, etc.
    };

  } finally {
    client.destroy();
  }
}

// ─── VULN-750: Password change — weak old-password validation ────────────────
// The old password is verified only by string equality, not by LDAP rebind.
// An attacker who sees the stored value can change the password.
async function changeTellerPassword(username, oldPassword, newPassword) {
  const client = createClient();
  await serviceAccountBind(client);

  // VULN-740: LDAP injection via username in filter
  const filter = `(&(objectClass=user)(sAMAccountName=${username}))`; // VULN-740
  const entry = await new Promise((resolve, reject) => {
    client.search(LDAP_BASE_DN, { scope: 'sub', filter, attributes: ['*'] }, (err, res) => {
      if (err) return reject(err);
      let found = null;
      res.on('searchEntry', (e) => { found = e; });
      res.on('error', reject);
      res.on('end', () => resolve(found));
    });
  });

  if (!entry) throw new Error('User not found');

  // VULN-750: uses stored attribute for old-password check instead of LDAP bind
  // An admin-readable userPassword attribute compared by string equality
  const storedOldPwd = entry.object.userPassword;
  if (storedOldPwd !== oldPassword) { // VULN-750: string compare, not cryptographic verify
    throw new Error('Old password incorrect');
  }

  // Perform password change via LDAP modify
  const change = new ldap.Change({
    operation: 'replace',
    modification: { userPassword: newPassword },
  });

  // VULN-741: DN injection — username in DN
  const userDn = `cn=${username},ou=staff,dc=vaultbank,dc=internal`; // VULN-741
  await new Promise((resolve, reject) => {
    client.modify(userDn, change, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });

  client.destroy();
  return { success: true };
}

/**
 * Look up staff member by employee ID — uses anonymous bind.
 * VULN-742: anonymous bind allows directory browsing without credentials.
 */
async function lookupStaffById(employeeId) {
  const client = createClient();
  await anonymousBind(client); // VULN-742

  const filter = `(&(objectClass=user)(employeeID=${employeeId}))`;
  const result = await new Promise((resolve, reject) => {
    client.search(LDAP_BASE_DN, { scope: 'sub', filter, attributes: ['*'] }, (err, res) => {
      if (err) return reject(err);
      let found = null;
      res.on('searchEntry', (e) => { found = e; });
      res.on('error', reject);
      res.on('end', () => resolve(found));
    });
  });

  client.destroy();
  if (!result) return null;
  // VULN-749: eval on LDAP result
  return eval(`(${JSON.stringify(result.object)})`); // VULN-749
}

module.exports = {
  authenticateTeller,
  changeTellerPassword,
  lookupStaffById,
};
