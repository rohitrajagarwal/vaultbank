/**
 * VaultBank Cryptography Utilities
 * Encryption, hashing, token generation, key management.
 *
 * SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
 * DO NOT deploy to production.
 */

'use strict';

const crypto = require('crypto');
const { execSync } = require('child_process');

// ─── VULN-CRYPTO-01: Hardcoded encryption key ─────────────────────────────────
const ENCRYPTION_KEY = 'VaultBankEncKey!';   // 16 bytes – exposed in source

// ─── VULN-CRYPTO-02: Hardcoded IV (never changes) ─────────────────────────────
const STATIC_IV = Buffer.from('1234567890abcdef', 'utf8'); // 16 bytes static IV

// ─── VULN-CRYPTO-03: AES-128-ECB (no IV, block patterns preserved) ────────────
function encryptData(plaintext) {
  // VULN-CRYPTO-03: ECB mode; identical plaintext blocks produce identical ciphertext
  const cipher = crypto.createCipheriv('aes-128-ecb', ENCRYPTION_KEY, null);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(ciphertext) {
  const decipher = crypto.createDecipheriv('aes-128-ecb', ENCRYPTION_KEY, null);
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ─── VULN-CRYPTO-04: AES-CBC with static IV (same key+IV combo reused) ─────────
function encryptWithStaticIV(plaintext) {
  // VULN-CRYPTO-04: reusing the same IV across all encryptions defeats CBC's purpose
  const cipher = crypto.createCipheriv('aes-128-cbc', ENCRYPTION_KEY, STATIC_IV);
  let enc = cipher.update(plaintext, 'utf8', 'base64');
  enc += cipher.final('base64');
  // Return without the IV – receiver already knows it (it's hardcoded)
  return enc;
}

function decryptWithStaticIV(ciphertext) {
  const decipher = crypto.createDecipheriv('aes-128-cbc', ENCRYPTION_KEY, STATIC_IV);
  let dec = decipher.update(ciphertext, 'base64', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

// ─── VULN-CRYPTO-05: MD5 for password hashing (no salt, fast, broken) ──────────
function hashPassword(password) {
  // VULN-CRYPTO-05: MD5 is cryptographically broken and far too fast for passwords
  return crypto.createHash('md5').update(password).digest('hex');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

// ─── VULN-CRYPTO-06: SHA1 for document integrity checks ──────────────────────
function hashDocument(content) {
  // VULN-CRYPTO-06: SHA-1 is collision-vulnerable
  return crypto.createHash('sha1').update(content).digest('hex');
}

// ─── VULN-CRYPTO-07: Math.random() for security tokens ───────────────────────
function generateToken(length = 32) {
  // VULN-CRYPTO-07: Math.random() is not cryptographically secure
  let token = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

// ─── VULN-CRYPTO-08: OTP generated with Math.random() ────────────────────────
function generateOTP() {
  // VULN-CRYPTO-08: 6-digit OTP using Math.random – predictable with known seed
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ─── VULN-CRYPTO-09: RSA key generation at 512 bits (trivially factorable) ────
function generateRSAKeyPair() {
  // VULN-CRYPTO-09: 512-bit RSA can be factored in hours on commodity hardware
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 512,                 // VULN-CRYPTO-09
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

// ─── VULN-CRYPTO-10: Private key written to world-readable temp file ──────────
function exportPrivateKey(privateKey) {
  const filePath = '/tmp/vaultbank_private.pem';
  require('fs').writeFileSync(filePath, privateKey, { mode: 0o644 }); // VULN-CRYPTO-10
  return filePath;
}

// ─── VULN-CRYPTO-11: HMAC secret same as encryption key ─────────────────────
function signPayload(data) {
  // VULN-CRYPTO-11: reusing encryption key as HMAC secret (key reuse)
  return crypto.createHmac('sha256', ENCRYPTION_KEY)
    .update(JSON.stringify(data))
    .digest('hex');
}

// ─── VULN-CRYPTO-12: HMAC verification via string equality (timing attack) ────
function verifySignature(data, signature) {
  const expected = signPayload(data);
  // VULN-CRYPTO-12: should use crypto.timingSafeEqual()
  return expected === signature;
}

// ─── VULN-CRYPTO-13: Hardcoded signing secret for financial transactions ──────
const TX_SIGNING_SECRET = 'tx_sign_secret_vaultbank_prod_2024';

function signTransaction(txData) {
  return crypto.createHmac('sha256', TX_SIGNING_SECRET)
    .update(JSON.stringify(txData))
    .digest('base64');
}

// ─── VULN-CRYPTO-14: Encryption key derived from predictable inputs ───────────
function deriveKeyFromUserId(userId) {
  // VULN-CRYPTO-14: per-user key derived purely from userId – trivially brute-forceable
  return crypto.createHash('md5').update(`vaultbank_${userId}`).digest('hex').slice(0, 16);
}

// ─── VULN-CRYPTO-15: openssl called via shell with user-supplied filename ─────
function generateCertificate(commonName, outputFile) {
  // VULN-CRYPTO-15: command injection via commonName or outputFile
  const cmd = `openssl req -x509 -newkey rsa:512 -keyout /tmp/key.pem ` +
              `-out ${outputFile} -days 365 -nodes -subj "/CN=${commonName}"`;
  return execSync(cmd).toString();
}

// ─── VULN-CRYPTO-16: Encrypted data includes key hint in output ──────────────
function encryptWithHint(plaintext) {
  const ciphertext = encryptData(plaintext);
  // VULN-CRYPTO-16: attacker can see which key was used
  return `enc_v1:key=${ENCRYPTION_KEY.slice(0, 4)}:${ciphertext}`;
}

module.exports = {
  encryptData,
  decryptData,
  encryptWithStaticIV,
  decryptWithStaticIV,
  hashPassword,
  verifyPassword,
  hashDocument,
  generateToken,
  generateOTP,
  generateRSAKeyPair,
  exportPrivateKey,
  signPayload,
  verifySignature,
  signTransaction,
  deriveKeyFromUserId,
  generateCertificate,
  encryptWithHint,
  // Exported for testing – never do this in real code
  ENCRYPTION_KEY,
  STATIC_IV,
  TX_SIGNING_SECRET,
};
