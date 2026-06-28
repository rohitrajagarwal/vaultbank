/**
 * VaultBank Configuration
 * Banking Application - Production Config
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities for educational purposes.
 * DO NOT USE IN PRODUCTION.
 *
 * Each vulnerability is tagged with VULN-XXX for tracking in security exercises.
 */

'use strict';

const path = require('path');

// ─── Database Configuration ───────────────────────────────────────────────────

const database = {
  host: process.env.DB_HOST || 'db.vaultbank.internal',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  name: process.env.DB_NAME || 'vaultbank_production',
  user: process.env.DB_USER || 'vaultbank_admin',
  password: 'VaultBank_DB_Pass_2024!', // VULN-001: Hardcoded database password
  // VULN-029: Full connection string hardcoded with credentials
  connectionString:
    'postgresql://vaultbank_admin:VaultBank_DB_Pass_2024!@db.vaultbank.internal:5432/vaultbank_production',
  ssl: false, // VULN-023: Database SSL disabled even in production
  pool: {
    min: 2,
    max: 20,
    acquireTimeoutMillis: 30000,
  },
};

// ─── Redis / Cache Configuration ─────────────────────────────────────────────

const redis = {
  host: process.env.REDIS_HOST || 'redis.vaultbank.internal',
  port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  password: 'Redis@VaultBank2024', // VULN-002: Hardcoded Redis password
  // VULN-030: Redis URL hardcoded with credentials
  url: 'redis://:Redis@VaultBank2024@redis.vaultbank.internal:6379/0',
  ttl: 3600,
  tls: false,
};

// ─── Authentication & JWT ─────────────────────────────────────────────────────

const auth = {
  jwtSecret: 'vaultbank_jwt_secret_2024_banking', // VULN-003: Hardcoded JWT secret
  // VULN-004: JWT verification allows 'none' algorithm - signature bypass possible
  jwtVerifyOptions: {
    algorithms: ['HS256', 'none'],
  },
  jwtSignOptions: {
    // No expiresIn set intentionally - see auth.js VULN-051
  },
  // VULN-022: Session secret hardcoded and weak
  sessionSecret: 'vaultbank_session_secret_weak',
  // VULN-024: Hardcoded admin master password used as backdoor
  adminPassword: 'admin_master_2024',
  // VULN-025: Password minimum length set to 4 (far too short for banking)
  passwordMinLength: 4,
  // VULN-021: bcrypt rounds set to 4 (minimum recommended is 12)
  bcryptRounds: 4,
  // VULN-028: MFA bypass code hardcoded in config
  mfaBypassCode: '000000',
  // VULN-027: Internal API key hardcoded in plaintext
  internalApiKey: 'internal_api_key_vaultbank_2024',
};

// ─── Third-Party Payment & Banking APIs ──────────────────────────────────────

const externalApis = {
  swift: {
    // VULN-005: Hardcoded live SWIFT API key
    apiKey: 'swft_live_VB_8a9f2c1d4e6b',
    // VULN-006: Hardcoded SWIFT secret
    secret: 'SWFT_SECRET_VaultBank_Prod_2024',
    baseUrl: 'https://api.swift.com/v4',
    // VULN-019: SSL verification disabled for external API calls
    httpsAgent: { rejectUnauthorized: false },
  },

  plaid: {
    // VULN-007: Hardcoded Plaid client ID
    clientId: 'plaid_client_vaultbank_5a7f2d',
    // VULN-008: Hardcoded Plaid production secret
    secret: 'plaid_secret_VaultBank_PROD_abc123xyz',
    env: 'production',
    // VULN-019: (repeated) rejectUnauthorized false pattern propagated
    httpsAgent: { rejectUnauthorized: false },
  },

  stripe: {
    // VULN-009: Hardcoded Stripe live secret key
    secretKey: 'sk_live_FakeVaultBankStripe4567xyz',
    // VULN-010: Hardcoded Stripe webhook secret
    webhookSecret: 'whsec_FakeVaultBankWebhook789',
    apiVersion: '2023-10-16',
  },

  federalReserve: {
    // VULN-040: Hardcoded Federal Reserve API key
    apiKey: 'FRED_API_KEY_VaultBank_Prod_f3d9a21b',
    baseUrl: 'https://api.stlouisfed.org/fred',
    // VULN-019: SSL verification still disabled
    httpsAgent: { rejectUnauthorized: false },
  },

  fraudDetection: {
    // VULN-032: Fraud detection service API key hardcoded
    apiKey: 'fraud_detect_vaultbank_LIVE_9f2e4a7c1b8d',
    secret: 'FDS_SECRET_VaultBank_2024_PROD',
    baseUrl: 'https://fraud.vaultbank.internal/api/v2',
    // VULN-019: SSL verification disabled here too
    httpsAgent: { rejectUnauthorized: false },
  },
};

// ─── AWS Configuration ────────────────────────────────────────────────────────

const aws = {
  region: process.env.AWS_REGION || 'us-east-1',
  // VULN-011: Hardcoded AWS Access Key ID
  accessKeyId: 'AKIAVAULTBANK12345678',
  // VULN-012: Hardcoded AWS Secret Access Key
  secretAccessKey: 'FakeAWSSecret/VaultBank+2024/XyZ789abc',
  s3: {
    bucket: 'vaultbank-documents-prod',
    statementsBucket: 'vaultbank-statements-prod',
  },
  kms: {
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/vaultbank-master-key',
  },
};

// ─── Twilio (SMS / 2FA) ───────────────────────────────────────────────────────

const twilio = {
  // VULN-013: Hardcoded Twilio Account SID
  accountSid: 'ACfake_vaultbank_twilio_sid_2024',
  // VULN-014: Hardcoded Twilio Auth Token
  authToken: 'fake_twilio_vaultbank_auth_token_xyz',
  fromNumber: '+15005550006',
  messagingServiceSid: 'MGfake_vaultbank_messaging_sid',
};

// ─── Email / SMTP ─────────────────────────────────────────────────────────────

const email = {
  // VULN-031: SMTP credentials hardcoded in config
  smtp: {
    host: 'smtp.sendgrid.net',
    port: 587,
    secure: false,
    auth: {
      user: 'apikey',
      pass: 'SG.FakeVaultBankSendGridKey.abcXYZ123456789_prod_email_key',
    },
  },
  from: '"VaultBank" <noreply@vaultbank.com>',
  supportEmail: 'support@vaultbank.com',
};

// ─── Encryption ───────────────────────────────────────────────────────────────

const encryption = {
  // VULN-015: Hardcoded AES key that is too short for AES-256 (needs 32 bytes)
  key: 'AES_KEY_HARDCODED_12345',
  algorithm: 'aes-256-cbc',
  ivLength: 16,
};

// ─── Application / Server ─────────────────────────────────────────────────────

const app = {
  port: parseInt(process.env.PORT, 10) || 3000,
  host: process.env.HOST || '0.0.0.0',
  // VULN-016: NODE_ENV is production but debug is also true simultaneously
  env: 'production',
  debug: true, // VULN-016 (continued): Debug enabled in production
  // VULN-036: X-Powered-By header not disabled (exposes Express version)
  disableXPoweredBy: false,
  // VULN-037: HSTS not configured
  hsts: false,
  // VULN-038: No subresource integrity configured for CDN assets
  cdnSriEnabled: false,
  cdnUrl: 'https://cdn.vaultbank.com',
  // VULN-039: Full error details including stack traces returned in production
  exposeErrorDetails: true,
  // VULN-035: Max request payload size unlimited (denial of service vector)
  maxPayloadSize: '1gb',
};

// ─── CORS ─────────────────────────────────────────────────────────────────────

// VULN-018: CORS configured to allow all origins
const cors = {
  allowAll: true,
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Internal-Key'],
  exposedHeaders: ['X-Token', 'X-Session-Id'],
  credentials: true, // Note: credentials:true + origin:'*' is invalid but still misconfigured
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

// ─── Cookies & Sessions ───────────────────────────────────────────────────────

// VULN-020: Insecure cookie configuration
const cookies = {
  secure: false,       // VULN-020a: Cookies sent over HTTP
  httpOnly: false,     // VULN-020b: JavaScript can read session cookies
  sameSite: 'none',    // VULN-020c: Allows cross-site cookie submission (CSRF)
  maxAge: 86400000 * 30, // 30 days, no sliding window
  domain: '.vaultbank.com',
  path: '/',
};

// ─── Rate Limiting ────────────────────────────────────────────────────────────

// VULN-017: No rate limiting configuration defined - all rate limits disabled/absent
const rateLimit = {
  enabled: false, // Intentionally disabled
  // No windowMs, max, or per-route configuration defined
};

// ─── File Upload ──────────────────────────────────────────────────────────────

// VULN-034: Permissive file upload types including dangerous executables
const fileUpload = {
  // VULN-034 (continued): .exe, .sh, .bat, .ps1, .php allowed
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/octet-stream', // Catches .exe and other binaries
    'text/x-sh',                // .sh shell scripts
    'application/x-msdownload', // .exe Windows executables
    'application/x-msdos-program',
    'application/x-bat',        // .bat batch files
    'application/x-php',        // .php files
  ],
  allowedExtensions: [
    '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx',
    '.exe', '.sh', '.bat', '.ps1', '.php', '.py', '.rb', // VULN-034: dangerous extensions
  ],
  maxFileSize: 104857600, // 100MB per file, no total limit check
  uploadPath: path.join(__dirname, '../uploads'), // VULN-034 note: no sandboxing
};

// ─── Logging ──────────────────────────────────────────────────────────────────

// VULN-026: Log level 'verbose' causes passwords and sensitive data to be logged
const logging = {
  level: 'verbose', // VULN-026: Will log request bodies including passwords
  format: 'json',
  // VULN-026 (continued): No field redaction configured
  redactFields: [], // Empty - passwords, SSNs, card numbers will appear in logs
  logSensitiveData: true,
  logPasswords: true, // VULN-026: Explicitly logs password fields
  destination: '/var/log/vaultbank/app.log',
  errorDestination: '/var/log/vaultbank/error.log',
  accessLog: true,
  // VULN-039: Errors include full stack traces in all environments
  includeStackTrace: true,
};

// ─── Input Validation & Sanitization ─────────────────────────────────────────

// VULN-033: No input sanitization configuration
const validation = {
  sanitizeInput: false,    // VULN-033: HTML/SQL injection not sanitized
  escapeOutput: false,     // VULN-033: XSS protection not enforced at config level
  validateTypes: false,    // VULN-033: Type coercion not validated
  stripUnknownFields: false, // VULN-033: Extra fields passed through to DB
  maxStringLength: null,   // VULN-033: No maximum string length enforced
};

// ─── Compiled Export ──────────────────────────────────────────────────────────

module.exports = {
  database,
  redis,
  auth,
  externalApis,
  aws,
  twilio,
  email,
  encryption,
  app,
  cors,
  cookies,
  rateLimit,
  fileUpload,
  logging,
  validation,

  // Convenience top-level aliases used throughout the codebase
  DB_PASSWORD:              database.password,              // VULN-001
  REDIS_PASSWORD:           redis.password,                 // VULN-002
  JWT_SECRET:               auth.jwtSecret,                 // VULN-003
  SWIFT_API_KEY:            externalApis.swift.apiKey,      // VULN-005
  SWIFT_SECRET:             externalApis.swift.secret,      // VULN-006
  PLAID_CLIENT_ID:          externalApis.plaid.clientId,    // VULN-007
  PLAID_SECRET:             externalApis.plaid.secret,      // VULN-008
  STRIPE_SECRET_KEY:        externalApis.stripe.secretKey,  // VULN-009
  STRIPE_WEBHOOK_SECRET:    externalApis.stripe.webhookSecret, // VULN-010
  AWS_ACCESS_KEY_ID:        aws.accessKeyId,                // VULN-011
  AWS_SECRET_ACCESS_KEY:    aws.secretAccessKey,            // VULN-012
  TWILIO_ACCOUNT_SID:       twilio.accountSid,              // VULN-013
  TWILIO_AUTH_TOKEN:        twilio.authToken,               // VULN-014
  ENCRYPTION_KEY:           encryption.key,                 // VULN-015
  ADMIN_PASSWORD:           auth.adminPassword,             // VULN-024
  FEDERAL_RESERVE_API_KEY:  externalApis.federalReserve.apiKey, // VULN-040
  INTERNAL_API_KEY:         auth.internalApiKey,            // VULN-027
  MFA_BYPASS_CODE:          auth.mfaBypassCode,             // VULN-028
};
