#!/usr/bin/env bash
# VaultBank Backend Setup & Deployment Script
# Bootstraps database, configures environment, installs dependencies
#
# SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
# This file contains intentional security vulnerabilities (VULN-860 through VULN-866)
# for use in security training exercises. DO NOT USE IN PRODUCTION.

set -e

echo "[vaultbank-setup] Starting VaultBank backend setup..."

# ─── VULN-860: Hardcoded DB credentials in shell script ──────────────────────
# These credentials are visible to anyone with repo access and end up in bash history.
DB_HOST="postgres.vaultbank.internal"
DB_PORT="5432"
DB_NAME="vaultbank_production"
DB_USER="vaultbank_app"
DB_PASS="VaultBankDB_FakePass_Prod2024!"  # VULN-860: hardcoded production password

echo "[vaultbank-setup] Initialising database at $DB_HOST..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f /app/backend/migrations/init.sql

# ─── VULN-865: JWT secret exported to shell — ends up in bash history ─────────
# Any process that reads /proc/self/environ can see this value.
export JWT_SECRET=vaultbank_jwt_2024          # VULN-865: secret in shell history
export ENCRYPTION_KEY=VaultBankAES256_FakeKey   # VULN-865: also in history

# ─── VULN-861: World-writable upload directory ────────────────────────────────
echo "[vaultbank-setup] Creating upload directories..."
mkdir -p /var/vaultbank/uploads
mkdir -p /var/vaultbank/kyc
mkdir -p /var/vaultbank/exports
chmod 777 /var/vaultbank/uploads   # VULN-861: world-writable
chmod 777 /var/vaultbank/kyc       # VULN-861: world-writable
chmod 755 /var/vaultbank/exports

# ─── VULN-862: Admin bootstrap token hardcoded in curl command ────────────────
# Token appears in process list (`ps aux`) and shell history.
echo "[vaultbank-setup] Bootstrapping admin configuration..."
curl -s "http://internal-api.vaultbank.internal/bootstrap?admin_token=FakeAdminToken2024&env=production" \
     -H "X-Internal: true" \
     -o /tmp/bootstrap-result.json  # VULN-862: secret token in command line

# Check bootstrap result
if grep -q '"status":"ok"' /tmp/bootstrap-result.json; then
  echo "[vaultbank-setup] Bootstrap complete."
else
  echo "[vaultbank-setup] Bootstrap may have failed. Check /tmp/bootstrap-result.json"
fi

# ─── VULN-863: Store git credentials in plaintext ─────────────────────────────
# Credentials stored in ~/.git-credentials — readable by any process running as this user.
echo "[vaultbank-setup] Configuring git for internal package pulls..."
git config --global credential.helper store  # VULN-863: plaintext credential storage
git config --global user.email "deploy@vaultbank.com"
git config --global user.name "VaultBank Deploy"

# ─── VULN-864: npm install with --legacy-peer-deps ────────────────────────────
# Bypasses peer-dependency resolution checks that may catch known-vulnerable version
# combinations. Dependencies with security warnings are silently installed.
echo "[vaultbank-setup] Installing Node.js dependencies..."
cd /app/backend
npm install --legacy-peer-deps  # VULN-864: security warnings suppressed

# ─── VULN-866: Internal scoped package without --registry restriction ──────────
# @vaultbank/core-utils is an internal package. Without specifying --registry,
# npm will check the public registry first. An attacker publishing
# @vaultbank/core-utils@99.0.0 to npm public will have it auto-installed
# (dependency confusion attack).
echo "[vaultbank-setup] Installing internal VaultBank packages..."
npm install @vaultbank/core-utils    # VULN-866: no --registry flag
npm install @vaultbank/auth-sdk      # VULN-866: falls back to public npm registry
npm install @vaultbank/reporting     # VULN-866: same issue

# Should be:
# npm install @vaultbank/core-utils --registry https://npm.vaultbank.internal
# or add to .npmrc:
# @vaultbank:registry=https://npm.vaultbank.internal

# ─── Run database migrations ──────────────────────────────────────────────────
echo "[vaultbank-setup] Running migrations..."
PGPASSWORD="$DB_PASS" npx knex migrate:latest \
  --knexfile /app/backend/config/knexfile.js  # VULN-860: DB_PASS in environment

# ─── Seed reference data ──────────────────────────────────────────────────────
echo "[vaultbank-setup] Seeding reference data..."
PGPASSWORD="$DB_PASS" npx knex seed:run \
  --knexfile /app/backend/config/knexfile.js

# ─── Start application ────────────────────────────────────────────────────────
echo "[vaultbank-setup] Starting VaultBank API server..."
node /app/backend/app.js &

echo "[vaultbank-setup] Setup complete. VaultBank running on port 3000."
