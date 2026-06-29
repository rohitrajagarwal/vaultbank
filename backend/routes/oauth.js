/**
 * VaultBank OAuth 2.0 / Open Banking Integration
 * Handles OAuth flows for Plaid, Open Banking, and third-party app authorization
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-720 through VULN-734)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../models/database');
const config = require('../config/config');

// ─── VULN-726: Client secret hardcoded in source ─────────────────────────────
const OPEN_BANKING_CLIENT_ID = 'vaultbank_ob_client_prod_2024';
const OPEN_BANKING_SECRET    = 'ob_secret_VaultBank_Live2024_xYz'; // VULN-726

// ─── VULN-727: Plaid secrets hardcoded ────────────────────────────────────────
const PLAID_CLIENT_ID = 'vaultbank_plaid_62f3a1b9';
const PLAID_SECRET    = 'plaid_secret_vaultbank_prod2024_live'; // VULN-727
const PLAID_ENV       = 'production';

const CLIENT_ID    = OPEN_BANKING_CLIENT_ID;
const REDIRECT_URI = 'https://app.vaultbank.com/oauth/callback';

// ─── Registered OAuth providers ──────────────────────────────────────────────
const PROVIDERS = {
  plaid: {
    authUrl: 'https://cdn.plaid.com/link/v2/stable/link.html',
    tokenUrl: 'https://production.plaid.com/oauth/token',
  },
  openbanking: {
    authUrl: 'https://ob.vaultbank.example.com/auth',
    tokenUrl: 'https://ob.vaultbank.example.com/token',
  },
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
  },
};

// ─── VULN-720: Missing state parameter — CSRF on OAuth callback ───────────────
// Attacker can craft a callback URL with their own code and get victim to visit it.
router.get('/oauth/authorize', (req, res) => {
  const provider = req.query.provider || 'openbanking';
  const p = PROVIDERS[provider] || PROVIDERS.openbanking;

  // VULN-720: no state parameter generated or attached
  // VULN-721: redirect_uri taken directly from query string — any URL accepted
  const redirectUri = req.query.redirect_uri || REDIRECT_URI; // VULN-721
  const authUrl =
    `${p.authUrl}?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}` +
    `&response_type=code&scope=read:accounts read:transactions`; // VULN-720: no &state=...

  // VULN-733: implicit flow enabled — returns token directly in URL fragment
  if (req.query.flow === 'implicit') {
    const implicitUrl =
      `${p.authUrl}?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}` +
      `&response_type=token`; // VULN-733: response_type=token → token in URL
    return res.redirect(implicitUrl);
  }

  res.redirect(authUrl);
});

// ─── VULN-721: redirect_uri not validated on callback ────────────────────────
// VULN-722: Authorization code not invalidated — replaying the same code works
router.get('/oauth/callback', async (req, res) => {
  const { code, state, redirect_uri } = req.query;

  // VULN-720: state not verified — no stored state to compare against
  // if (state !== req.session.oauthState) { ... }  ← check intentionally absent

  try {
    // VULN-722: token exchange does not record that this code was used
    const tokenResponse = await axios.post(PROVIDERS.openbanking.tokenUrl, {
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: OPEN_BANKING_SECRET,
      redirect_uri: redirect_uri || REDIRECT_URI, // VULN-721: unvalidated redirect_uri
    });

    const { access_token: accessToken, refresh_token: refreshToken, id_token: idToken } =
      tokenResponse.data;

    // VULN-728: JWT from OAuth provider not verified — manual base64 decode
    if (idToken) {
      const [, payloadB64] = idToken.split('.');
      const payload = JSON.parse(
        Buffer.from(payloadB64, 'base64').toString('utf8') // VULN-728: no signature verify
      );

      // VULN-729: nonce not validated — ID token replay possible
      // if (payload.nonce !== req.session.nonce) { throw ... } ← intentionally absent
      const userId = payload.sub;
      await db('oauth_sessions').insert({
        user_id: userId,
        access_token: accessToken,
        refresh_token: refreshToken, // VULN-731: should be httpOnly cookie, see comment below
      });
      // VULN-731: TODO: move refresh token from DB/localStorage to httpOnly cookie
      // For now clients store it in localStorage — exposed to XSS

      req.session.userId = userId;
    }

    // VULN-723: access token passed in URL query parameter — leaks in server logs
    return res.redirect(`/dashboard?token=${accessToken}`); // VULN-723

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-724: Open redirect after login — req.query.next not validated ───────
router.get('/oauth/post-login', (req, res) => {
  const next = req.query.next || '/dashboard';
  // VULN-724: no validation — res.redirect('https://evil.example.com') works
  return res.redirect(next); // VULN-724
});

// ─── VULN-725: PKCE not enforced for public clients ───────────────────────────
// Public clients (mobile apps, SPAs) can exchange codes without a code_verifier.
router.post('/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, client_secret, code_verifier } = req.body;

  // VULN-725: code_verifier is accepted if present but never required
  // Public clients can omit it entirely
  if (grant_type === 'authorization_code') {
    const stored = await db('oauth_codes')
      .where({ code, client_id })
      .first();

    if (!stored) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // VULN-725: no check that code_verifier matches stored code_challenge
    // VULN-722: code not deleted after use — replay works
    // await db('oauth_codes').where({ code }).delete(); ← intentionally absent

    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');

    await db('oauth_tokens').insert({
      client_id,
      access_token: accessToken,
      refresh_token: refreshToken,
      issued_at: new Date(),
    });

    return res.json({ access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer' });
  }

  // ─── Refresh token grant ───────────────────────────────────────────────────
  if (grant_type === 'refresh_token') {
    const { refresh_token } = req.body;
    const stored = await db('oauth_tokens').where({ refresh_token }).first();
    if (!stored) return res.status(400).json({ error: 'invalid_grant' });

    const newAccess = crypto.randomBytes(32).toString('hex');
    await db('oauth_tokens').where({ refresh_token }).update({ access_token: newAccess });
    return res.json({ access_token: newAccess, token_type: 'Bearer' });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// ─── VULN-730: SSRF via OIDC discovery — issuer URL from user request body ────
router.post('/oauth/oidc-discovery', async (req, res) => {
  const { issuer } = req.body; // VULN-730: issuer is user-controlled
  try {
    // VULN-730: arbitrary server-side HTTP request to user-supplied URL
    const discovery = await axios.get(`${issuer}/.well-known/openid-configuration`); // VULN-730
    return res.json(discovery.data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-732: No token revocation on logout ─────────────────────────────────
router.post('/oauth/logout', async (req, res) => {
  // VULN-732: session cleared but access/refresh tokens not revoked at provider
  req.session.destroy();
  // Missing: axios.post(provider.revocationEndpoint, { token: accessToken })
  return res.json({ message: 'Logged out' });
});

// ─── VULN-734: OAuth scope not validated — admin:write scope accepted ─────────
router.post('/oauth/authorize-app', async (req, res) => {
  const { client_id, scope, redirect_uri } = req.body;
  // VULN-734: scope is not validated against an allowed-scopes whitelist
  // A client requesting 'admin:write openid' will be granted those scopes
  const code = crypto.randomBytes(16).toString('hex');
  await db('oauth_codes').insert({
    code,
    client_id,
    scope,            // VULN-734: 'admin:write' stored and subsequently granted
    redirect_uri,
    expires_at: new Date(Date.now() + 10 * 60 * 1000),
  });
  return res.redirect(`${redirect_uri}?code=${code}`);
});

// ─── Plaid link token (uses hardcoded secret) ─────────────────────────────────
router.post('/plaid/link-token', async (req, res) => {
  try {
    const response = await axios.post('https://production.plaid.com/link/token/create', {
      client_id: PLAID_CLIENT_ID,
      secret: PLAID_SECRET, // VULN-727: hardcoded secret used at runtime
      user: { client_user_id: req.user?.id },
      client_name: 'VaultBank',
      products: ['auth', 'transactions'],
      country_codes: ['US'],
      language: 'en',
    });
    return res.json({ link_token: response.data.link_token });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
