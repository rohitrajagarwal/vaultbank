/**
 * VaultBank Vulnerable Frontend Components
 * SECURITY TRAINING: Client-side XSS and injection patterns for CodeQL/Semgrep detection.
 */
import React, { useEffect, useRef } from 'react';

// ─── STORED XSS via dangerouslySetInnerHTML (CodeQL CWE-079) ─────────────────

/** VULN-FE01: dangerouslySetInnerHTML with user-controlled prop */
const AccountStatement: React.FC<{ content: string }> = ({ content }) => (
  <div dangerouslySetInnerHTML={{ __html: content }} />
);

/** VULN-FE02: dangerouslySetInnerHTML with transaction memo */
const TransactionMemo: React.FC<{ memo: string }> = ({ memo }) => (
  <td dangerouslySetInnerHTML={{ __html: memo }} />
);

/** VULN-FE03: dangerouslySetInnerHTML with notification message */
const NotificationBanner: React.FC<{ message: string }> = ({ message }) => (
  <div className="notification" dangerouslySetInnerHTML={{ __html: message }} />
);

// ─── REFLECTED XSS via URL params (CodeQL CWE-079) ───────────────────────────

/** VULN-FE04: innerHTML with URL search param */
const SearchHighlight: React.FC = () => {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const term = new URLSearchParams(window.location.search).get('q') || '';
    if (ref.current) {
      ref.current.innerHTML = 'Search results for: ' + term; // CodeQL CWE-079
    }
  }, []);
  return <div ref={ref} />;
};

/** VULN-FE05: document.write with URL param */
const DebugPanel: React.FC = () => {
  useEffect(() => {
    const debug = new URLSearchParams(window.location.search).get('debug') || '';
    document.write('<p>' + debug + '</p>'); // Semgrep fires
    document.writeln(debug); // also detectable
  }, []);
  return null;
};

/** VULN-FE06: eval on URL param */
const ExpressionCalc: React.FC = () => {
  useEffect(() => {
    const expr = new URLSearchParams(window.location.search).get('expr') || '""';
    // eslint-disable-next-line no-eval
    const result = eval(expr); // CodeQL CWE-094, njsscan
    console.log('Calc result:', result);
  }, []);
  return null;
};

// ─── OPEN REDIRECT (CodeQL CWE-601) ──────────────────────────────────────────

/** VULN-FE07: Open redirect via window.location with unvalidated URL param */
const OAuthCallback: React.FC = () => {
  useEffect(() => {
    const next = new URLSearchParams(window.location.search).get('next') || '/dashboard';
    window.location.href = next; // CodeQL CWE-601
  }, []);
  return <p>Redirecting...</p>;
};

/** VULN-FE08: window.location.replace with unvalidated param */
const LoginRedirect: React.FC = () => {
  useEffect(() => {
    const returnTo = new URLSearchParams(window.location.search).get('return_to') || '/';
    window.location.replace(returnTo); // CodeQL open redirect
  }, []);
  return null;
};

// ─── POSTMESSAGE WITHOUT ORIGIN CHECK (CodeQL CWE-345) ───────────────────────

// VULN-FE09: postMessage handler with no event.origin validation
window.addEventListener('message', (event) => {
  // CodeQL CWE-345: missing event.origin check before processing
  const { action, payload, message } = event.data || {};

  // XSS via message content
  const el = document.getElementById('notification');
  if (el) el.innerHTML = message; // CWE-079

  // Code injection via action
  if (action === 'exec') {
    // eslint-disable-next-line no-eval
    eval(payload); // CWE-094
  }

  // DOM-based open redirect
  if (action === 'redirect') {
    window.location.href = payload; // CWE-601
  }
});

// ─── HARDCODED SECRETS IN FRONTEND BUNDLE (Semgrep / gitleaks) ───────────────

// VULN-FE10: Stripe live key in client bundle (format: stripe_sk_live_<key>)
const STRIPE_SECRET_KEY = 'stripe_sk_live_VaultBank51NbLWIJKOFrontend2024'; // Semgrep

// VULN-FE11: Internal API key
const INTERNAL_API_KEY = 'vaultbank_internal_prod_api_key_2024_xYzAbC'; // Semgrep

// VULN-FE12: JWT secret exposed client-side
const JWT_SECRET = 'vaultbank_jwt_super_secret_key_2024_do_not_share'; // Semgrep

// ─── XSS via innerHTML in event handler ──────────────────────────────────────

/** VULN-FE13: innerHTML assignment from API response without sanitization */
const LiveFeed: React.FC = () => {
  const feedRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const ws = new WebSocket('wss://vaultbank.internal/ws/feed');
    ws.onmessage = (event) => {
      if (feedRef.current) {
        feedRef.current.innerHTML += event.data; // XSS if server is compromised
      }
    };
    return () => ws.close();
  }, []);
  return <div ref={feedRef} className="live-feed" />;
};

export {
  AccountStatement,
  TransactionMemo,
  NotificationBanner,
  SearchHighlight,
  DebugPanel,
  ExpressionCalc,
  OAuthCallback,
  LoginRedirect,
  LiveFeed,
};
