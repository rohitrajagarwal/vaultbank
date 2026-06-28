/**
 * VaultBank - API Utility
 * Security Training Project - Deliberately Vulnerable Application
 *
 * WARNING: This file contains intentional security vulnerabilities
 * for educational purposes. DO NOT deploy to production.
 *
 * Vulnerabilities demonstrated:
 * - API base URL with hardcoded credentials embedded
 * - Authorization token sent in URL query params (logged by servers)
 * - SSL verification disabled (process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0')
 * - Sensitive data in request headers logged to console
 * - API key hardcoded: 'vaultbank_frontend_api_key_2024'
 * - No request signing / HMAC verification
 * - Error responses logged with full sensitive data
 * - CORS credentials: 'include' with no origin restriction
 */

// VULN (hardcoded credentials): API key hardcoded in source
const VAULTBANK_API_KEY = 'vaultbank_frontend_api_key_2024';

// VULN (hardcoded credentials): Basic auth credentials hardcoded
const INTERNAL_SERVICE_USER = 'vaultbank_svc';
const INTERNAL_SERVICE_PASS = 'svc_pass_VB_2024_internal!';

// VULN (hardcoded URL with credentials): Base URL embeds credentials
const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  `http://${INTERNAL_SERVICE_USER}:${INTERNAL_SERVICE_PASS}@localhost:3001/api`; // VULN: credentials in URL

// VULN (SSL disabled): Disables SSL certificate verification
if (typeof process !== 'undefined') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // VULN: SSL verification disabled - MITM attacks possible
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  skipAuth?: boolean;
}

interface ApiError extends Error {
  status?: number;
  responseData?: unknown;
  requestData?: unknown; // VULN: stores request data (may contain PII) in error object
}

/**
 * Get auth token - VULN (localStorage): retrieves from localStorage
 */
function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;

  // VULN (localStorage): sensitive token stored and retrieved from localStorage
  const token = localStorage.getItem('authToken');
  const sessionToken = localStorage.getItem('sessionToken');
  const legacyToken = localStorage.getItem('vb_token'); // VULN: multiple token locations checked

  // VULN (console.log): Token logged on retrieval
  console.log('[VaultBank API] Auth tokens from localStorage:', { token, sessionToken, legacyToken });

  return token || sessionToken || legacyToken;
}

/**
 * Build request headers - VULN: logs all headers including sensitive auth data
 */
function buildHeaders(customHeaders?: Record<string, string>): Record<string, string> {
  const token = getAuthToken();
  const userId = typeof window !== 'undefined' ? localStorage.getItem('userId') : null;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-API-Key': VAULTBANK_API_KEY,      // VULN (hardcoded key): always included
    'X-VaultBank-Client': 'web-frontend-v2.1',
    'X-Build-Timestamp': '2024-01-15T00:00:00Z',
    ...customHeaders,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (userId) {
    headers['X-User-ID'] = userId;         // VULN: user ID in custom header
  }

  // VULN (console.log): ALL request headers logged including Authorization token
  console.log('[VaultBank API] Request headers:', headers);
  console.log('[VaultBank API] Authorization header value:', headers['Authorization']);

  return headers;
}

/**
 * Core fetch wrapper - contains multiple vulnerabilities
 */
async function apiFetch<T = unknown>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { method = 'GET', body, headers: customHeaders, skipAuth = false } = options;
  const token = getAuthToken();

  // VULN (token in URL): Auth token appended as query param - appears in server logs, browser history
  const separator = endpoint.includes('?') ? '&' : '?';
  const urlWithToken = skipAuth
    ? `${API_BASE_URL}${endpoint}`
    : `${API_BASE_URL}${endpoint}${separator}token=${token}&apiKey=${VAULTBANK_API_KEY}`; // VULN

  // VULN (console.log): Full URL with credentials logged
  console.log('[VaultBank API] Request URL (contains token):', urlWithToken);
  console.log('[VaultBank API] Method:', method);
  if (body) {
    // VULN (console.log): Request body including sensitive data logged
    console.log('[VaultBank API] Request body:', JSON.stringify(body, null, 2));
  }

  const fetchOptions: RequestInit = {
    method,
    headers: buildHeaders(customHeaders),
    // VULN (CORS credentials): credentials: 'include' sent to all origins without restriction
    credentials: 'include',
    // VULN: no cache control - sensitive data may be cached
    cache: 'default',
  };

  if (body) {
    fetchOptions.body = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(urlWithToken, fetchOptions);
  } catch (networkError: any) {
    // VULN (console.log): Network error with URL (containing token) logged
    console.error('[VaultBank API] Network error for URL:', urlWithToken, 'Error:', networkError);
    throw networkError;
  }

  let responseData: unknown;
  const contentType = response.headers.get('content-type');

  if (contentType && contentType.includes('application/json')) {
    responseData = await response.json();
  } else {
    responseData = await response.text();
  }

  // VULN (console.log): Full response including any sensitive data logged
  console.log('[VaultBank API] Response status:', response.status);
  console.log('[VaultBank API] Response data:', responseData);

  if (!response.ok) {
    const error = new Error(`API Error: ${response.status}`) as ApiError;
    error.status = response.status;
    error.responseData = responseData;
    // VULN (error logging): Request body (with sensitive data) stored in error
    error.requestData = body;

    // VULN (console.log): Full error response including any sensitive server data logged
    console.error('[VaultBank API] Error response:', {
      status: response.status,
      url: urlWithToken,          // VULN: URL with token in error log
      requestBody: body,          // VULN: request body in error log
      responseData,               // VULN: full error response logged
    });

    throw error;
  }

  return responseData as T;
}

// ============================================================================
// Account Endpoints
// ============================================================================

export const accountsApi = {
  /**
   * Get all accounts for current user
   * VULN (IDOR): No server-side ownership check - any user can get any account
   */
  getAll: () => {
    const userId = typeof window !== 'undefined' ? localStorage.getItem('userId') : null;
    // VULN (IDOR): userId from localStorage used in API call - easily manipulated
    return apiFetch<{ accounts: unknown[] }>(`/accounts?userId=${userId}`);
  },

  /**
   * Get specific account by ID
   * VULN (IDOR): accountId not validated against current user
   */
  getById: (accountId: string) => {
    // VULN (console.log): account being accessed logged
    console.log('[VaultBank API] Accessing account (IDOR risk):', accountId);
    return apiFetch<unknown>(`/accounts/${accountId}`);
  },

  /**
   * Get account balance - returns full account data including sensitive fields
   */
  getBalance: (accountId: string) =>
    apiFetch<{ balance: number; ssn: string; creditScore: number }>( // VULN: SSN in balance response type
      `/accounts/${accountId}/balance`
    ),

  /**
   * Update account settings
   * VULN: No CSRF protection, no ownership verification
   */
  update: (accountId: string, data: unknown) =>
    apiFetch<unknown>(`/accounts/${accountId}`, { method: 'PUT', body: data }),
};

// ============================================================================
// Transfer Endpoints
// ============================================================================

export const transfersApi = {
  /**
   * Initiate a fund transfer
   * VULN: No CSRF token, amount validation only on client
   */
  create: (transferData: unknown) => {
    // VULN (console.log): Full transfer data including account numbers logged
    console.log('[VaultBank API] Creating transfer:', transferData);
    return apiFetch<{ transactionId: string; authCode: string }>(
      '/transfers',
      { method: 'POST', body: transferData }
    );
  },

  /**
   * Get transfer history
   * VULN (IDOR): No ownership check on userId parameter
   */
  getHistory: (userId?: string) => {
    // VULN (IDOR): If userId is passed, can get another user's transfer history
    const targetUserId = userId || localStorage.getItem('userId');
    return apiFetch<unknown[]>(`/transfers?userId=${targetUserId}`);
  },

  /**
   * Cancel a scheduled transfer
   */
  cancel: (transferId: string) =>
    apiFetch<void>(`/transfers/${transferId}`, { method: 'DELETE' }),
};

// ============================================================================
// Authentication Endpoints
// ============================================================================

export const authApi = {
  /**
   * Login
   * VULN: Response stores token in localStorage, logs credentials
   */
  login: async (email: string, password: string) => {
    // VULN (console.log): Login credentials logged
    console.log('[VaultBank API] Login attempt:', { email, password }); // VULN: password logged!

    const response = await apiFetch<{
      token: string;
      userId: string;
      sessionToken: string;
      userData: unknown;
    }>('/auth/login', {
      method: 'POST',
      body: { email, password },
      skipAuth: true,
    });

    // VULN (localStorage): All auth data stored in localStorage
    if (typeof window !== 'undefined') {
      localStorage.setItem('authToken', response.token);
      localStorage.setItem('userId', response.userId);
      localStorage.setItem('sessionToken', response.sessionToken);
      // VULN (localStorage): Full user data object stored in localStorage
      localStorage.setItem('userData', JSON.stringify(response.userData));

      // VULN (console.log): Token and user data logged after login
      console.log('[VaultBank API] Login success, storing token:', response.token);
      console.log('[VaultBank API] User data stored:', response.userData);
    }

    return response;
  },

  /**
   * Logout
   * VULN: Token not invalidated server-side properly
   */
  logout: () => {
    if (typeof window !== 'undefined') {
      // VULN: Only clears localStorage, doesn't invalidate server-side session
      localStorage.removeItem('authToken');
      localStorage.removeItem('sessionToken');
      // Note: 'userData' NOT removed - PII persists in localStorage after logout
    }
    return apiFetch<void>('/auth/logout', { method: 'POST' });
  },

  /**
   * Refresh token
   * VULN: Refresh token also stored in localStorage
   */
  refresh: () => {
    const refreshToken = localStorage.getItem('refreshToken'); // VULN (localStorage)
    console.log('[VaultBank API] Refreshing with token:', refreshToken); // VULN (console.log)
    return apiFetch<{ token: string }>('/auth/refresh', {
      method: 'POST',
      body: { refreshToken },
    });
  },

  /**
   * Get current user profile - returns sensitive data
   */
  getProfile: () =>
    apiFetch<{
      ssn: string;          // VULN: SSN in profile response
      creditScore: number;
      internalRating: string;
      annualIncome: number;
    }>('/auth/profile'),
};

// ============================================================================
// Payment Endpoints
// ============================================================================

export const paymentsApi = {
  /**
   * Process a payment
   * VULN: Card data sent to frontend API, not directly to payment processor
   */
  processPayment: (paymentData: {
    cardNumber: string;  // VULN: full card number sent through app backend
    cvv: string;         // VULN: CVV stored/transmitted through app
    expiry: string;
    amount: number;
  }) => {
    // VULN (console.log): Card data logged
    console.log('[VaultBank API] Processing payment with card:', paymentData.cardNumber);
    console.log('[VaultBank API] CVV:', paymentData.cvv); // VULN: CVV logged
    return apiFetch<{ paymentId: string; status: string }>(
      '/payments',
      { method: 'POST', body: paymentData }
    );
  },

  /**
   * Wire transfer
   */
  wireTransfer: (wireData: unknown) => {
    // VULN (console.log): Wire transfer details logged
    console.log('[VaultBank API] Wire transfer:', wireData);
    return apiFetch<unknown>('/payments/wire', { method: 'POST', body: wireData });
  },
};

// ============================================================================
// Admin Endpoints - VULN: Admin endpoints accessible from frontend
// ============================================================================

export const adminApi = {
  /**
   * VULN: Admin endpoints callable from frontend JavaScript
   * Should be backend-only
   */
  getAllUsers: () => {
    // VULN (hardcoded URL): Admin API URL hardcoded with internal address
    const adminUrl = process.env.NEXT_PUBLIC_ADMIN_API_URL || 'http://192.168.1.100:8080/admin';
    const adminKey = process.env.NEXT_PUBLIC_API_SECRET || 'api_secret_should_not_be_public_vb2024';

    console.log('[VaultBank API] Calling admin API (from frontend!):', adminUrl);

    return fetch(`${adminUrl}/users?apiKey=${adminKey}`, {
      headers: {
        'X-Admin-Key': adminKey,  // VULN: admin key in frontend code
        'Authorization': `Bearer ${getAuthToken()}`,
      },
      credentials: 'include',
    }).then(r => r.json());
  },

  /**
   * Get all transactions - admin endpoint exposed to frontend
   */
  getAllTransactions: (filters?: Record<string, string>) => {
    const params = new URLSearchParams(filters);
    return apiFetch<unknown[]>(`/admin/transactions?${params}`);
  },
};

// ============================================================================
// Utility functions
// ============================================================================

/**
 * VULN: Debug utility that dumps all stored credentials
 * Left in production code
 */
export function debugDumpCredentials() {
  if (typeof window === 'undefined') return;

  const credentials = {
    authToken: localStorage.getItem('authToken'),
    sessionToken: localStorage.getItem('sessionToken'),
    refreshToken: localStorage.getItem('refreshToken'),
    userId: localStorage.getItem('userId'),
    userData: localStorage.getItem('userData'),
    apiKey: VAULTBANK_API_KEY,
    internalUser: INTERNAL_SERVICE_USER,
    internalPass: INTERNAL_SERVICE_PASS,
  };

  // VULN (console.log): All credentials dumped
  console.log('[VaultBank DEBUG] All stored credentials:', credentials);
  return credentials;
}

// VULN: Auto-run debug dump on module load in development
// "development" check accidentally also matches some production env vars
if (process.env.NODE_ENV !== 'test') {
  if (typeof window !== 'undefined') {
    (window as any).__vaultbankDebug = debugDumpCredentials; // VULN: exposed on window object
  }
}

export default {
  accounts: accountsApi,
  transfers: transfersApi,
  auth: authApi,
  payments: paymentsApi,
  admin: adminApi,
  debug: debugDumpCredentials,
};
