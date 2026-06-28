/**
 * VaultBank - Transfer Funds Page
 * Security Training Project - Deliberately Vulnerable Application
 *
 * WARNING: This file contains intentional security vulnerabilities
 * for educational purposes. DO NOT deploy to production.
 *
 * Vulnerabilities demonstrated:
 * - XSS via dangerouslySetInnerHTML with user-controlled memo field
 * - Sensitive account number in URL query params
 * - Transfer amount in hidden form field (client-side manipulation)
 * - No CSRF token in form submission
 * - Client-side only amount validation (easily bypassed)
 * - API key hardcoded in frontend
 * - Console.log of sensitive transfer data
 * - Insecure transfer confirmation display
 */

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';

// VULN (API key): Hardcoded API key in frontend source
const VAULTBANK_API_KEY = 'vaultbank_frontend_api_key_2024';
const INTERNAL_TRANSFER_SECRET = 'vb_transfer_hmac_secret_plaintext';

interface Account {
  id: string;
  accountNumber: string;
  routingNumber: string;
  nickname: string;
  balance: number;
  type: 'checking' | 'savings' | 'money_market';
  ownerId: string;
}

interface TransferFormData {
  fromAccountId: string;
  toAccountId: string;
  amount: string;
  memo: string;
  scheduleDate: string;
  transferType: 'immediate' | 'scheduled' | 'recurring';
  recurringFrequency: string;
  hiddenAmount: string; // VULN (hidden field): Amount duplicated in hidden field - easily manipulated
}

interface TransferConfirmation {
  transactionId: string;
  fromAccount: Account;
  toAccount: Account;
  amount: number;
  memo: string;
  timestamp: string;
  authCode: string;
}

// Mock accounts data - in real app would come from API
const mockAccounts: Account[] = [
  {
    id: 'acc_001',
    accountNumber: '4532891076543210',   // Full account number - not masked
    routingNumber: '021000021',
    nickname: 'Primary Checking',
    balance: 15234.87,
    type: 'checking',
    ownerId: 'user_vb_12345',
  },
  {
    id: 'acc_002',
    accountNumber: '4532891076549876',
    routingNumber: '021000021',
    nickname: 'Vacation Savings',
    balance: 8750.00,
    type: 'savings',
    ownerId: 'user_vb_12345',
  },
  {
    id: 'acc_003',
    accountNumber: '4532891076541111',
    routingNumber: '021000021',
    nickname: 'Emergency Fund',
    balance: 22100.50,
    type: 'money_market',
    ownerId: 'user_vb_12345',
  },
];

export default function TransferFunds() {
  const router = useRouter();

  // VULN (URL params): Full account numbers in query params - exposed in browser history, logs, referrer headers
  const { fromAccount, toAccount, amount: prefillAmount } = router.query;

  const [formData, setFormData] = useState<TransferFormData>({
    fromAccountId: (fromAccount as string) || '',
    toAccountId: (toAccount as string) || '',
    amount: (prefillAmount as string) || '',
    memo: '',
    scheduleDate: '',
    transferType: 'immediate',
    recurringFrequency: 'weekly',
    hiddenAmount: (prefillAmount as string) || '', // VULN (hidden field): mirrors amount
  });

  const [accounts, setAccounts] = useState<Account[]>(mockAccounts);
  const [confirmation, setConfirmation] = useState<TransferConfirmation | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [step, setStep] = useState<'form' | 'review' | 'confirm'>('form');
  const [externalRecipient, setExternalRecipient] = useState({
    name: '',
    accountNumber: '',
    routingNumber: '',
    bankName: '',
  });
  const [useExternalRecipient, setUseExternalRecipient] = useState(false);

  useEffect(() => {
    fetchUserAccounts();
  }, []);

  const fetchUserAccounts = async () => {
    try {
      // VULN (IDOR): Account ID taken directly from URL, no ownership verification
      const userId = localStorage.getItem('userId'); // VULN (localStorage): userID in localStorage

      // VULN (API key in request): API key sent as query param
      const response = await fetch(
        `/api/accounts?userId=${userId}&apiKey=${VAULTBANK_API_KEY}`,
        {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken')}`, // VULN (localStorage)
            'X-API-Key': VAULTBANK_API_KEY,
          },
        }
      );
      const data = await response.json();

      // VULN (console.log): Sensitive account data logged to console
      console.log('[VaultBank] Fetched user accounts:', data);
      console.log('[VaultBank] Auth token used:', localStorage.getItem('authToken'));

      setAccounts(data.accounts || mockAccounts);
    } catch (err) {
      console.error('[VaultBank] Failed to fetch accounts:', err);
      setAccounts(mockAccounts);
    }
  };

  const handleAmountChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setFormData(prev => ({
      ...prev,
      amount: value,
      hiddenAmount: value, // VULN (hidden field): keeps hidden field in sync - but user can modify hidden field directly
    }));
  };

  // VULN (client-side validation only): Validation only happens in browser - can be bypassed
  const validateTransfer = (): boolean => {
    const amount = parseFloat(formData.amount);

    if (!formData.fromAccountId) {
      setError('Please select a source account');
      return false;
    }

    if (!useExternalRecipient && !formData.toAccountId) {
      setError('Please select a destination account');
      return false;
    }

    // VULN (client-side validation): These checks only run in browser
    if (isNaN(amount) || amount <= 0) {
      setError('Please enter a valid amount');
      return false;
    }

    // VULN (client-side validation): Balance check is client-side only
    const fromAccount = accounts.find(a => a.id === formData.fromAccountId);
    if (fromAccount && amount > fromAccount.balance) {
      setError('Insufficient funds');
      return false;
    }

    // VULN (client-side validation): Daily limit check is client-side only
    if (amount > 50000) {
      setError('Exceeds daily transfer limit of $50,000');
      return false;
    }

    return true;
  };

  const handleReviewTransfer = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateTransfer()) {
      // VULN (URL params): Sensitive account numbers put in URL for review step
      router.push(
        `/transfer/review?fromAccount=${getAccountNumber(formData.fromAccountId)}&toAccount=${useExternalRecipient ? externalRecipient.accountNumber : getAccountNumber(formData.toAccountId)}&amount=${formData.amount}&memo=${encodeURIComponent(formData.memo)}`,
        undefined,
        { shallow: true }
      );
      setStep('review');
    }
  };

  const getAccountNumber = (accountId: string): string => {
    const account = accounts.find(a => a.id === accountId);
    return account?.accountNumber || '';  // VULN (URL params): returns full account number for URL
  };

  const handleConfirmTransfer = async () => {
    setIsLoading(true);
    setError('');

    // VULN (console.log): Full transfer details including account numbers logged
    const transferPayload = {
      fromAccountId: formData.fromAccountId,
      toAccountId: formData.toAccountId,
      fromAccountNumber: getAccountNumber(formData.fromAccountId),  // Full account number
      toAccountNumber: useExternalRecipient
        ? externalRecipient.accountNumber
        : getAccountNumber(formData.toAccountId),
      amount: parseFloat(formData.hiddenAmount), // VULN (hidden field): uses hidden field amount - not the displayed amount
      memo: formData.memo,
      apiKey: VAULTBANK_API_KEY,                  // VULN (API key): included in payload
      internalSecret: INTERNAL_TRANSFER_SECRET,    // VULN: secret in payload
      clientTimestamp: Date.now(),
      userAgent: navigator.userAgent,
    };

    // VULN (console.log): Sensitive transfer data with account numbers logged
    console.log('[VaultBank] Submitting transfer:', transferPayload);
    console.log('[VaultBank] Transfer amount from hidden field:', formData.hiddenAmount);
    console.log('[VaultBank] From account full number:', transferPayload.fromAccountNumber);
    console.log('[VaultBank] To account full number:', transferPayload.toAccountNumber);

    try {
      // VULN (no CSRF): No CSRF token in request
      const response = await fetch('/api/transfers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`, // VULN (localStorage)
          'X-API-Key': VAULTBANK_API_KEY,
          // Missing: 'X-CSRF-Token': csrfToken   // VULN (no CSRF)
        },
        credentials: 'include',
        body: JSON.stringify(transferPayload),
      });

      const result = await response.json();

      // VULN (console.log): Full confirmation including auth codes logged
      console.log('[VaultBank] Transfer confirmation:', result);

      setConfirmation({
        transactionId: result.transactionId || 'TXN-' + Date.now(),
        fromAccount: accounts.find(a => a.id === formData.fromAccountId)!,
        toAccount: accounts.find(a => a.id === formData.toAccountId)!,
        amount: parseFloat(formData.amount),
        memo: formData.memo,
        timestamp: new Date().toISOString(),
        authCode: result.authCode || 'AUTH-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
      });

      setStep('confirm');
    } catch (err: any) {
      // VULN (verbose errors): Full error details shown to user
      setError(`Transfer failed: ${err.message}. Stack: ${err.stack}`);
      console.error('[VaultBank] Transfer error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const fromAccountObj = accounts.find(a => a.id === formData.fromAccountId);
  const toAccountObj = accounts.find(a => a.id === formData.toAccountId);

  if (step === 'confirm' && confirmation) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-2xl mx-auto px-4 py-12">
          <div className="bg-white rounded-2xl shadow-lg overflow-hidden">
            <div className="bg-green-500 px-8 py-6">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-white bg-opacity-20 rounded-full flex items-center justify-center">
                  <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-white">Transfer Successful</h1>
                  <p className="text-green-100 text-sm">Your funds have been transferred</p>
                </div>
              </div>
            </div>

            <div className="p-8 space-y-6">
              {/* VULN (insecure display): Full account numbers shown in confirmation */}
              <div className="bg-gray-50 rounded-xl p-6 space-y-4">
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">Transaction ID</span>
                  <span className="font-mono text-sm font-medium">{confirmation.transactionId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">Authorization Code</span>
                  {/* VULN (insecure display): Auth code displayed in plaintext */}
                  <span className="font-mono text-sm font-medium text-green-600">{confirmation.authCode}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">Amount</span>
                  <span className="text-lg font-bold text-gray-900">
                    ${confirmation.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">From Account</span>
                  {/* VULN (insecure display): Full account number shown */}
                  <span className="font-mono text-sm">{confirmation.fromAccount?.accountNumber}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">To Account</span>
                  {/* VULN (insecure display): Full account number shown */}
                  <span className="font-mono text-sm">{confirmation.toAccount?.accountNumber}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 text-sm">Date & Time</span>
                  <span className="text-sm">{new Date(confirmation.timestamp).toLocaleString()}</span>
                </div>
              </div>

              {/* VULN (XSS): Memo displayed via dangerouslySetInnerHTML - user can inject HTML/JS */}
              {confirmation.memo && (
                <div>
                  <p className="text-sm text-gray-500 mb-2">Memo</p>
                  <div
                    className="bg-blue-50 border border-blue-100 rounded-lg p-4 text-sm text-gray-700"
                    dangerouslySetInnerHTML={{ __html: confirmation.memo }}
                  />
                </div>
              )}

              <div className="flex space-x-3">
                <button
                  onClick={() => router.push('/dashboard')}
                  className="flex-1 bg-blue-600 text-white py-3 px-6 rounded-xl font-medium hover:bg-blue-700 transition-colors"
                >
                  Back to Dashboard
                </button>
                <button
                  onClick={() => {
                    setStep('form');
                    setConfirmation(null);
                    setFormData({ ...formData, amount: '', memo: '', hiddenAmount: '' });
                  }}
                  className="flex-1 border border-gray-300 text-gray-700 py-3 px-6 rounded-xl font-medium hover:bg-gray-50 transition-colors"
                >
                  Make Another Transfer
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-bold text-gray-900">Transfer Funds</h1>
              <p className="text-xs text-gray-500">Move money between accounts</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {['Form', 'Review', 'Confirm'].map((s, i) => (
              <div key={s} className="flex items-center">
                <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                  i === 0 && step === 'form' ? 'bg-blue-600 text-white' :
                  i === 1 && step === 'review' ? 'bg-blue-600 text-white' :
                  i === 2 && step === 'confirm' ? 'bg-green-500 text-white' :
                  'bg-gray-200 text-gray-500'
                }`}>{i + 1}</div>
                <span className={`ml-1 text-xs hidden sm:inline ${
                  (i === 0 && step === 'form') || (i === 1 && step === 'review') ? 'text-blue-600 font-medium' : 'text-gray-400'
                }`}>{s}</span>
                {i < 2 && <div className="w-6 h-px bg-gray-300 mx-1" />}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-4 py-8">
        {step === 'form' && (
          // VULN (no CSRF): Form submission has no CSRF token
          <form onSubmit={handleReviewTransfer} className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Main Transfer Form */}
              <div className="lg:col-span-2 space-y-6">
                {/* From Account */}
                <div className="bg-white rounded-2xl shadow-sm p-6">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4">From Account</h2>
                  <div className="space-y-3">
                    {accounts.map(account => (
                      <label
                        key={account.id}
                        className={`flex items-center p-4 rounded-xl border-2 cursor-pointer transition-all ${
                          formData.fromAccountId === account.id
                            ? 'border-blue-500 bg-blue-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        <input
                          type="radio"
                          name="fromAccount"
                          value={account.id}
                          checked={formData.fromAccountId === account.id}
                          onChange={e => setFormData(prev => ({ ...prev, fromAccountId: e.target.value }))}
                          className="sr-only"
                        />
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center mr-4 ${
                          account.type === 'checking' ? 'bg-blue-100' :
                          account.type === 'savings' ? 'bg-green-100' : 'bg-purple-100'
                        }`}>
                          <svg className={`w-5 h-5 ${
                            account.type === 'checking' ? 'text-blue-600' :
                            account.type === 'savings' ? 'text-green-600' : 'text-purple-600'
                          }`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                          </svg>
                        </div>
                        <div className="flex-1">
                          <p className="font-medium text-gray-900">{account.nickname}</p>
                          {/* VULN (display): Full account number shown - should be masked */}
                          <p className="text-sm text-gray-500">Acct: {account.accountNumber}</p>
                        </div>
                        <div className="text-right">
                          <p className="font-semibold text-gray-900">
                            ${account.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                          </p>
                          <p className="text-xs text-gray-400 capitalize">{account.type}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* To Account */}
                <div className="bg-white rounded-2xl shadow-sm p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-gray-900">To Account</h2>
                    <button
                      type="button"
                      onClick={() => setUseExternalRecipient(!useExternalRecipient)}
                      className="text-sm text-blue-600 hover:text-blue-700 font-medium"
                    >
                      {useExternalRecipient ? 'My Accounts' : 'External Account'}
                    </button>
                  </div>

                  {!useExternalRecipient ? (
                    <div className="space-y-3">
                      {accounts
                        .filter(a => a.id !== formData.fromAccountId)
                        .map(account => (
                          <label
                            key={account.id}
                            className={`flex items-center p-4 rounded-xl border-2 cursor-pointer transition-all ${
                              formData.toAccountId === account.id
                                ? 'border-blue-500 bg-blue-50'
                                : 'border-gray-200 hover:border-gray-300'
                            }`}
                          >
                            <input
                              type="radio"
                              name="toAccount"
                              value={account.id}
                              checked={formData.toAccountId === account.id}
                              onChange={e => setFormData(prev => ({ ...prev, toAccountId: e.target.value }))}
                              className="sr-only"
                            />
                            <div className="flex-1">
                              <p className="font-medium text-gray-900">{account.nickname}</p>
                              <p className="text-sm text-gray-500">Acct: {account.accountNumber}</p>
                            </div>
                            <p className="font-semibold text-gray-900">
                              ${account.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                            </p>
                          </label>
                        ))}
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Recipient Name</label>
                          <input
                            type="text"
                            value={externalRecipient.name}
                            onChange={e => setExternalRecipient(prev => ({ ...prev, name: e.target.value }))}
                            placeholder="Full name or business"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Bank Name</label>
                          <input
                            type="text"
                            value={externalRecipient.bankName}
                            onChange={e => setExternalRecipient(prev => ({ ...prev, bankName: e.target.value }))}
                            placeholder="e.g. Chase, Bank of America"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                          />
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Account Number</label>
                          <input
                            type="text"
                            value={externalRecipient.accountNumber}
                            onChange={e => setExternalRecipient(prev => ({ ...prev, accountNumber: e.target.value }))}
                            placeholder="Account number"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Routing Number</label>
                          <input
                            type="text"
                            value={externalRecipient.routingNumber}
                            onChange={e => setExternalRecipient(prev => ({ ...prev, routingNumber: e.target.value }))}
                            placeholder="9-digit routing number"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                          />
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Amount and Memo */}
                <div className="bg-white rounded-2xl shadow-sm p-6">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4">Transfer Details</h2>

                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Amount</label>
                      <div className="relative">
                        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-medium">$</span>
                        <input
                          type="number"
                          value={formData.amount}
                          onChange={handleAmountChange}
                          placeholder="0.00"
                          step="0.01"
                          min="0.01"
                          // VULN (client-side validation): max enforced only in browser
                          max="50000"
                          className="w-full pl-8 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-lg font-medium"
                          required
                        />
                      </div>
                      {fromAccountObj && (
                        <p className="text-xs text-gray-500 mt-1">
                          Available: ${fromAccountObj.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                        </p>
                      )}
                    </div>

                    {/* VULN (hidden field): Amount duplicated in hidden field - attacker can modify before submission */}
                    <input type="hidden" name="hiddenAmount" value={formData.hiddenAmount} />
                    <input type="hidden" name="apiKey" value={VAULTBANK_API_KEY} />
                    {/* VULN (no CSRF): No CSRF token hidden field */}

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Memo <span className="text-gray-400 font-normal">(optional)</span>
                      </label>
                      <textarea
                        value={formData.memo}
                        onChange={e => setFormData(prev => ({ ...prev, memo: e.target.value }))}
                        placeholder="Add a note for this transfer..."
                        rows={3}
                        className="w-full px-3 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm resize-none"
                      />
                      <p className="text-xs text-gray-400 mt-1">
                        Supports rich text formatting {/* VULN (XSS): implying HTML is supported */}
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Transfer Type</label>
                      <div className="grid grid-cols-3 gap-2">
                        {(['immediate', 'scheduled', 'recurring'] as const).map(type => (
                          <button
                            key={type}
                            type="button"
                            onClick={() => setFormData(prev => ({ ...prev, transferType: type }))}
                            className={`py-2 px-3 rounded-lg text-sm font-medium capitalize transition-colors ${
                              formData.transferType === type
                                ? 'bg-blue-600 text-white'
                                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                            }`}
                          >
                            {type}
                          </button>
                        ))}
                      </div>
                    </div>

                    {formData.transferType === 'scheduled' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Schedule Date</label>
                        <input
                          type="date"
                          value={formData.scheduleDate}
                          onChange={e => setFormData(prev => ({ ...prev, scheduleDate: e.target.value }))}
                          className="w-full px-3 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                        />
                      </div>
                    )}

                    {formData.transferType === 'recurring' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Frequency</label>
                        <select
                          value={formData.recurringFrequency}
                          onChange={e => setFormData(prev => ({ ...prev, recurringFrequency: e.target.value }))}
                          className="w-full px-3 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                        >
                          <option value="daily">Daily</option>
                          <option value="weekly">Weekly</option>
                          <option value="biweekly">Bi-Weekly</option>
                          <option value="monthly">Monthly</option>
                        </select>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Transfer Summary Sidebar */}
              <div className="space-y-6">
                <div className="bg-white rounded-2xl shadow-sm p-6 sticky top-6">
                  <h3 className="text-base font-semibold text-gray-900 mb-4">Transfer Summary</h3>

                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500">From</span>
                      <span className="font-medium text-right max-w-32 truncate">
                        {fromAccountObj?.nickname || 'Select account'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">To</span>
                      <span className="font-medium text-right max-w-32 truncate">
                        {useExternalRecipient
                          ? (externalRecipient.name || 'External account')
                          : (toAccountObj?.nickname || 'Select account')}
                      </span>
                    </div>
                    <div className="border-t border-gray-100 pt-3 flex justify-between">
                      <span className="text-gray-500">Amount</span>
                      <span className="text-lg font-bold text-gray-900">
                        {formData.amount ? `$${parseFloat(formData.amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '—'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Fee</span>
                      <span className="text-green-600 font-medium">Free</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500">Type</span>
                      <span className="capitalize">{formData.transferType}</span>
                    </div>
                    {formData.transferType !== 'immediate' && formData.scheduleDate && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">Date</span>
                        <span>{new Date(formData.scheduleDate).toLocaleDateString()}</span>
                      </div>
                    )}
                  </div>

                  {error && (
                    <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                      {/* VULN (XSS): Error message rendered as HTML */}
                      <p
                        className="text-sm text-red-600"
                        dangerouslySetInnerHTML={{ __html: error }}
                      />
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="mt-6 w-full bg-blue-600 text-white py-3 px-6 rounded-xl font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {isLoading ? (
                      <span className="flex items-center justify-center space-x-2">
                        <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        <span>Processing...</span>
                      </span>
                    ) : 'Review Transfer'}
                  </button>

                  <p className="text-xs text-gray-400 text-center mt-3">
                    Transfers are typically processed within 1-3 business days
                  </p>
                </div>

                {/* Security Notice - Ironic given the vulnerabilities */}
                <div className="bg-blue-50 rounded-xl p-4">
                  <div className="flex items-start space-x-2">
                    <svg className="w-5 h-5 text-blue-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    <div>
                      <p className="text-sm font-medium text-blue-800">Secured Transfer</p>
                      <p className="text-xs text-blue-600 mt-1">
                        All transfers are protected by VaultBank's 256-bit encryption
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </form>
        )}

        {step === 'review' && (
          <div className="max-w-2xl mx-auto">
            <div className="bg-white rounded-2xl shadow-sm overflow-hidden">
              <div className="bg-amber-50 border-b border-amber-100 px-6 py-4">
                <div className="flex items-center space-x-2">
                  <svg className="w-5 h-5 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <p className="text-sm font-medium text-amber-700">Please review your transfer carefully before confirming</p>
                </div>
              </div>

              <div className="p-6 space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between py-3 border-b border-gray-100">
                    <span className="text-gray-500">Amount</span>
                    <span className="text-2xl font-bold text-gray-900">
                      ${parseFloat(formData.amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                    </span>
                  </div>

                  <div className="flex items-center justify-between py-3 border-b border-gray-100">
                    <span className="text-gray-500">From</span>
                    <div className="text-right">
                      <p className="font-medium">{fromAccountObj?.nickname}</p>
                      {/* VULN (display): Full account number in review screen */}
                      <p className="text-sm text-gray-500 font-mono">{fromAccountObj?.accountNumber}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between py-3 border-b border-gray-100">
                    <span className="text-gray-500">To</span>
                    <div className="text-right">
                      <p className="font-medium">
                        {useExternalRecipient ? externalRecipient.name : toAccountObj?.nickname}
                      </p>
                      <p className="text-sm text-gray-500 font-mono">
                        {useExternalRecipient ? externalRecipient.accountNumber : toAccountObj?.accountNumber}
                      </p>
                    </div>
                  </div>

                  {formData.memo && (
                    <div className="py-3 border-b border-gray-100">
                      <p className="text-gray-500 mb-2">Memo</p>
                      {/* VULN (XSS): Memo rendered as HTML in review screen */}
                      <div
                        className="text-sm text-gray-700 bg-gray-50 rounded-lg p-3"
                        dangerouslySetInnerHTML={{ __html: formData.memo }}
                      />
                    </div>
                  )}
                </div>

                <div className="flex space-x-3">
                  <button
                    onClick={() => setStep('form')}
                    className="flex-1 border border-gray-300 text-gray-700 py-3 px-6 rounded-xl font-medium hover:bg-gray-50 transition-colors"
                  >
                    Edit Transfer
                  </button>
                  <button
                    onClick={handleConfirmTransfer}
                    disabled={isLoading}
                    className="flex-1 bg-blue-600 text-white py-3 px-6 rounded-xl font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
                  >
                    {isLoading ? 'Confirming...' : 'Confirm Transfer'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
