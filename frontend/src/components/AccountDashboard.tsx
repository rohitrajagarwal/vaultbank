/**
 * VaultBank - Account Dashboard Component
 * Security Training Project - Deliberately Vulnerable Application
 *
 * WARNING: This file contains intentional security vulnerabilities
 * for educational purposes. DO NOT deploy to production.
 *
 * Vulnerabilities demonstrated:
 * - Full account number displayed (should be masked to last 4)
 * - Full SSN displayed (should never be displayed)
 * - Credit score and internal notes visible to client
 * - Console.log of sensitive account data including PII
 * - XSS in account name display via dangerouslySetInnerHTML
 * - IDOR in account fetch (accountId from URL, no ownership check)
 * - Auth token stored in localStorage and logged to console
 */

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/router';

interface Transaction {
  id: string;
  date: string;
  description: string;
  amount: number;
  type: 'credit' | 'debit';
  balance: number;
  category: string;
  merchantId: string;
  internalNotes: string; // VULN: internal notes visible to client
}

interface AccountData {
  id: string;
  accountNumber: string;       // VULN: full account number - should never be fully exposed
  routingNumber: string;
  type: 'checking' | 'savings' | 'money_market' | 'credit';
  nickname: string;
  balance: number;
  availableBalance: number;
  pendingAmount: number;
  // Highly sensitive fields that should NOT be on the client
  ssn: string;                 // VULN: SSN should NEVER be returned to client
  dateOfBirth: string;         // VULN: DOB on client
  creditScore: number;         // VULN: credit score visible
  creditScoreModel: string;
  internalRiskRating: string;  // VULN: internal bank risk rating
  internalNotes: string;       // VULN: internal notes visible
  fraudAlerts: string[];       // VULN: fraud alerts visible
  kycStatus: string;
  ofacStatus: string;          // VULN: OFAC screening status
  ownerId: string;
  transactions: Transaction[];
  linkedCards: {
    number: string;            // VULN: full card number
    cvv: string;               // VULN: CVV should NEVER be exposed
    expiry: string;
    type: string;
  }[];
}

interface UserProfile {
  id: string;
  email: string;
  phone: string;
  ssn: string;                 // VULN: SSN in profile object
  address: string;
  employerName: string;
  annualIncome: number;        // VULN: income data on client
  accountManager: string;
  internalCustomerTier: string;
}

// VULN (IDOR): Account fetch uses ID from URL without server-side ownership verification
const fetchAccountData = async (accountId: string, authToken: string): Promise<AccountData> => {
  // VULN (console.log): auth token logged
  console.log('[VaultBank] Fetching account:', accountId, 'with token:', authToken);

  // VULN (IDOR): accountId from query param used directly - attacker can enumerate other accounts
  const response = await fetch(`/api/accounts/${accountId}`, {
    headers: {
      'Authorization': `Bearer ${authToken}`,
      // VULN: token also sent as query param for "compatibility"
    },
  });

  const data = await response.json();

  // VULN (console.log): Full response including SSN, account numbers logged
  console.log('[VaultBank] Account data received:', data);
  console.log('[VaultBank] Account SSN:', data.ssn);                    // VULN
  console.log('[VaultBank] Account number:', data.accountNumber);       // VULN
  console.log('[VaultBank] Credit score:', data.creditScore);           // VULN
  console.log('[VaultBank] Internal risk rating:', data.internalRiskRating); // VULN

  return data;
};

const MOCK_ACCOUNT_DATA: AccountData = {
  id: 'acc_001',
  accountNumber: '4532891076543210',    // VULN: full account number in mock data
  routingNumber: '021000021',
  type: 'checking',
  nickname: 'Primary Checking',
  balance: 15234.87,
  availableBalance: 14734.87,
  pendingAmount: 500.00,
  ssn: '123-45-6789',                  // VULN: SSN in frontend data
  dateOfBirth: '1985-03-15',
  creditScore: 742,                    // VULN: credit score
  creditScoreModel: 'FICO 9',
  internalRiskRating: 'LOW',           // VULN: internal rating
  internalNotes: 'Customer since 2018. High-value client. Flagged for potential structuring in Q3 2023 - cleared. Prefers wire transfers.', // VULN: internal notes
  fraudAlerts: ['Unusual login location: Lagos, NG - 2024-01-15'],       // VULN: fraud alert data
  kycStatus: 'VERIFIED',
  ofacStatus: 'CLEAR',                 // VULN: OFAC status exposed
  ownerId: 'user_vb_12345',
  linkedCards: [
    {
      number: '4532891076543210',      // VULN: full card number exposed
      cvv: '456',                      // VULN: CVV should NEVER be exposed
      expiry: '12/27',
      type: 'Visa Debit',
    },
  ],
  transactions: [
    {
      id: 'txn_001',
      date: '2024-01-20',
      description: 'AMAZON.COM*2X3Y4Z5',
      amount: 127.43,
      type: 'debit',
      balance: 15107.44,
      category: 'Shopping',
      merchantId: 'AMZN_US_001',
      internalNotes: 'Fraud rule R-47 triggered, cleared automatically', // VULN: internal notes
    },
    {
      id: 'txn_002',
      date: '2024-01-19',
      description: 'DIRECT DEPOSIT - ACME CORP',
      amount: 3500.00,
      type: 'credit',
      balance: 15234.87,
      category: 'Income',
      merchantId: 'PAYROLL_001',
      internalNotes: 'Employer payroll verified',
    },
    {
      id: 'txn_003',
      date: '2024-01-18',
      description: 'SHELL OIL 0023412',
      amount: 65.00,
      type: 'debit',
      balance: 11734.87,
      category: 'Gas & Fuel',
      merchantId: 'SHELL_0023412',
      internalNotes: '',
    },
    {
      id: 'txn_004',
      date: '2024-01-17',
      description: 'TRANSFER TO SAVINGS',
      amount: 1000.00,
      type: 'debit',
      balance: 11799.87,
      category: 'Transfer',
      merchantId: 'INTERNAL',
      internalNotes: 'Customer initiated - no flags',
    },
    {
      id: 'txn_005',
      date: '2024-01-16',
      description: 'STARBUCKS #04521 NYC',
      amount: 8.75,
      type: 'debit',
      balance: 12799.87,
      category: 'Food & Drink',
      merchantId: 'SBUX_04521',
      internalNotes: '',
    },
  ],
};

const MOCK_USER: UserProfile = {
  id: 'user_vb_12345',
  email: 'john.smith@example.com',
  phone: '+1-555-867-5309',
  ssn: '123-45-6789',                  // VULN: SSN in user profile
  address: '742 Evergreen Terrace, Springfield, IL 62701',
  employerName: 'Acme Corporation',
  annualIncome: 95000,                 // VULN: income data
  accountManager: 'Sarah Johnson (Ext. 4521)',
  internalCustomerTier: 'GOLD',        // VULN: internal tier
};

export default function AccountDashboard() {
  const router = useRouter();
  const { accountId } = router.query;  // VULN (IDOR): accountId from URL

  const [accountData, setAccountData] = useState<AccountData | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'transactions' | 'details' | 'cards'>('overview');
  const [showSensitive, setShowSensitive] = useState(false);

  useEffect(() => {
    loadAccountData();
  }, [accountId]);

  const loadAccountData = async () => {
    setIsLoading(true);

    // VULN (localStorage): Auth token retrieved from localStorage
    const authToken = localStorage.getItem('authToken');
    const userId = localStorage.getItem('userId');
    const sessionData = localStorage.getItem('sessionData'); // VULN: session data in localStorage

    // VULN (console.log): Auth token and session data logged
    console.log('[VaultBank] Dashboard loading for user:', userId);
    console.log('[VaultBank] Auth token from localStorage:', authToken);
    console.log('[VaultBank] Full session data:', sessionData);
    console.log('[VaultBank] Loading account ID:', accountId, '(from URL - no ownership verification)');

    try {
      // Use mock data for demo, but would call vulnerable fetchAccountData in real app
      const data = accountId
        ? await fetchAccountData(accountId as string, authToken || '')
        : MOCK_ACCOUNT_DATA;

      // VULN (console.log): All sensitive data logged after fetch
      console.log('[VaultBank] Full account data (including SSN):', data);

      setAccountData(data || MOCK_ACCOUNT_DATA);
      setUserProfile(MOCK_USER);
    } catch (err) {
      console.error('[VaultBank] Failed to load account:', err);
      setAccountData(MOCK_ACCOUNT_DATA);
      setUserProfile(MOCK_USER);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-500">Loading your accounts...</p>
        </div>
      </div>
    );
  }

  if (!accountData) return null;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Navigation */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-2 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
            <span className="text-lg font-bold text-gray-900">VaultBank</span>
          </div>
          <div className="flex items-center space-x-4">
            <button className="text-sm text-gray-600 hover:text-gray-900">Notifications</button>
            <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
              <span className="text-sm font-medium text-blue-600">
                {userProfile?.email.charAt(0).toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Account Hero Card */}
        <div className="bg-gradient-to-br from-blue-600 to-blue-800 rounded-2xl p-8 text-white mb-8">
          <div className="flex items-start justify-between">
            <div>
              {/* VULN (XSS): Account name rendered via dangerouslySetInnerHTML */}
              <h1
                className="text-2xl font-bold mb-1"
                dangerouslySetInnerHTML={{ __html: accountData.nickname }}
              />
              <div className="flex items-center space-x-2 mb-6">
                <span className="text-blue-200 text-sm">
                  {accountData.type.charAt(0).toUpperCase() + accountData.type.slice(1).replace('_', ' ')}
                </span>
                <span className="text-blue-300">•</span>
                {/* VULN (display): Full account number displayed - should show only last 4 */}
                <span className="text-blue-200 text-sm font-mono">
                  Acct: {accountData.accountNumber}
                </span>
                <span className="text-blue-300">•</span>
                <span className="text-blue-200 text-sm font-mono">
                  Routing: {accountData.routingNumber}
                </span>
              </div>

              <div className="space-y-1">
                <p className="text-blue-200 text-sm">Current Balance</p>
                <p className="text-4xl font-bold">
                  ${accountData.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                </p>
                <p className="text-blue-200 text-sm">
                  Available: ${accountData.availableBalance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                  {accountData.pendingAmount > 0 && (
                    <span className="ml-2">(${accountData.pendingAmount.toFixed(2)} pending)</span>
                  )}
                </p>
              </div>
            </div>

            <div className="text-right space-y-2">
              <div className="bg-white bg-opacity-20 rounded-xl px-4 py-2">
                <p className="text-blue-100 text-xs">Credit Score</p>
                {/* VULN (display): Credit score displayed - internal data */}
                <p className="text-2xl font-bold">{accountData.creditScore}</p>
                <p className="text-blue-200 text-xs">{accountData.creditScoreModel}</p>
              </div>
              <div className="bg-white bg-opacity-20 rounded-xl px-4 py-2">
                <p className="text-blue-100 text-xs">Risk Rating</p>
                {/* VULN (display): Internal risk rating displayed */}
                <p className="text-xl font-bold text-green-300">{accountData.internalRiskRating}</p>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-4 gap-3 mt-8">
            {[
              { label: 'Transfer', icon: 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4', href: '/transfer' },
              { label: 'Pay Bills', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2', href: '/bills' },
              { label: 'Deposit', icon: 'M12 4v16m8-8H4', href: '/deposit' },
              { label: 'Statements', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z', href: '/statements' },
            ].map(action => (
              <button
                key={action.label}
                onClick={() => router.push(action.href)}
                className="flex flex-col items-center space-y-2 bg-white bg-opacity-10 hover:bg-opacity-20 rounded-xl p-4 transition-all"
              >
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={action.icon} />
                </svg>
                <span className="text-sm font-medium text-white">{action.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Alert Banner - VULN: fraud alerts exposed to client */}
        {accountData.fraudAlerts && accountData.fraudAlerts.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-6">
            <div className="flex items-start space-x-3">
              <svg className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <p className="text-sm font-medium text-amber-800">Security Notices</p>
                {/* VULN (display): Internal fraud alerts shown to user */}
                {accountData.fraudAlerts.map((alert, i) => (
                  <p key={i} className="text-sm text-amber-700 mt-1">{alert}</p>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2">
            {/* Tabs */}
            <div className="flex space-x-1 bg-white rounded-xl p-1 shadow-sm mb-6">
              {(['overview', 'transactions', 'details', 'cards'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium capitalize transition-colors ${
                    activeTab === tab
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Spending Overview */}
                <div className="bg-white rounded-2xl shadow-sm p-6">
                  <h2 className="text-lg font-semibold text-gray-900 mb-4">This Month's Activity</h2>
                  <div className="grid grid-cols-3 gap-4">
                    {[
                      { label: 'Total Spent', value: '$2,847.32', color: 'text-red-500' },
                      { label: 'Total Received', value: '$3,500.00', color: 'text-green-500' },
                      { label: 'Net Change', value: '+$652.68', color: 'text-blue-500' },
                    ].map(stat => (
                      <div key={stat.label} className="text-center p-4 bg-gray-50 rounded-xl">
                        <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
                        <p className="text-xs text-gray-500 mt-1">{stat.label}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recent Transactions Preview */}
                <div className="bg-white rounded-2xl shadow-sm p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-gray-900">Recent Transactions</h2>
                    <button
                      onClick={() => setActiveTab('transactions')}
                      className="text-sm text-blue-600 hover:text-blue-700"
                    >
                      View all
                    </button>
                  </div>
                  <div className="space-y-3">
                    {accountData.transactions.slice(0, 3).map(txn => (
                      <div key={txn.id} className="flex items-center justify-between py-3 border-b border-gray-50 last:border-0">
                        <div className="flex items-center space-x-3">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                            txn.type === 'credit' ? 'bg-green-100' : 'bg-red-100'
                          }`}>
                            <svg className={`w-5 h-5 ${txn.type === 'credit' ? 'text-green-600' : 'text-red-600'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={txn.type === 'credit' ? 'M7 16V4m0 0L3 8m4-4l4 4' : 'M17 8l4 4m0 0l-4 4m4-4H3'} />
                            </svg>
                          </div>
                          <div>
                            {/* VULN (XSS): Transaction description rendered as HTML */}
                            <p
                              className="font-medium text-gray-900 text-sm"
                              dangerouslySetInnerHTML={{ __html: txn.description }}
                            />
                            <p className="text-xs text-gray-500">{txn.date} • {txn.category}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className={`font-semibold ${txn.type === 'credit' ? 'text-green-600' : 'text-red-600'}`}>
                            {txn.type === 'credit' ? '+' : '-'}${txn.amount.toFixed(2)}
                          </p>
                          <p className="text-xs text-gray-400">Bal: ${txn.balance.toFixed(2)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'transactions' && (
              <div className="bg-white rounded-2xl shadow-sm overflow-hidden">
                <div className="p-6 border-b border-gray-100">
                  <h2 className="text-lg font-semibold text-gray-900">Transaction History</h2>
                </div>
                <div className="divide-y divide-gray-50">
                  {accountData.transactions.map(txn => (
                    <div key={txn.id} className="p-4 hover:bg-gray-50 transition-colors">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
                            txn.type === 'credit' ? 'bg-green-100' : 'bg-gray-100'
                          }`}>
                            <svg className={`w-5 h-5 ${txn.type === 'credit' ? 'text-green-600' : 'text-gray-500'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={txn.type === 'credit' ? 'M12 4v16m8-8H4' : 'M20 12H4'} />
                            </svg>
                          </div>
                          <div>
                            <p
                              className="font-medium text-gray-900 text-sm"
                              dangerouslySetInnerHTML={{ __html: txn.description }}
                            />
                            <p className="text-xs text-gray-500">{txn.date} • {txn.category}</p>
                            {/* VULN (display): Internal notes visible in transaction list */}
                            {txn.internalNotes && (
                              <p className="text-xs text-amber-600 mt-1">Internal: {txn.internalNotes}</p>
                            )}
                          </div>
                        </div>
                        <div className="text-right">
                          <p className={`font-semibold ${txn.type === 'credit' ? 'text-green-600' : 'text-gray-900'}`}>
                            {txn.type === 'credit' ? '+' : '-'}${txn.amount.toFixed(2)}
                          </p>
                          <p className="text-xs text-gray-400">Merchant: {txn.merchantId}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'details' && (
              <div className="bg-white rounded-2xl shadow-sm p-6 space-y-6">
                <h2 className="text-lg font-semibold text-gray-900">Account Details</h2>

                <div className="grid grid-cols-2 gap-4">
                  {/* VULN (display): All these fields should be masked or not returned to client */}
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Account Number</p>
                    {/* VULN (display): Full account number - should show only last 4 */}
                    <p className="font-mono font-medium">{accountData.accountNumber}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Routing Number</p>
                    <p className="font-mono font-medium">{accountData.routingNumber}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Social Security Number</p>
                    {/* VULN (display): SSN should NEVER be shown */}
                    <p className="font-mono font-medium text-red-600">{userProfile?.ssn}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Date of Birth</p>
                    {/* VULN (display): DOB exposed */}
                    <p className="font-medium">{accountData.dateOfBirth}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Credit Score ({accountData.creditScoreModel})</p>
                    {/* VULN (display): Credit score visible */}
                    <p className="text-2xl font-bold text-blue-600">{accountData.creditScore}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">KYC Status</p>
                    <p className="font-medium text-green-600">{accountData.kycStatus}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">OFAC Screening</p>
                    {/* VULN (display): OFAC status exposed */}
                    <p className="font-medium">{accountData.ofacStatus}</p>
                  </div>
                  <div className="p-4 bg-gray-50 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Annual Income</p>
                    {/* VULN (display): Income data on client */}
                    <p className="font-medium">${userProfile?.annualIncome?.toLocaleString()}</p>
                  </div>
                </div>

                {/* VULN (display): Internal notes visible */}
                <div className="p-4 bg-amber-50 rounded-xl border border-amber-200">
                  <p className="text-xs text-amber-600 mb-2 font-medium">Internal Account Notes</p>
                  <p className="text-sm text-gray-700">{accountData.internalNotes}</p>
                </div>

                <div className="p-4 bg-gray-50 rounded-xl">
                  <p className="text-xs text-gray-500 mb-2 font-medium">Customer Tier</p>
                  {/* VULN (display): Internal customer tier */}
                  <p className="text-lg font-bold text-purple-600">{userProfile?.internalCustomerTier}</p>
                </div>
              </div>
            )}

            {activeTab === 'cards' && (
              <div className="bg-white rounded-2xl shadow-sm p-6">
                <h2 className="text-lg font-semibold text-gray-900 mb-4">Linked Cards</h2>
                {accountData.linkedCards.map((card, i) => (
                  <div key={i} className="bg-gradient-to-r from-gray-800 to-gray-900 rounded-2xl p-6 text-white">
                    <div className="flex justify-between items-start mb-8">
                      <p className="text-gray-400 text-sm">{card.type}</p>
                      <div className="flex space-x-1">
                        <div className="w-8 h-8 bg-red-500 rounded-full opacity-80" />
                        <div className="w-8 h-8 bg-yellow-500 rounded-full opacity-80 -ml-4" />
                      </div>
                    </div>
                    {/* VULN (display): Full card number shown - should be masked */}
                    <p className="font-mono text-xl tracking-widest mb-4">
                      {card.number.replace(/(\d{4})/g, '$1 ').trim()}
                    </p>
                    <div className="flex justify-between items-end">
                      <div>
                        <p className="text-gray-400 text-xs mb-1">EXPIRES</p>
                        <p className="font-mono">{card.expiry}</p>
                      </div>
                      <div>
                        <p className="text-gray-400 text-xs mb-1">CVV</p>
                        {/* VULN (display): CVV should NEVER be displayed */}
                        <p className="font-mono">{card.cvv}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* User Profile Widget */}
            <div className="bg-white rounded-2xl shadow-sm p-6">
              <h3 className="text-base font-semibold text-gray-900 mb-4">Account Holder</h3>
              <div className="space-y-3 text-sm">
                <div>
                  <p className="text-gray-400 text-xs">Email</p>
                  <p className="font-medium">{userProfile?.email}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs">Phone</p>
                  <p className="font-medium">{userProfile?.phone}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs">Address</p>
                  <p className="font-medium">{userProfile?.address}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs">Account Manager</p>
                  <p className="font-medium text-blue-600">{userProfile?.accountManager}</p>
                </div>
                {/* VULN (display): SSN in sidebar */}
                <div>
                  <p className="text-gray-400 text-xs">SSN (last 4)</p>
                  {/* Actually shows full SSN despite label saying "last 4" */}
                  <p className="font-medium font-mono">{userProfile?.ssn}</p>
                </div>
              </div>
            </div>

            {/* Account Security Status */}
            <div className="bg-white rounded-2xl shadow-sm p-6">
              <h3 className="text-base font-semibold text-gray-900 mb-4">Security Status</h3>
              <div className="space-y-2">
                {[
                  { label: 'Risk Rating', value: accountData.internalRiskRating, color: 'text-green-600' },
                  { label: 'OFAC Status', value: accountData.ofacStatus, color: 'text-green-600' },
                  { label: 'KYC Status', value: accountData.kycStatus, color: 'text-green-600' },
                  { label: 'Fraud Alerts', value: String(accountData.fraudAlerts.length), color: accountData.fraudAlerts.length > 0 ? 'text-amber-600' : 'text-green-600' },
                ].map(item => (
                  <div key={item.label} className="flex justify-between items-center py-2 border-b border-gray-50 last:border-0">
                    <span className="text-sm text-gray-500">{item.label}</span>
                    <span className={`text-sm font-medium ${item.color}`}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Debug Info - VULN: debug panel exposed in production */}
            <div className="bg-gray-800 rounded-2xl p-4 text-xs font-mono text-green-400">
              <p className="text-gray-400 mb-2">// DEBUG INFO (remove in prod)</p>
              <p>userId: {userProfile?.id}</p>
              <p>accountId: {accountData.id}</p>
              {/* VULN (display): Auth token shown in debug panel */}
              <p>token: {typeof window !== 'undefined' ? localStorage.getItem('authToken')?.substring(0, 20) + '...' : 'N/A'}</p>
              <p>ownerId: {accountData.ownerId}</p>
              <p>ssn: {accountData.ssn}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
