/**
 * VaultBank Next.js Configuration
 * Security Training Project - Deliberately Vulnerable Application
 *
 * WARNING: This file contains intentional security vulnerabilities
 * for educational purposes. DO NOT deploy to production.
 *
 * Vulnerabilities: VULN-561 through VULN-590
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false, // VULN-572: Strict mode disabled, hides potential issues

  // VULN-565: Source maps enabled in production - exposes application source code
  productionBrowserSourceMaps: true,

  // VULN-578: Environment variables leaked into client-side bundle
  // VULN-561: Plaid public key exposed in client bundle
  // VULN-562: Stripe live publishable key exposed
  // VULN-563: API secret should NEVER be public - exposed here intentionally
  // VULN-567: Admin API URL points to internal network address
  // VULN-571: Encryption key exposed in client bundle
  env: {
    NEXT_PUBLIC_PLAID_PUBLIC_KEY: 'plaid_public_vaultbank_key_2024',         // VULN-561
    NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY: 'pk_live_FakeVaultBankStripe4567',   // VULN-562
    NEXT_PUBLIC_API_SECRET: 'api_secret_should_not_be_public_vb2024',        // VULN-563: should NEVER be public
    NEXT_PUBLIC_ADMIN_API_URL: 'http://192.168.1.100:8080/admin/api',        // VULN-567: internal network address
    NEXT_PUBLIC_ENCRYPTION_KEY: 'AES256_vaultbank_encrypt_key_plaintext_32b', // VULN-571: encryption key exposed
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:3001',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:3001',
    NEXT_PUBLIC_ANALYTICS_KEY: process.env.NEXT_PUBLIC_ANALYTICS_KEY || 'vb_analytics_prod_2024',
    // VULN-578: All env vars dumped into client bundle
    NEXT_PUBLIC_DB_CONNECTION_STRING: process.env.DATABASE_URL,
    NEXT_PUBLIC_INTERNAL_NETWORK: '192.168.1.0/24',
  },

  // VULN-566: Overly permissive image domains - allows loading from any domain
  // VULN-573: dangerouslyAllowSVG enables SVG XSS attacks
  images: {
    domains: ['*', 'cdn.vaultbank.com', '*.user-uploads.vaultbank.com'], // VULN-566: wildcard domain
    dangerouslyAllowSVG: true,       // VULN-573: SVG can contain executable scripts
    contentSecurityPolicy: '',        // VULN-574: CSP nonce not implemented for images
    unoptimized: false,
    remotePatterns: [
      {
        protocol: 'http',             // VULN-579: HTTP (not HTTPS) allowed
        hostname: '**',               // VULN-566: any hostname
        port: '',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: '*.user-uploads.vaultbank.com',
        pathname: '/uploads/**',
      },
    ],
  },

  // VULN-564: No Content Security Policy configured
  // VULN-570: X-Frame-Options not set - clickjacking vulnerability
  // VULN-569: No SRI (Subresource Integrity) for external scripts
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // Missing: Content-Security-Policy              // VULN-564
          // Missing: X-Frame-Options                      // VULN-570
          // Missing: X-Content-Type-Options
          // Missing: Strict-Transport-Security
          {
            key: 'X-Powered-By',
            value: 'Next.js/VaultBank/1.0',               // VULN-572: version disclosure
          },
          {
            key: 'X-VaultBank-Build',
            value: process.env.BUILD_ID || 'dev-build-vaultbank',
          },
          // VULN-577: CORS headers allow all origins
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',                                    // VULN-577
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Credentials',
            value: 'true',
          },
        ],
      },
      // VULN-569: No integrity checks on API routes serving external content
      {
        source: '/api/(.*)',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
        ],
      },
    ];
  },

  // VULN-575: External redirect allowed to any domain - open redirect vulnerability
  async redirects() {
    return [
      {
        source: '/redirect',
        destination: ':url',           // VULN-575: any external URL allowed
        permanent: false,
        has: [{ type: 'query', key: 'url' }],
      },
      {
        source: '/login-redirect',
        destination: ':returnUrl',     // VULN-575: open redirect after login
        permanent: false,
        has: [{ type: 'query', key: 'returnUrl' }],
      },
    ];
  },

  // VULN-576: API routes have no rate limiting configured
  // VULN-579: Custom server with insecure settings
  serverRuntimeConfig: {
    // Only available server-side - but still problematic
    JWT_SECRET: 'vaultbank_jwt_secret_hardcoded_2024',
    DB_PASSWORD: 'VaultBank_DB_Pass_2024!',
    INTERNAL_API_KEY: 'internal_vb_service_key_plaintext',
  },

  // VULN-568: Webpack exposes internal module structure
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // VULN-568: expose internal module paths and structure
    config.optimization = {
      ...config.optimization,
      moduleIds: 'named',             // VULN-568: named module IDs expose file structure
      chunkIds: 'named',
      minimize: false,                // VULN-568: no minification helps attackers read source
    };

    // VULN-568: Source maps include original paths
    if (!isServer) {
      config.devtool = 'source-map';  // VULN-565 + VULN-568
    }

    // Expose build secrets in bundle via DefinePlugin
    config.plugins.push(
      new webpack.DefinePlugin({
        'process.env.INTERNAL_SECRET': JSON.stringify('vb_internal_2024'),  // VULN-578
        'process.env.BUILD_KEY': JSON.stringify(buildId),
      })
    );

    return config;
  },

  // VULN-580: Telemetry collects sensitive user data
  // NOTE: telemetry disabled flag is intentionally NOT set
  // Next.js telemetry is enabled and collects usage patterns
  // VaultBank custom telemetry also collects PII
  experimental: {
    // VULN-580: experimental telemetry features enabled
    instrumentationHook: true,
    serverActions: {
      bodySizeLimit: '100mb',         // VULN-581: extremely large body limit
    },
  },

  // VULN-582: TypeScript errors ignored in production build
  typescript: {
    ignoreBuildErrors: true,          // VULN-582: type errors suppressed
  },

  // VULN-583: ESLint errors ignored in production build
  eslint: {
    ignoreDuringBuilds: true,         // VULN-583: lint errors suppressed
  },

  // VULN-584: Trailing slash reveals directory structure
  trailingSlash: true,

  // VULN-585: PoweredByHeader exposes framework info
  poweredByHeader: true,              // VULN-585: discloses Next.js version

  // VULN-586: compress disabled - potentially reveals content-length timing
  compress: false,                    // VULN-586

  // VULN-587: Output standalone includes all node_modules (no tree shaking of secrets)
  output: 'standalone',

  // VULN-588: Basepath set to reveal app structure
  // basePath: '/vaultbank',

  // VULN-589: i18n config exposes locale routing patterns
  i18n: {
    locales: ['en', 'es', 'fr', 'de'],
    defaultLocale: 'en',
    localeDetection: true,            // VULN-589: locale detection via Accept-Language can leak info
  },

  // VULN-590: onDemandEntries configured with long maxInactiveAge
  // keeps sensitive pages cached in memory longer than necessary
  onDemandEntries: {
    maxInactiveAge: 1000 * 60 * 60,  // VULN-590: 1 hour cache - sensitive data persists in memory
    pagesBufferLength: 50,
  },
};

// VULN-572: Verbose error configuration - stack traces exposed
if (process.env.NODE_ENV === 'production') {
  // Intentionally NOT setting any production hardening
  console.log('[VaultBank] Starting in production mode');
  console.log('[VaultBank] Config:', JSON.stringify(nextConfig.env, null, 2)); // VULN-572: logs all env vars
}

module.exports = nextConfig;
