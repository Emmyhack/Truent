/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          // Content-Security-Policy. Next.js hydration uses inline scripts
          // (no nonce middleware here), so script-src allows 'unsafe-inline';
          // everything else is locked to self plus Stripe and Google Fonts.
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' https://js.stripe.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: https:",
              "connect-src 'self' https://api.stripe.com",
              "frame-src https://js.stripe.com https://checkout.stripe.com",
              "frame-ancestors 'none'",
              "object-src 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
        ],
      },
    ]
  },
  // The docs are one hash-routed page now, so the former sub-routes redirect
  // rather than 404 for anyone holding an old link.
  async redirects() {
    return [
      { source: '/docs/getting-started', destination: '/docs#getting-started', permanent: true },
      { source: '/docs/cli', destination: '/docs#cli', permanent: true },
      { source: '/docs/ai', destination: '/docs#ai', permanent: true },
      { source: '/docs/api', destination: '/docs#api', permanent: true },
      { source: '/docs/ci-cd', destination: '/docs#ci-cd', permanent: true },
      { source: '/docs/reports', destination: '/docs#reports', permanent: true },
      { source: '/library', destination: '/docs#cli', permanent: true },
    ]
  },

  reactStrictMode: true,
}

module.exports = nextConfig
