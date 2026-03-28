/** @type {import('next').NextConfig} */
const { withSentryConfig } = require("@sentry/nextjs");

const securityHeaders = [
  { key: "X-DNS-Prefetch-Control", value: "on" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // next.js requires unsafe-eval in dev
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https://avatars.githubusercontent.com",
      // /monitoring tunnels Sentry through our own origin — no external CSP entry needed
      "connect-src 'self' https://api.github.com",
      "frame-ancestors 'none'",
    ].join("; "),
  },
];

const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ["@neondatabase/serverless"],
    instrumentationHook: true,
  },
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "avatars.githubusercontent.com" },
    ],
    formats: ["image/webp", "image/avif"],
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

module.exports = withSentryConfig(nextConfig, {
  // Sentry organisation + project — set SENTRY_ORG / SENTRY_PROJECT env vars
  // in your Vercel project to enable source-map uploads on deploy.
  silent: !process.env.CI,           // suppress noise locally, show in CI
  hideSourceMaps: true,              // don't ship source maps to the browser
  disableLogger: true,               // tree-shake Sentry debug logs from bundle
  tunnelRoute: "/monitoring",        // proxy errors through our origin (bypasses ad-blockers)
  widenClientFileUpload: true,       // upload more source files for better stack traces
  automaticVercelMonitors: false,    // we don't use Vercel Cron
});
