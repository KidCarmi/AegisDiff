import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,

  // Capture 10% of transactions for performance monitoring
  tracesSampleRate: 0.1,

  // Session replays only on errors (saves quota)
  replaysOnErrorSampleRate: 1.0,
  replaysSessionSampleRate: 0,

  integrations: [
    Sentry.replayIntegration({
      // Never capture diffs, code, or tokens in replay
      maskAllText: true,
      blockAllMedia: true,
    }),
  ],

  // Don't report expected non-errors:
  // - 401/403 navigation errors (unauthenticated users hitting protected routes)
  // - NEXT_REDIRECT (Next.js redirect() throws internally — not a real error)
  // - NEXT_NOT_FOUND (notFound() throws internally — not a real error)
  beforeSend(event, hint) {
    const status = event.extra?.status ?? (event.contexts?.response as any)?.status_code;
    if (status === 401 || status === 403) return null;
    const err = hint?.originalException as any;
    if (err?.digest === "NEXT_REDIRECT" || err?.digest === "NEXT_NOT_FOUND") return null;
    return event;
  },

  environment: process.env.NODE_ENV,
});
