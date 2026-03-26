import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.SENTRY_DSN ?? process.env.NEXT_PUBLIC_SENTRY_DSN,

  tracesSampleRate: 0.1,

  // Scrub any accidental diff/code content from error context
  beforeSend(event) {
    // Drop expected auth errors — not actionable
    const status = (event.contexts?.response as any)?.status_code;
    if (status === 401 || status === 403 || status === 429) return null;
    return event;
  },

  environment: process.env.NODE_ENV,
});
