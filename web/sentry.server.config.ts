import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.SENTRY_DSN ?? process.env.NEXT_PUBLIC_SENTRY_DSN,

  tracesSampleRate: 0.1,

  beforeSend(event, hint) {
    // Drop expected auth errors — not actionable
    const status = (event.contexts?.response as any)?.status_code;
    if (status === 401 || status === 403 || status === 429) return null;
    // Drop Next.js internal redirect/notFound — these are control-flow, not errors
    const err = hint?.originalException as any;
    if (err?.digest === "NEXT_REDIRECT" || err?.digest === "NEXT_NOT_FOUND") return null;
    return event;
  },

  environment: process.env.NODE_ENV,
});
