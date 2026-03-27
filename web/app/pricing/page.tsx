import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Pricing — AegisDiff",
  description: "AegisDiff is free. No credit card. No infrastructure.",
};

const FREE_FEATURES = [
  "100 scans / repo / day",
  "Unlimited repos",
  "Inline PR review comments",
  "Slack, Discord & MS Teams alerts",
  "Per-hunk analysis (large PRs)",
  "aegisdiff-ignore inline suppression",
  "Feedback loop — correct false positives",
  "@aegisdiff rescan on demand",
  "SLA breach tracking",
  "Weekly digest emails",
  "CSV & SARIF export",
  "Public REST API",
  "Zero code egress — source never leaves GitHub",
];

const PRO_FEATURES = [
  "Everything in Free",
  "Unlimited scans per day",
  "Priority LLM routing (faster results)",
  "Custom SLA thresholds",
  "SSO / SAML (GitHub Org enforcement)",
  "Dedicated support channel",
  "Custom data retention (up to 1 year)",
  "Audit log export",
];

export default function PricingPage() {
  return (
    <div className="max-w-4xl mx-auto py-12 space-y-12">
      {/* Header */}
      <div className="text-center space-y-3">
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-50">
          Simple, honest pricing
        </h1>
        <p className="text-lg text-gray-500 dark:text-gray-400">
          Free for individuals and small teams. Always.
        </p>
      </div>

      {/* Plans */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Free */}
        <div className="rounded-2xl border-2 border-brand-blue bg-white dark:bg-gray-900 p-8 shadow-sm relative">
          <div className="absolute -top-3 left-6">
            <span className="rounded-full bg-brand-blue px-3 py-0.5 text-xs font-semibold text-white">
              Current plan
            </span>
          </div>
          <div className="mb-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-gray-50">Free</h2>
            <div className="mt-2 flex items-end gap-1">
              <span className="text-5xl font-bold text-gray-900 dark:text-gray-50">$0</span>
              <span className="text-gray-500 dark:text-gray-400 mb-1">/ month</span>
            </div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              No credit card. No catch. No infrastructure to manage.
            </p>
          </div>
          <ul className="space-y-2.5 mb-8">
            {FREE_FEATURES.map((f) => (
              <li key={f} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                <span className="text-brand-blue mt-0.5 shrink-0">✓</span>
                {f}
              </li>
            ))}
          </ul>
          <Link
            href="/dashboard"
            className="block w-full rounded-xl bg-brand-blue px-4 py-3 text-center text-sm font-semibold text-white hover:opacity-90 transition-opacity"
          >
            Go to Dashboard →
          </Link>
        </div>

        {/* Pro */}
        <div className="rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-8 shadow-sm opacity-80">
          <div className="mb-6">
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-gray-900 dark:text-gray-50">Pro</h2>
              <span className="rounded-full bg-gray-100 dark:bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-500 dark:text-gray-400">
                Coming soon
              </span>
            </div>
            <div className="mt-2 flex items-end gap-1">
              <span className="text-5xl font-bold text-gray-400 dark:text-gray-500">$?</span>
              <span className="text-gray-400 dark:text-gray-500 mb-1">/ month</span>
            </div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              For teams that need higher throughput and enterprise features.
            </p>
          </div>
          <ul className="space-y-2.5 mb-8">
            {PRO_FEATURES.map((f) => (
              <li key={f} className="flex items-start gap-2 text-sm text-gray-500 dark:text-gray-400">
                <span className="text-gray-400 dark:text-gray-500 mt-0.5 shrink-0">✓</span>
                {f}
              </li>
            ))}
          </ul>
          <a
            href="https://github.com/KidCarmi/AegisDiff/issues/new?title=Pro+plan+interest"
            target="_blank"
            rel="noopener noreferrer"
            className="block w-full rounded-xl border border-gray-300 dark:border-gray-600 px-4 py-3 text-center text-sm font-semibold text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
          >
            Register interest →
          </a>
        </div>
      </div>

      {/* FAQ */}
      <div className="space-y-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-50 text-center">FAQ</h2>
        <div className="grid md:grid-cols-2 gap-4">
          {[
            {
              q: "Will it always be free?",
              a: "The free tier will always exist. We may introduce a paid Pro tier for teams needing higher limits or enterprise features, but the current feature set stays free.",
            },
            {
              q: "What counts as a scan?",
              a: "One scan = one LLM analysis of a pull request (or a hunk of a large PR). The default limit is 100 per repo per day — enough for active teams.",
            },
            {
              q: "What happens if I hit the daily limit?",
              a: "Scans above the limit are skipped for that day. You can supply your own Gemini or Groq API keys in your GitHub repo secrets for unlimited scans.",
            },
            {
              q: "Does AegisDiff see my source code?",
              a: "No. The analysis engine runs inside your GitHub Actions runner. Code never reaches our servers. We store only scan metadata: verdict, severity, CWE ID, confidence.",
            },
            {
              q: "Can I self-host AegisDiff?",
              a: "Yes — AegisDiff is open source. You can run your own Vercel + Neon deployment. See the GitHub repo for instructions.",
            },
            {
              q: "How do I cancel?",
              a: "There's nothing to cancel. Just stop using it, or delete your account from Settings. No subscriptions, no billing, no retention dark patterns.",
            },
          ].map(({ q, a }) => (
            <div
              key={q}
              className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-5"
            >
              <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">{q}</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 leading-relaxed">{a}</p>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="text-center rounded-2xl border border-brand-blue/30 bg-brand-blue/5 dark:bg-brand-blue/10 p-10 space-y-4">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-50">
          Start in 60 seconds
        </h2>
        <p className="text-gray-500 dark:text-gray-400">
          Sign in with GitHub, connect a repo, open a PR. Done.
        </p>
        <Link
          href="/api/auth/signin"
          className="inline-block rounded-xl bg-brand-blue px-6 py-3 text-sm font-semibold text-white hover:opacity-90 transition-opacity"
        >
          Start Free with GitHub →
        </Link>
      </div>
    </div>
  );
}
