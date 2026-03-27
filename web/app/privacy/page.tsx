import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy — AegisDiff",
};

const EFFECTIVE_DATE = "March 27, 2026";

export default function PrivacyPage() {
  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8 text-gray-800 dark:text-gray-200">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-50">Privacy Policy</h1>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Effective date: {EFFECTIVE_DATE}</p>
      </div>

      <div className="rounded-xl border border-brand-blue/30 bg-brand-blue/5 p-4 text-sm text-gray-700 dark:text-gray-300">
        <strong className="text-brand-blue">TL;DR —</strong> Your source code never leaves
        GitHub. We store only scan metadata. You can delete everything at any time.
      </div>

      <Section title="1. What We Collect">
        <p>When you use AegisDiff we collect:</p>
        <table className="w-full text-sm border-collapse mt-2">
          <thead>
            <tr className="bg-gray-50 dark:bg-gray-800 text-left">
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Data</th>
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Why</th>
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Retained</th>
            </tr>
          </thead>
          <tbody>
            {[
              ["GitHub username, email, avatar", "Authentication & display", "Until account deleted"],
              ["Scan metadata (verdict, severity, CWE ID, confidence, commit SHA)", "Dashboard & analytics", "Per your retention setting (default 90 days)"],
              ["Webhook URLs (Slack, Discord, Teams)", "Alert delivery", "Until you remove them"],
              ["Audit log entries (action, timestamp, repo)", "Security & compliance", "90 days"],
              ["API keys (SHA-256 hash only — never the raw key)", "REST API access", "Until revoked"],
            ].map(([data, why, retained]) => (
              <tr key={data} className="even:bg-gray-50 dark:even:bg-gray-800/50">
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2">{data}</td>
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2">{why}</td>
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2">{retained}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="2. What We Never Collect">
        <ul className="list-disc pl-5 space-y-1">
          <li><strong>Source code</strong> — the analysis engine runs inside your GitHub Actions runner. Code never reaches our servers.</li>
          <li><strong>Diff content</strong> — raw diffs are processed in your runner and discarded.</li>
          <li><strong>Evidence quotes</strong> — the vulnerable code snippet shown in PR comments is posted by GitHub Actions directly to GitHub, not stored by us.</li>
          <li><strong>LLM API keys</strong> — if you supply your own keys, they are used only inside your runner environment.</li>
        </ul>
      </Section>

      <Section title="3. How We Use Your Data">
        <ul className="list-disc pl-5 space-y-1">
          <li>To display your scan history and analytics in the dashboard.</li>
          <li>To send alert notifications via the webhooks you configure.</li>
          <li>To enforce rate limits and prevent abuse.</li>
          <li>To operate the platform (error monitoring via Sentry — metadata only, no code).</li>
        </ul>
      </Section>

      <Section title="4. Third-Party Services">
        <table className="w-full text-sm border-collapse mt-2">
          <thead>
            <tr className="bg-gray-50 dark:bg-gray-800 text-left">
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Service</th>
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Purpose</th>
              <th className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">Data shared</th>
            </tr>
          </thead>
          <tbody>
            {[
              ["GitHub OAuth", "Authentication", "GitHub ID, username, email"],
              ["Neon (PostgreSQL)", "Database hosting", "All metadata listed above"],
              ["Vercel", "Web hosting & functions", "Request logs (standard)"],
              ["Sentry", "Error monitoring", "Error messages, stack traces (no code)"],
              ["Gemini / Groq", "LLM analysis (platform key path)", "Only if using platform keys — code runs in your runner, we call the API on your behalf"],
            ].map(([svc, purpose, data]) => (
              <tr key={svc} className="even:bg-gray-50 dark:even:bg-gray-800/50">
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2 font-medium">{svc}</td>
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2">{purpose}</td>
                <td className="border border-gray-200 dark:border-gray-700 px-3 py-2">{data}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="5. Data Retention">
        <p>
          Scan records are automatically deleted after your configured retention period
          (30–90 days, configurable in Settings). Audit logs are kept for 90 days.
          Account data is retained until you delete your account.
        </p>
      </Section>

      <Section title="6. Your Rights (GDPR & CCPA)">
        <p>You have the right to:</p>
        <ul className="list-disc pl-5 space-y-1 mt-2">
          <li><strong>Access</strong> — export your scan data at any time via Settings → SARIF Export or the REST API.</li>
          <li><strong>Deletion</strong> — delete your account and all associated data from Settings → Danger Zone. This is immediate and irreversible.</li>
          <li><strong>Correction</strong> — update your preferences in Settings at any time.</li>
          <li><strong>Portability</strong> — download your data in CSV or SARIF format.</li>
        </ul>
        <p className="mt-2">
          For requests that cannot be fulfilled through the UI, contact us via{" "}
          <a
            href="https://github.com/KidCarmi/AegisDiff/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-blue hover:underline"
          >
            GitHub Issues
          </a>.
        </p>
      </Section>

      <Section title="7. Cookies">
        <p>
          We use a single session cookie (NextAuth.js) required for authentication.
          No tracking cookies, no advertising cookies, no third-party analytics cookies.
        </p>
      </Section>

      <Section title="8. Security">
        <p>
          All traffic is encrypted in transit (TLS 1.2+). API keys are stored as
          SHA-256 hashes — we cannot recover the raw key. Webhook URLs are stored
          encrypted at rest via Neon's database encryption.
        </p>
      </Section>

      <Section title="9. Changes">
        <p>
          We will notify you of material changes by posting a notice in the dashboard.
          The effective date at the top of this page will be updated.
        </p>
      </Section>

      <Section title="10. Contact">
        <p>
          Privacy questions or deletion requests:{" "}
          <a
            href="https://github.com/KidCarmi/AegisDiff/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-blue hover:underline"
          >
            GitHub Issues
          </a>
          .
        </p>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-50">{title}</h2>
      <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed space-y-2">
        {children}
      </div>
    </section>
  );
}
