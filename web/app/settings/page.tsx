import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { SettingsForm } from "./SettingsForm";

export default async function SettingsPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";

  const userRows = await sql`
    SELECT scan_retention_days AS "scanRetentionDays" FROM users
    WHERE github_id = ${githubId} LIMIT 1
  `;
  const retentionDays = (userRows[0] as any)?.scanRetentionDays ?? 30;

  const repoRows = await sql`
    SELECT r.owner, r.name,
           (r.slack_webhook_url IS NOT NULL) AS "slackConfigured"
    FROM repos r
    WHERE (
      r.id IN (SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id WHERE u.github_id = ${githubId})
      OR (r.installation_id IS NOT NULL AND r.owner = ${username})
    )
    ORDER BY r.created_at DESC
  `;

  const baseUrl = process.env.NEXTAUTH_URL ?? "";

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Settings</h1>

      {/* Account */}
      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-4">Account</h2>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-3">
            <span className="text-gray-500 w-28">GitHub user</span>
            <span className="font-mono text-gray-900">{username || session.user?.name}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-gray-500 w-28">Email</span>
            <span className="text-gray-900">{session.user?.email ?? "—"}</span>
          </div>
        </div>
      </section>

      {/* Scan retention */}
      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-1">Scan Retention</h2>
        <p className="text-sm text-gray-500 mb-4">
          Scans older than this are deleted automatically by the daily cleanup job.
        </p>
        <SettingsForm retentionDays={retentionDays} />
      </section>

      {/* Slack notifications */}
      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-1">Slack Notifications</h2>
        <p className="text-sm text-gray-500 mb-4">
          Get a Slack alert on every <strong>TRUE_POSITIVE</strong> detection. Configure a{" "}
          <a
            href="https://api.slack.com/messaging/webhooks"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:underline"
          >
            Slack Incoming Webhook
          </a>{" "}
          per repo below.
        </p>
        {(repoRows as any[]).length === 0 ? (
          <p className="text-sm text-gray-400">No connected repos yet.</p>
        ) : (
          <div className="space-y-2">
            {(repoRows as any[]).map((r) => (
              <div
                key={`${r.owner}/${r.name}`}
                className="flex items-center justify-between rounded-md border border-gray-100 bg-gray-50 px-4 py-2"
              >
                <span className="font-mono text-sm text-gray-800">
                  {r.owner}/{r.name}
                </span>
                <a
                  href={`/repos/${r.owner}/${r.name}/slack`}
                  className="text-xs text-blue-600 hover:underline"
                >
                  {r.slackConfigured ? "✓ Edit webhook" : "Add webhook"}
                </a>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* README Badge */}
      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-1">README Badge</h2>
        <p className="text-sm text-gray-500 mb-4">
          Drop this into your README to show live scan status.
        </p>
        {(repoRows as any[]).length === 0 ? (
          <p className="text-sm text-gray-400">No connected repos yet.</p>
        ) : (
          <div className="space-y-4">
            {(repoRows as any[]).map((r) => {
              const badgeUrl = `${baseUrl}/api/badge/${r.owner}/${r.name}`;
              const md = `[![AegisDiff](${badgeUrl})](${baseUrl}/dashboard)`;
              return (
                <div key={`${r.owner}/${r.name}`} className="space-y-2">
                  <p className="text-xs font-semibold text-gray-600 font-mono">
                    {r.owner}/{r.name}
                  </p>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={badgeUrl} alt="AegisDiff badge" height={20} />
                  <pre className="rounded bg-gray-50 border border-gray-200 p-2 text-xs text-gray-700 overflow-x-auto whitespace-pre-wrap break-all">
                    {md}
                  </pre>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Privacy */}
      <section className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-800 mb-2">Privacy</h2>
        <p className="text-sm text-gray-500">
          AegisDiff operates on a <strong>zero code egress</strong> model. Your source code
          never leaves GitHub&apos;s infrastructure. Only scan metadata (verdict, severity,
          confidence) is sent to this dashboard — never code, diffs, or evidence quotes.
        </p>
      </section>
    </div>
  );
}
