import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { SettingsForm } from "./SettingsForm";
import { ApiKeySection } from "./ApiKeySection";
import { DeleteAccountButton } from "../../components/DeleteAccountButton";

const SECTION = "rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6 shadow-sm";
const SECTION_TITLE = "text-lg font-semibold text-gray-800 dark:text-gray-100";

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
    SELECT r.owner, r.name
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
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-50">Settings</h1>

      {/* Account */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-4`}>Account</h2>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-3">
            <span className="text-gray-500 dark:text-gray-400 w-28">GitHub user</span>
            <span className="font-mono text-gray-900 dark:text-gray-100">{username || session.user?.name}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-gray-500 dark:text-gray-400 w-28">Email</span>
            <span className="text-gray-900 dark:text-gray-100">{session.user?.email ?? "—"}</span>
          </div>
        </div>
      </section>

      {/* Scan retention */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-1`}>Scan Retention</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Scans older than this are deleted automatically by the daily cleanup job.
        </p>
        <SettingsForm retentionDays={retentionDays} />
      </section>

      {/* README Badge */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-1`}>README Badge</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Drop this into your README to show live scan status.
        </p>
        {(repoRows as any[]).length === 0 ? (
          <p className="text-sm text-gray-400 dark:text-gray-500">No connected repos yet.</p>
        ) : (
          <div className="space-y-4">
            {(repoRows as any[]).map((r) => {
              const badgeUrl = `${baseUrl}/api/badge/${r.owner}/${r.name}`;
              const md = `[![AegisDiff](${badgeUrl})](${baseUrl}/dashboard)`;
              return (
                <div key={`${r.owner}/${r.name}`} className="space-y-2">
                  <p className="text-xs font-semibold text-gray-600 dark:text-gray-400 font-mono">
                    {r.owner}/{r.name}
                  </p>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={badgeUrl} alt="AegisDiff badge" height={20} />
                  <pre className="rounded bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-2 text-xs text-gray-700 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
                    {md}
                  </pre>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* REST API */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-1`}>REST API</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Query your scan data programmatically with a personal API key.
        </p>
        <ApiKeySection />
      </section>

      {/* SARIF export */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-1`}>SARIF Export</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
          Download scan results in SARIF 2.1.0 format — compatible with GitHub Code Scanning,
          VS Code SARIF Viewer, and most security tooling.
        </p>
        {(repoRows as any[]).length > 0 && (
          <div className="flex flex-wrap gap-2">
            {(repoRows as any[]).map((r) => (
              <a key={`${r.owner}/${r.name}`}
                href={`/api/scans/export?repo=${r.owner}/${r.name}&format=sarif`}
                className="rounded-md border border-gray-200 dark:border-gray-700 px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                download>
                {r.owner}/{r.name} ↓ SARIF
              </a>
            ))}
          </div>
        )}
      </section>

      {/* Privacy */}
      <section className={SECTION}>
        <h2 className={`${SECTION_TITLE} mb-2`}>Privacy</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          AegisDiff operates on a <strong>zero code egress</strong> model. Your source code
          never leaves GitHub&apos;s infrastructure. Only scan metadata (verdict, severity,
          confidence) is sent to this dashboard — never code, diffs, or evidence quotes.
        </p>
        <div className="mt-3 flex gap-3 text-xs text-gray-400 dark:text-gray-500">
          <a href="/privacy" className="hover:text-brand-blue hover:underline">Privacy Policy</a>
          <span>·</span>
          <a href="/terms" className="hover:text-brand-blue hover:underline">Terms of Service</a>
        </div>
      </section>

      {/* Danger Zone */}
      <section className="rounded-lg border border-red-200 dark:border-red-900 bg-white dark:bg-gray-900 p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-red-700 dark:text-red-400 mb-1">Danger Zone</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Permanently delete your account and all associated data. This cannot be undone.
        </p>
        <DeleteAccountButton />
      </section>
    </div>
  );
}
