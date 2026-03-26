import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { TrendChart } from "../../components/TrendChart";
import { ScanList } from "../../components/ScanList";
import type { Scan } from "../../lib/types";

async function getRecentScans(githubId: number, username: string): Promise<Scan[]> {
  const rows = await sql`
    SELECT
      s.id,
      r.owner  AS "repoOwner",
      r.name   AS "repoName",
      s.pr_number    AS "prNumber",
      s.commit_sha   AS "commitSha",
      s.pr_url       AS "prUrl",
      s.verdict,
      s.severity,
      s.cwe_id       AS "cweId",
      s.confidence,
      s.title,
      s.provider,
      s.scan_ms      AS "scanMs",
      s.created_at   AS "createdAt"
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE
      r.id IN (
        SELECT r2.id FROM repos r2
        JOIN users u ON r2.user_id = u.id
        WHERE u.github_id = ${githubId}
      )
      OR (r.installation_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM installations i
        WHERE i.installation_id = r.installation_id
          AND i.account_login = ${username}
          AND i.deleted_at IS NULL
      ))
    ORDER BY s.created_at DESC
    LIMIT 100
  `;
  return rows as unknown as Scan[];
}

async function getScanStats(githubId: number, username: string) {
  const rows = await sql`
    SELECT
      COUNT(*)                                           AS total,
      COUNT(*) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')  AS true_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'FALSE_POSITIVE') AS false_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')   AS needs_review
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE (
      r.id IN (
        SELECT r2.id FROM repos r2
        JOIN users u ON r2.user_id = u.id
        WHERE u.github_id = ${githubId}
      )
      OR (r.installation_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM installations i
        WHERE i.installation_id = r.installation_id
          AND i.account_login = ${username}
          AND i.deleted_at IS NULL
      ))
    )
    AND s.created_at > NOW() - INTERVAL '30 days'
  `;
  return rows[0] as {
    total: string;
    true_positives: string;
    false_positives: string;
    needs_review: string;
  };
}

async function hasConnectedRepos(githubId: number, username: string): Promise<boolean> {
  const owned = await sql`
    SELECT 1 FROM repos r
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
    LIMIT 1
  `;
  if (owned.length > 0) return true;

  const appInstalled = await sql`
    SELECT 1 FROM installations
    WHERE account_login = ${username} AND deleted_at IS NULL
    LIMIT 1
  `;
  return appInstalled.length > 0;
}

export default async function DashboardPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";

  const [scans, stats, connected] = await Promise.all([
    getRecentScans(githubId, username),
    getScanStats(githubId, username),
    hasConnectedRepos(githubId, username),
  ]);

  // New users with no repos → onboarding (skip if they already completed it)
  const onboarded = cookies().get("aegisdiff_onboarded");
  if (!connected && scans.length === 0 && !onboarded) {
    redirect("/onboarding");
  }

  const statCards = [
    {
      label: "Total Scans",
      value: stats?.total ?? "0",
      sub: "last 30 days",
      color: "text-gray-900",
      bg: "bg-white",
    },
    {
      label: "Issues Found",
      value: stats?.true_positives ?? "0",
      sub: "true positives",
      color: "text-red-600",
      bg: "bg-red-50",
    },
    {
      label: "False Positives",
      value: stats?.false_positives ?? "0",
      sub: "noise filtered",
      color: "text-green-600",
      bg: "bg-green-50",
    },
    {
      label: "Needs Review",
      value: stats?.needs_review ?? "0",
      sub: "human check needed",
      color: "text-yellow-600",
      bg: "bg-yellow-50",
    },
  ];

  const hasScans = scans.length > 0;

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500">
            {username || session.user?.name} · Last 30 days
          </p>
        </div>
        {hasScans && (
          <div className="flex items-center gap-3">
            <a
              href="/api/scans/export"
              className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50 transition-colors"
              download
            >
              ↓ Export CSV
            </a>
            <a
              href="/repos"
              className="rounded-lg bg-gray-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-gray-700 transition-colors"
            >
              Manage repos →
            </a>
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {statCards.map((s) => (
          <div
            key={s.label}
            className={`rounded-xl border border-gray-200 ${s.bg} p-4 shadow-sm`}
          >
            <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
            <div className="mt-1 text-xs font-semibold text-gray-700">{s.label}</div>
            <div className="text-[11px] text-gray-400 mt-0.5">{s.sub}</div>
          </div>
        ))}
      </div>

      {/* Trend chart */}
      {hasScans && (
        <div className="mb-6">
          <TrendChart githubId={githubId} username={username} />
        </div>
      )}

      {/* Waiting for first scan — has repos but no scans yet */}
      {connected && !hasScans && (
        <div className="mb-6 rounded-xl border border-blue-200 bg-blue-50 p-6">
          <div className="flex items-start gap-4">
            <div className="text-3xl">⏳</div>
            <div className="flex-1">
              <h2 className="text-base font-semibold text-blue-900 mb-1">
                Waiting for your first scan
              </h2>
              <p className="text-sm text-blue-700 mb-4">
                Your repo is connected. Open a pull request to trigger the first
                security analysis — results appear here within ~90 seconds.
              </p>
              <div className="flex gap-2 flex-wrap">
                {[
                  { icon: "✓", text: "Signed in" },
                  { icon: "✓", text: "Repo connected" },
                  { icon: "→", text: "Open a PR", highlight: true },
                ].map((step) => (
                  <div
                    key={step.text}
                    className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
                      step.highlight
                        ? "bg-blue-600 text-white"
                        : "bg-blue-100 text-blue-700"
                    }`}
                  >
                    <span>{step.icon}</span>
                    {step.text}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan list */}
      <div>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-800">Recent Scans</h2>
        </div>
        <ScanList scans={scans} />
      </div>
    </div>
  );
}
