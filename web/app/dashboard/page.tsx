import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { ScanCard } from "../../components/ScanCard";
import type { Scan } from "../../lib/types";

async function getRecentScans(githubId: number): Promise<Scan[]> {
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
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
    ORDER BY s.created_at DESC
    LIMIT 50
  `;
  return rows as unknown as Scan[];
}

async function getScanStats(githubId: number) {
  const rows = await sql`
    SELECT
      COUNT(*)                                           AS total,
      COUNT(*) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')  AS true_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'FALSE_POSITIVE') AS false_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')   AS needs_review
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
      AND s.created_at > NOW() - INTERVAL '30 days'
  `;
  return rows[0] as { total: string; true_positives: string; false_positives: string; needs_review: string };
}

export default async function DashboardPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const [scans, stats] = await Promise.all([
    getRecentScans(githubId),
    getScanStats(githubId),
  ]);

  const statCards = [
    { label: "Total Scans (30d)", value: stats?.total ?? "0", color: "text-gray-900" },
    { label: "True Positives", value: stats?.true_positives ?? "0", color: "text-red-600" },
    { label: "False Positives", value: stats?.false_positives ?? "0", color: "text-green-600" },
    { label: "Needs Review", value: stats?.needs_review ?? "0", color: "text-yellow-600" },
  ];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">
          Last 30 days · {session.user?.name}
        </p>
      </div>

      {/* Stats */}
      <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {statCards.map((s) => (
          <div key={s.label} className="rounded-lg border border-gray-200 bg-white p-4 text-center shadow-sm">
            <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
            <div className="mt-1 text-xs text-gray-500">{s.label}</div>
          </div>
        ))}
      </div>

      {/* GitHub App install banner — shown when user has no repos yet */}
      {scans.length === 0 && (
        <div className="mb-8 rounded-xl border border-blue-200 bg-blue-50 p-6">
          <h2 className="text-base font-semibold text-blue-900">
            Get started in 30 seconds
          </h2>
          <p className="mt-1 text-sm text-blue-700">
            Install the AegisDiff GitHub App on your repos — no YAML, no secrets, zero config.
            Every pull request is scanned automatically using our API keys.
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <a
              href={`https://github.com/apps/${process.env.NEXT_PUBLIC_GITHUB_APP_SLUG ?? "aegisdiff"}/installations/new`}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
              target="_blank"
              rel="noopener noreferrer"
            >
              Install on GitHub
            </a>
            <a
              href="/repos"
              className="inline-flex items-center gap-2 rounded-lg border border-blue-300 bg-white px-4 py-2 text-sm font-medium text-blue-700 hover:bg-blue-50"
            >
              Manual setup (bring your own keys)
            </a>
          </div>
        </div>
      )}

      {/* Recent scans */}
      <div>
        <h2 className="mb-4 text-lg font-semibold text-gray-800">Recent Scans</h2>
        {scans.length === 0 ? (
          <div className="rounded-lg border border-dashed border-gray-300 p-12 text-center">
            <p className="text-gray-500">No scans yet.</p>
            <p className="mt-2 text-sm text-gray-400">
              Install the GitHub App above or{" "}
              <a href="/repos" className="text-blue-600 hover:underline">connect a repository manually</a>
              {" "}to start analyzing pull requests.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <a key={scan.id} href={`/scans/${scan.id}`}>
                <ScanCard scan={scan} />
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
