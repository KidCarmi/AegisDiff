/**
 * /admin — Platform admin dashboard.
 * Requires platform:admin role (enforced by middleware + server-side check).
 */
import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { isPlatformAdminSession } from "../../lib/rbac";
import { sql } from "../../lib/db";

async function getStats() {
  const [scanStats, topRepos, userStats, rateLimited, recentAudit] =
    await Promise.all([
      sql`
        SELECT
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')   AS today,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')  AS week,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS month,
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE verdict = 'TRUE_POSITIVE'
                             AND created_at > NOW() - INTERVAL '30 days') AS tp_month,
          COUNT(*) FILTER (WHERE verdict = 'ERROR'
                             AND created_at > NOW() - INTERVAL '7 days')  AS errors_week
        FROM scans
      `,
      sql`
        SELECT r.owner, r.name,
               COUNT(s.id) AS scans,
               COUNT(s.id) FILTER (WHERE s.verdict = 'TRUE_POSITIVE') AS tps
        FROM repos r
        JOIN scans s ON s.repo_id = r.id
        WHERE s.created_at > NOW() - INTERVAL '30 days'
        GROUP BY r.owner, r.name
        ORDER BY scans DESC
        LIMIT 8
      `,
      sql`
        SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS new_week
        FROM users
      `,
      sql`
        SELECT r.owner, r.name, COUNT(s.id) AS scans_today
        FROM repos r JOIN scans s ON s.repo_id = r.id
        WHERE s.created_at > NOW() - INTERVAL '24 hours'
        GROUP BY r.owner, r.name HAVING COUNT(s.id) >= 50
        ORDER BY scans_today DESC
      `,
      sql`
        SELECT action, repo_owner, repo_name, details, created_at
        FROM audit_log ORDER BY created_at DESC LIMIT 15
      `,
    ]);

  return {
    scans: scanStats[0] as any,
    topRepos: topRepos as any[],
    users: userStats[0] as any,
    rateLimited: rateLimited as any[],
    recentAudit: recentAudit as any[],
  };
}

export default async function AdminPage() {
  const session = await getServerSession(authOptions);
  if (!session || !isPlatformAdminSession(session)) redirect("/dashboard");

  const { scans, topRepos, users, rateLimited, recentAudit } = await getStats();

  const statCards = [
    { label: "Scans today",        value: scans.today,      sub: `${scans.week} this week` },
    { label: "Scans (30d)",        value: scans.month,      sub: `${scans.total} all-time` },
    { label: "True positives (30d)", value: scans.tp_month, sub: "confirmed findings" },
    { label: "Errors (7d)",        value: scans.errors_week, sub: "engine failures" },
    { label: "Total users",        value: users.total,      sub: `+${users.new_week} this week` },
    { label: "Rate-limited repos", value: rateLimited.length, sub: "hit 50/day cap" },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Platform Admin</h1>
          <p className="text-sm text-gray-500 mt-1">
            Operator dashboard — visible only to platform admins
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-100 px-3 py-1 text-xs font-semibold text-purple-700">
          platform:admin
        </span>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {statCards.map((c) => (
          <div key={c.label} className="rounded-xl border bg-white p-4 shadow-sm">
            <p className="text-2xl font-bold text-gray-900">{c.value ?? 0}</p>
            <p className="text-xs font-medium text-gray-700 mt-0.5">{c.label}</p>
            <p className="text-xs text-gray-400 mt-0.5">{c.sub}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top repos */}
        <div className="rounded-xl border bg-white shadow-sm">
          <div className="border-b px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-800">Top Repos (30 days)</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
                <th className="px-5 py-2 font-medium">Repo</th>
                <th className="px-5 py-2 font-medium text-right">Scans</th>
                <th className="px-5 py-2 font-medium text-right">TPs</th>
              </tr>
            </thead>
            <tbody>
              {topRepos.map((r: any) => (
                <tr key={`${r.owner}/${r.name}`} className="border-b last:border-0 hover:bg-gray-50">
                  <td className="px-5 py-2 font-mono text-xs text-gray-700">
                    {r.owner}/{r.name}
                  </td>
                  <td className="px-5 py-2 text-right text-gray-900">{r.scans}</td>
                  <td className="px-5 py-2 text-right text-red-600 font-medium">{r.tps}</td>
                </tr>
              ))}
              {topRepos.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-5 py-6 text-center text-sm text-gray-400">
                    No scans yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Rate-limited repos */}
        <div className="rounded-xl border bg-white shadow-sm">
          <div className="border-b px-5 py-3">
            <h2 className="text-sm font-semibold text-gray-800">
              Rate-Limited Today
              <span className="ml-2 rounded-full bg-orange-100 px-2 py-0.5 text-xs text-orange-700">
                {rateLimited.length} repos
              </span>
            </h2>
          </div>
          {rateLimited.length === 0 ? (
            <p className="px-5 py-6 text-sm text-gray-400 text-center">
              No repos have hit the 50/day limit
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-gray-50 text-left text-xs text-gray-500">
                  <th className="px-5 py-2 font-medium">Repo</th>
                  <th className="px-5 py-2 font-medium text-right">Scans today</th>
                </tr>
              </thead>
              <tbody>
                {rateLimited.map((r: any) => (
                  <tr key={`${r.owner}/${r.name}`} className="border-b last:border-0">
                    <td className="px-5 py-2 font-mono text-xs text-gray-700">
                      {r.owner}/{r.name}
                    </td>
                    <td className="px-5 py-2 text-right font-semibold text-orange-600">
                      {r.scans_today}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Recent audit log */}
      <div className="rounded-xl border bg-white shadow-sm">
        <div className="border-b px-5 py-3">
          <h2 className="text-sm font-semibold text-gray-800">Recent Audit Events</h2>
        </div>
        <div className="divide-y text-sm">
          {recentAudit.map((e: any, i: number) => (
            <div key={i} className="flex items-start gap-3 px-5 py-3">
              <span className="mt-0.5 shrink-0 rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-gray-600">
                {e.action}
              </span>
              <span className="text-gray-700">
                {e.repo_owner && e.repo_name
                  ? `${e.repo_owner}/${e.repo_name}`
                  : "—"}
              </span>
              <span className="ml-auto shrink-0 text-xs text-gray-400">
                {new Date(e.created_at).toLocaleString()}
              </span>
            </div>
          ))}
          {recentAudit.length === 0 && (
            <p className="px-5 py-6 text-center text-sm text-gray-400">No audit events yet</p>
          )}
        </div>
      </div>
    </div>
  );
}
