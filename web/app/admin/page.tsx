/**
 * /admin — Platform admin dashboard.
 * Requires platform:admin role (enforced by middleware + server-side check).
 */
import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { isPlatformAdminSession } from "../../lib/rbac";
import { sql } from "../../lib/db";
import { AdminTabs } from "./AdminTabs";

async function getStats() {
  const [scanStats, topRepos, userStats, rateLimited, recentAudit,
         providerFailures, failureReasons, failureTrend] =
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
        SELECT r.owner, r.name, COUNT(s.id) AS scans_today,
               COALESCE(r.custom_daily_limit, 100) AS daily_limit
        FROM repos r JOIN scans s ON s.repo_id = r.id
        WHERE s.created_at > NOW() - INTERVAL '24 hours'
        GROUP BY r.owner, r.name, r.custom_daily_limit
        HAVING COUNT(s.id) >= COALESCE(r.custom_daily_limit, 100) * 0.8
        ORDER BY scans_today DESC
      `,
      sql`
        SELECT action, repo_owner, repo_name, details, created_at
        FROM audit_log ORDER BY created_at DESC LIMIT 15
      `,
      // Failures by provider module (7d)
      sql`
        SELECT
          COALESCE(provider, 'unknown')                                     AS provider,
          COUNT(*)                                                           AS total,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')    AS today,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h
        FROM scans
        WHERE verdict = 'ERROR'
          AND created_at > NOW() - INTERVAL '7 days'
        GROUP BY provider
        ORDER BY total DESC
      `,
      // Top error messages (from title field, 7d)
      sql`
        SELECT
          title,
          COUNT(*)        AS count,
          MAX(created_at) AS last_seen
        FROM scans
        WHERE verdict = 'ERROR'
          AND created_at > NOW() - INTERVAL '7 days'
          AND title IS NOT NULL
        GROUP BY title
        ORDER BY count DESC
        LIMIT 12
      `,
      // Daily error trend (last 7 days)
      sql`
        SELECT
          DATE_TRUNC('day', created_at AT TIME ZONE 'UTC')::date AS day,
          COUNT(*)                                                 AS errors
        FROM scans
        WHERE verdict = 'ERROR'
          AND created_at > NOW() - INTERVAL '7 days'
        GROUP BY day
        ORDER BY day ASC
      `,
    ]);

  return {
    scans: scanStats[0] as any,
    topRepos: topRepos as any[],
    users: userStats[0] as any,
    rateLimited: rateLimited as any[],
    recentAudit: recentAudit as any[],
    providerFailures: providerFailures as any[],
    failureReasons: failureReasons as any[],
    failureTrend: failureTrend as any[],
  };
}

export default async function AdminPage() {
  const session = await getServerSession(authOptions);
  if (!session || !isPlatformAdminSession(session)) redirect("/dashboard");

  const { scans, topRepos, users, rateLimited, recentAudit,
          providerFailures, failureReasons, failureTrend } = await getStats();

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-50">
            Platform Admin
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Operator dashboard — visible only to platform admins
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-100 dark:bg-purple-900/40 px-3 py-1 text-xs font-semibold text-purple-700 dark:text-purple-300">
          platform:admin
        </span>
      </div>

      <AdminTabs
        scans={scans}
        topRepos={topRepos}
        users={users}
        rateLimited={rateLimited}
        recentAudit={recentAudit}
        providerFailures={providerFailures}
        failureReasons={failureReasons}
        failureTrend={failureTrend}
      />
    </div>
  );
}
