/**
 * GET /api/admin/stats
 *
 * Platform-wide usage stats for the admin dashboard.
 * Requires platform:admin role (enforced by middleware).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { isPlatformAdminSession } from "../../../../lib/rbac";

export async function GET(_req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session || !isPlatformAdminSession(session)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const [scanStats, repoStats, userStats, rateLimited, recentAudit] =
    await Promise.all([
      // Scan counts: today / 7d / 30d / all-time
      sql`
        SELECT
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day')   AS today,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')  AS week,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS month,
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE verdict = 'TRUE_POSITIVE'
                             AND created_at > NOW() - INTERVAL '30 days') AS true_positives_month,
          COUNT(*) FILTER (WHERE verdict = 'ERROR'
                             AND created_at > NOW() - INTERVAL '7 days')  AS errors_week
        FROM scans
      `,

      // Top repos by scan count (last 30 days)
      sql`
        SELECT r.owner, r.name,
               COUNT(s.id) AS scans_30d,
               COUNT(s.id) FILTER (WHERE s.verdict = 'TRUE_POSITIVE') AS true_positives
        FROM repos r
        JOIN scans s ON s.repo_id = r.id
        WHERE s.created_at > NOW() - INTERVAL '30 days'
        GROUP BY r.owner, r.name
        ORDER BY scans_30d DESC
        LIMIT 10
      `,

      // User count + new users this week
      sql`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS new_this_week
        FROM users
      `,

      // Repos that hit rate limit today (≥50 scans in last 24h)
      sql`
        SELECT r.owner, r.name, COUNT(s.id) AS scans_today
        FROM repos r
        JOIN scans s ON s.repo_id = r.id
        WHERE s.created_at > NOW() - INTERVAL '24 hours'
        GROUP BY r.owner, r.name
        HAVING COUNT(s.id) >= 50
        ORDER BY scans_today DESC
      `,

      // Recent audit events
      sql`
        SELECT action, repo_owner, repo_name, details, created_at
        FROM audit_log
        ORDER BY created_at DESC
        LIMIT 20
      `,
    ]);

  return NextResponse.json({
    scans: scanStats[0],
    topRepos: repoStats,
    users: userStats[0],
    rateLimitedRepos: rateLimited,
    recentAudit,
  });
}
