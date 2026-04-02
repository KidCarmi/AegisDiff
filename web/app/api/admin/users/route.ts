/**
 * GET /api/admin/users
 *
 * List all platform users with their repo count and last scan time.
 * Requires platform:admin role (enforced by middleware).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { isPlatformAdminSession } from "../../../../lib/rbac";

export const dynamic = "force-dynamic";

export async function GET(_req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session || !isPlatformAdminSession(session)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const users = await sql`
    SELECT
      u.github_id,
      u.username,
      u.email,
      u.created_at,
      COUNT(DISTINCT r.id)                              AS repo_count,
      COUNT(s.id)                                       AS total_scans,
      MAX(s.created_at)                                 AS last_scan_at,
      MAX(COALESCE(r.custom_daily_limit, 100))          AS daily_limit,
      BOOL_OR(r.custom_daily_limit IS NOT NULL)         AS has_custom_limit
    FROM users u
    LEFT JOIN repos r ON (
      r.user_id = u.id
      OR (r.installation_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM installations i
        WHERE i.installation_id = r.installation_id
          AND i.account_login = u.username
          AND i.deleted_at IS NULL
      ))
    )
    LEFT JOIN scans  s ON s.repo_id = r.id
    GROUP BY u.github_id, u.username, u.email, u.created_at
    ORDER BY last_scan_at DESC NULLS LAST
    LIMIT 200
  `;

  return NextResponse.json({ users });
}
