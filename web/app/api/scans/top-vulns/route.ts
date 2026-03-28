/**
 * GET /api/scans/top-vulns
 *
 * Returns the top vulnerability classes (by CWE + severity) across all
 * repos the authenticated user can see, for the last 30 days.
 *
 * Used by the dashboard "Top Vulnerabilities" tab.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";

  const rows = await sql`
    SELECT
      REGEXP_REPLACE(COALESCE(s.cwe_id, 'Unknown'), '^CWE-0+([0-9]+)', 'CWE-\1') AS cwe_id,
      s.severity,
      MODE() WITHIN GROUP (ORDER BY s.title)  AS title,
      COUNT(*)                                 AS total,
      COUNT(*) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')  AS true_positives,
      COUNT(*) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')   AS needs_review,
      COUNT(*) FILTER (WHERE s.verdict = 'FALSE_POSITIVE') AS false_positives,
      MAX(s.created_at)                        AS last_seen
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
    AND s.verdict IN ('TRUE_POSITIVE', 'NEEDS_REVIEW')
    AND s.cwe_id IS NOT NULL
    AND s.cwe_id != 'N/A'
    GROUP BY REGEXP_REPLACE(COALESCE(s.cwe_id, 'Unknown'), '^CWE-0+([0-9]+)', 'CWE-\1'), s.severity
    ORDER BY true_positives DESC, total DESC
    LIMIT 15
  `;

  return NextResponse.json({ vulns: rows });
}
