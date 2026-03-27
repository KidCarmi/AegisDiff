/**
 * GET /api/scans/sla-breaches
 *
 * Returns TRUE_POSITIVE scans with severity CRITICAL or HIGH that are older
 * than 7 days and have not been marked FALSE_POSITIVE via feedback.
 *
 * These findings have breached the SLA and need immediate attention.
 *
 * Query params:
 *   ?sla_days=N  Override the SLA window (default: 7)
 *
 * Returns:
 *   {
 *     breaches: SLABreach[],
 *     total: number,
 *     sla_days: number,
 *   }
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

export interface SLABreach {
  id: string;
  repoOwner: string;
  repoName: string;
  prNumber: number | null;
  prUrl: string | null;
  severity: string;
  cweId: string | null;
  title: string | null;
  createdAt: string;
  daysOpen: number;
}

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";

  const slaDaysParam = req.nextUrl.searchParams.get("sla_days");
  const slaDays = slaDaysParam ? Math.max(1, Math.min(90, parseInt(slaDaysParam, 10) || 7)) : 7;

  const rows = await sql`
    SELECT
      s.id,
      r.owner   AS "repoOwner",
      r.name    AS "repoName",
      s.pr_number  AS "prNumber",
      s.pr_url     AS "prUrl",
      s.severity,
      s.cwe_id     AS "cweId",
      s.title,
      s.created_at AS "createdAt",
      EXTRACT(EPOCH FROM (NOW() - s.created_at)) / 86400 AS "daysOpen"
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE
      s.verdict   = 'TRUE_POSITIVE'
      AND s.severity IN ('CRITICAL', 'HIGH')
      AND s.created_at < NOW() - (${slaDays} || ' days')::INTERVAL
      AND NOT EXISTS (
        SELECT 1 FROM scan_feedback sf
        WHERE sf.scan_id = s.id
          AND sf.correct_verdict = 'FALSE_POSITIVE'
      )
      AND (
        r.id IN (
          SELECT r2.id FROM repos r2
          JOIN users u ON r2.user_id = u.id
          WHERE u.github_id = ${githubId}
        )
        OR (r.installation_id IS NOT NULL AND EXISTS (
          SELECT 1 FROM installations i
          WHERE i.installation_id = r.installation_id
            AND i.account_login   = ${username}
            AND i.deleted_at IS NULL
        ))
      )
    ORDER BY s.severity DESC, s.created_at ASC
    LIMIT 50
  `;

  const breaches = rows.map((row: any) => ({
    ...row,
    daysOpen: Math.floor(parseFloat(row.daysOpen)),
  })) as SLABreach[];

  return NextResponse.json({
    breaches,
    total: breaches.length,
    sla_days: slaDays,
  });
}
