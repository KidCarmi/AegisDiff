/**
 * GET /api/repos/[owner]/[name]/usage
 *
 * Returns scan usage stats for this repo — used by the Settings > Usage tab
 * to show the rate-limit meter (50 scans/day on the free platform tier).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../../lib/auth";
import { requireRepoRole } from "../../../../../../lib/rbac";
import { sql } from "../../../../../../lib/db";

const DAILY_LIMIT = 50;

export async function GET(
  req: NextRequest,
  { params }: { params: { owner: string; name: string } },
) {
  const session = await getServerSession(authOptions);
  try {
    await requireRepoRole(session, params.owner, params.name, "repo:viewer");
  } catch (r) {
    return r as Response;
  }

  const rows = await sql`
    SELECT
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '24 hours') AS scans_today,
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '7 days')  AS scans_7d,
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '30 days') AS scans_30d,
      COUNT(*) FILTER (
        WHERE s.created_at > NOW() - INTERVAL '24 hours'
          AND s.verdict = 'TRUE_POSITIVE'
      ) AS tp_today
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${params.owner} AND r.name = ${params.name}
  `;

  const d = rows[0] as any;
  return NextResponse.json({
    scans_today: Number(d.scans_today),
    scans_7d: Number(d.scans_7d),
    scans_30d: Number(d.scans_30d),
    tp_today: Number(d.tp_today),
    limit: DAILY_LIMIT,
    remaining: Math.max(0, DAILY_LIMIT - Number(d.scans_today)),
  });
}
