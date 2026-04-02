/**
 * GET /api/repos/[owner]/[name]/usage
 *
 * Returns scan usage stats for this repo — used by the Settings > Usage tab
 * to show the rate-limit meter. Respects custom_daily_limit overrides set
 * by the platform admin (defaults to 100 scans/day on the free tier).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../../lib/auth";
import { requireRepoRole } from "../../../../../../lib/rbac";
import { sql } from "../../../../../../lib/db";

export const dynamic = "force-dynamic";

const DEFAULT_DAILY_LIMIT = 100;

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ owner: string; name: string }> },
) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try {
    await requireRepoRole(session, owner, name, "repo:viewer");
  } catch (r) {
    const { owner, name } = await params;
    return r as Response;
  }

  const rows = await sql`
    SELECT
      r.custom_daily_limit,
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '24 hours') AS scans_today,
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '7 days')  AS scans_7d,
      COUNT(*) FILTER (WHERE s.created_at > NOW() - INTERVAL '30 days') AS scans_30d,
      COUNT(*) FILTER (
        WHERE s.created_at > NOW() - INTERVAL '24 hours'
          AND s.verdict = 'TRUE_POSITIVE'
      ) AS tp_today
    FROM repos r
    LEFT JOIN scans s ON s.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
    GROUP BY r.id, r.custom_daily_limit
  `;

  const d = rows[0] as any;
  const effectiveLimit =
    d?.custom_daily_limit !== null && d?.custom_daily_limit !== undefined
      ? Number(d.custom_daily_limit)
      : DEFAULT_DAILY_LIMIT;

  return NextResponse.json({
    scans_today: Number(d?.scans_today ?? 0),
    scans_7d:    Number(d?.scans_7d    ?? 0),
    scans_30d:   Number(d?.scans_30d   ?? 0),
    tp_today:    Number(d?.tp_today    ?? 0),
    limit:       effectiveLimit,
    remaining:   Math.max(0, effectiveLimit - Number(d?.scans_today ?? 0)),
  });
}
