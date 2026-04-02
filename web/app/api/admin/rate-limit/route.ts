/**
 * POST /api/admin/rate-limit
 *
 * Override the daily scan limit for a specific repo.
 * Stores the override in the repos table (custom_daily_limit column).
 * Requires platform:admin role.
 *
 * Body: { owner: string, name: string, limit: number | null }
 * limit: null → remove override (back to default 50)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { isPlatformAdminSession } from "../../../../lib/rbac";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session || !isPlatformAdminSession(session)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body: { owner: string; name: string; limit: number | null };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { owner, name, limit } = body;
  if (!owner || !name) {
    return NextResponse.json({ error: "owner and name are required" }, { status: 400 });
  }
  if (limit !== null && (typeof limit !== "number" || limit < 0 || limit > 10_000)) {
    return NextResponse.json(
      { error: "limit must be null or a number 0–10000" },
      { status: 400 }
    );
  }

  await sql`
    UPDATE repos
    SET custom_daily_limit = ${limit}
    WHERE owner = ${owner} AND name = ${name}
  `;

  const githubId = (session.user as any).githubId as number;
  await sql`
    INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
    VALUES (
      ${githubId}, 'rate_limit_override',
      ${owner}, ${name},
      ${JSON.stringify({ limit })}
    )
  `;

  return NextResponse.json({ ok: true, owner, name, limit });
}
