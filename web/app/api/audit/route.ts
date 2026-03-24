/**
 * GET /api/audit
 * Returns audit log entries for the authenticated user (last 200 events).
 * Optional ?repo=owner/name to filter.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../lib/auth";
import { sql } from "../../../lib/db";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const githubId = (session.user as any).githubId as number;
  const repoFilter = new URL(req.url).searchParams.get("repo");

  const rows = await sql`
    SELECT al.id, al.action, al.repo_owner, al.repo_name,
           al.details, al.ip_hash, al.created_at
    FROM audit_log al
    WHERE al.github_id = ${githubId}
      AND (${repoFilter} IS NULL OR (al.repo_owner || '/' || al.repo_name) = ${repoFilter})
    ORDER BY al.created_at DESC
    LIMIT 200`;
  return NextResponse.json({ events: rows });
}
