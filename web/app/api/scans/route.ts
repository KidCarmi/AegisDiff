/**
 * GET /api/scans
 *
 * Returns recent scans for the authenticated user's repos.
 * Access is restricted to repos the user can see on GitHub (RBAC delegated to GitHub).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../lib/auth";
import { sql } from "../../../lib/db";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const githubId = (session.user as any).githubId as number;
  const { searchParams } = new URL(req.url);
  const repoFilter = searchParams.get("repo"); // optional "owner/name" filter
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50"), 100);

  let rows;
  if (repoFilter) {
    const [owner, name] = repoFilter.split("/");
    rows = await sql`
      SELECT
        s.id,
        r.owner  AS "repoOwner",
        r.name   AS "repoName",
        s.pr_number    AS "prNumber",
        s.commit_sha   AS "commitSha",
        s.pr_url       AS "prUrl",
        s.verdict,
        s.severity,
        s.cwe_id       AS "cweId",
        s.confidence,
        s.title,
        s.provider,
        s.scan_ms      AS "scanMs",
        s.created_at   AS "createdAt"
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      JOIN users u ON r.user_id = u.id
      WHERE u.github_id = ${githubId}
        AND r.owner = ${owner}
        AND r.name  = ${name}
      ORDER BY s.created_at DESC
      LIMIT ${limit}
    `;
  } else {
    rows = await sql`
      SELECT
        s.id,
        r.owner  AS "repoOwner",
        r.name   AS "repoName",
        s.pr_number    AS "prNumber",
        s.commit_sha   AS "commitSha",
        s.pr_url       AS "prUrl",
        s.verdict,
        s.severity,
        s.cwe_id       AS "cweId",
        s.confidence,
        s.title,
        s.provider,
        s.scan_ms      AS "scanMs",
        s.created_at   AS "createdAt"
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      JOIN users u ON r.user_id = u.id
      WHERE u.github_id = ${githubId}
      ORDER BY s.created_at DESC
      LIMIT ${limit}
    `;
  }

  return NextResponse.json({ scans: rows });
}
