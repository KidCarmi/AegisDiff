/**
 * GET /api/v1/scans
 *
 * Public REST API — requires an API key from /api/v1/key.
 *
 * Query params:
 *   repo=owner/name   — filter to one repo
 *   verdict=TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW
 *   severity=CRITICAL|HIGH|MEDIUM|LOW|INFO
 *   limit=N           — 1–200, default 50
 *   since=ISO8601     — only return scans after this timestamp
 *
 * Auth: Authorization: Bearer ak_...
 */
import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { sql } from "../../../../lib/db";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization",
};

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

export async function GET(req: NextRequest) {
  const authHeader = req.headers.get("authorization") ?? "";
  const rawKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!rawKey?.startsWith("ak_"))
    return NextResponse.json({ error: "Missing or invalid API key" }, { status: 401 }, );

  const keyHash = createHash("sha256").update(rawKey).digest("hex");
  const keyRows = await sql`
    SELECT github_id FROM api_keys
    WHERE key_hash = ${keyHash} AND revoked_at IS NULL LIMIT 1`;
  if (keyRows.length === 0)
    return NextResponse.json({ error: "Invalid API key" }, { status: 401 });

  const githubId = (keyRows[0] as any).github_id as number;
  const { searchParams } = new URL(req.url);

  const repoFilter = searchParams.get("repo");
  const verdictFilter = searchParams.get("verdict");
  const severityFilter = searchParams.get("severity");
  const since = searchParams.get("since");
  const limit = Math.min(200, Math.max(1, parseInt(searchParams.get("limit") ?? "50", 10)));

  // Fetch scans owned by this user
  const rows = await sql`
    SELECT s.id, r.owner AS "repoOwner", r.name AS "repoName",
           s.pr_number AS "prNumber", s.commit_sha AS "commitSha",
           s.pr_url AS "prUrl", s.verdict, s.severity,
           s.cwe_id AS "cweId", s.confidence, s.title,
           s.provider, s.scan_ms AS "scanMs", s.created_at AS "createdAt"
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
      AND (${repoFilter} IS NULL OR (r.owner || '/' || r.name) = ${repoFilter})
      AND (${verdictFilter} IS NULL OR s.verdict = ${verdictFilter})
      AND (${severityFilter} IS NULL OR s.severity = ${severityFilter})
      AND (${since} IS NULL OR s.created_at > ${since}::timestamptz)
    ORDER BY s.created_at DESC
    LIMIT ${limit}`;

  return NextResponse.json(
    { data: rows, count: rows.length, limit },
    { headers: CORS },
  );
}
