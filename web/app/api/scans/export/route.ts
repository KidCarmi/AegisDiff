/**
 * GET /api/scans/export
 * Downloads all scan history for the authenticated user as CSV.
 * Optional ?repo=owner/name to filter to one repo.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string;
  const { searchParams } = new URL(req.url);
  const repoFilter = searchParams.get("repo");

  let rows;
  if (repoFilter) {
    const parts = repoFilter.split("/");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return NextResponse.json({ error: "Invalid repo filter" }, { status: 400 });
    }
    const [owner, name] = parts;
    rows = await sql`
      SELECT s.id, r.owner, r.name, s.pr_number, s.commit_sha, s.pr_url,
             s.verdict, s.severity, s.cwe_id, s.confidence, s.title,
             s.provider, s.scan_ms, s.created_at
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      WHERE r.owner = ${owner} AND r.name = ${name}
        AND (
          r.id IN (SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id WHERE u.github_id = ${githubId})
          OR (r.installation_id IS NOT NULL AND r.owner = ${username})
        )
      ORDER BY s.created_at DESC
      LIMIT 10000
    `;
  } else {
    rows = await sql`
      SELECT s.id, r.owner, r.name, s.pr_number, s.commit_sha, s.pr_url,
             s.verdict, s.severity, s.cwe_id, s.confidence, s.title,
             s.provider, s.scan_ms, s.created_at
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      WHERE
        r.id IN (SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id WHERE u.github_id = ${githubId})
        OR (r.installation_id IS NOT NULL AND r.owner = ${username})
      ORDER BY s.created_at DESC
      LIMIT 10000
    `;
  }

  const header = "id,repo,pr_number,commit_sha,pr_url,verdict,severity,cwe_id,confidence,title,provider,scan_ms,created_at";
  const escape = (v: unknown) => {
    if (v == null) return "";
    const s = String(v).replace(/"/g, '""');
    return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
  };

  const lines = [
    header,
    ...(rows as any[]).map((r) =>
      [
        r.id, `${r.owner}/${r.name}`, r.pr_number, r.commit_sha, r.pr_url,
        r.verdict, r.severity, r.cwe_id, r.confidence, r.title,
        r.provider, r.scan_ms, r.created_at,
      ]
        .map(escape)
        .join(","),
    ),
  ];

  const filename = repoFilter
    ? `aegisdiff-${repoFilter.replace("/", "-")}.csv`
    : "aegisdiff-scans.csv";

  return new NextResponse(lines.join("\n"), {
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
