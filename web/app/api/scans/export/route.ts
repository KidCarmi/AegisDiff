/**
 * GET /api/scans/export
 * Downloads scan history for the authenticated user.
 *
 * Query params:
 *   ?repo=owner/name   — filter to one repo
 *   ?format=csv|sarif  — output format (default: csv)
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
  const format = searchParams.get("format") ?? "csv";

  let rows: any[];
  const baseQuery = (owner?: string, name?: string) =>
    owner && name
      ? sql`
          SELECT s.id, r.owner, r.name, s.pr_number, s.commit_sha, s.pr_url,
                 s.verdict, s.severity, s.cwe_id, s.confidence, s.title,
                 s.provider, s.scan_ms, s.created_at
          FROM scans s JOIN repos r ON s.repo_id = r.id
          WHERE r.owner = ${owner} AND r.name = ${name}
            AND (r.id IN (SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id WHERE u.github_id = ${githubId})
                 OR (r.installation_id IS NOT NULL AND r.owner = ${username}))
          ORDER BY s.created_at DESC LIMIT 10000`
      : sql`
          SELECT s.id, r.owner, r.name, s.pr_number, s.commit_sha, s.pr_url,
                 s.verdict, s.severity, s.cwe_id, s.confidence, s.title,
                 s.provider, s.scan_ms, s.created_at
          FROM scans s JOIN repos r ON s.repo_id = r.id
          WHERE r.id IN (SELECT r2.id FROM repos r2 JOIN users u ON r2.user_id = u.id WHERE u.github_id = ${githubId})
             OR (r.installation_id IS NOT NULL AND r.owner = ${username})
          ORDER BY s.created_at DESC LIMIT 10000`;

  if (repoFilter) {
    const parts = repoFilter.split("/");
    if (parts.length !== 2 || !parts[0] || !parts[1])
      return NextResponse.json({ error: "Invalid repo filter" }, { status: 400 });
    rows = (await baseQuery(parts[0], parts[1])) as any[];
  } else {
    rows = (await baseQuery()) as any[];
  }

  const slug = repoFilter?.replace("/", "-");

  // ── CSV ───────────────────────────────────────────────────────────────────
  if (format !== "sarif") {
    const escape = (v: unknown) => {
      if (v == null) return "";
      const s = String(v).replace(/"/g, '""');
      return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s}"` : s;
    };
    const header = "id,repo,pr_number,commit_sha,pr_url,verdict,severity,cwe_id,confidence,title,provider,scan_ms,created_at";
    const lines = [header, ...rows.map((r) =>
      [r.id, `${r.owner}/${r.name}`, r.pr_number, r.commit_sha, r.pr_url,
       r.verdict, r.severity, r.cwe_id, r.confidence, r.title,
       r.provider, r.scan_ms, r.created_at].map(escape).join(","))];
    return new NextResponse(lines.join("\n"), {
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="${slug ? `aegisdiff-${slug}` : "aegisdiff-scans"}.csv"`,
      },
    });
  }

  // ── SARIF 2.1.0 ──────────────────────────────────────────────────────────
  const SEVERITY_MAP: Record<string, string> = {
    CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "none",
  };
  const VERDICT_LEVEL: Record<string, string> = {
    TRUE_POSITIVE: "error", NEEDS_REVIEW: "warning", FALSE_POSITIVE: "none", ERROR: "none",
  };

  const results = rows
    .filter((r) => r.verdict === "TRUE_POSITIVE" || r.verdict === "NEEDS_REVIEW")
    .map((r) => ({
      ruleId: r.cwe_id ?? "AegisDiff/UnknownVulnerability",
      level: SEVERITY_MAP[r.severity] ?? VERDICT_LEVEL[r.verdict] ?? "warning",
      message: { text: r.title ?? "Security issue detected by AegisDiff" },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: `${r.owner}/${r.name}`, uriBaseId: "GITHUB" },
        },
      }],
      properties: {
        repo: `${r.owner}/${r.name}`,
        pr_number: r.pr_number,
        commit_sha: r.commit_sha,
        verdict: r.verdict,
        severity: r.severity,
        confidence: r.confidence,
        provider: r.provider,
        scanned_at: r.created_at,
      },
    }));

  const sarif = {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "AegisDiff",
          version: "1.0.0",
          informationUri: "https://aegis-diff.vercel.app",
          rules: [],
        },
      },
      results,
    }],
  };

  return new NextResponse(JSON.stringify(sarif, null, 2), {
    headers: {
      "Content-Type": "application/sarif+json",
      "Content-Disposition": `attachment; filename="${slug ? `aegisdiff-${slug}` : "aegisdiff-scans"}.sarif"`,
    },
  });
}
