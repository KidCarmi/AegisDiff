/**
 * POST /api/admin/cleanup
 *
 * Deletes scan records older than 90 days (retention policy).
 * Called daily by the cleanup GitHub Actions workflow.
 * Authenticated via the same AEGISDIFF_REPO_TOKEN mechanism.
 */
import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { sql } from "../../../../lib/db";

export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return NextResponse.json({ error: "Missing authorization" }, { status: 401 });
  }

  // Any valid repo token can trigger cleanup (the operation is safe and non-destructive to other repos)
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const repoRows = await sql`SELECT id FROM repos WHERE token_hash = ${tokenHash} LIMIT 1`;

  if (repoRows.length === 0) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }

  const result = await sql`
    DELETE FROM scans
    WHERE created_at < NOW() - INTERVAL '90 days'
  `;

  return NextResponse.json({
    ok: true,
    deleted: (result as any).count ?? 0,
    message: "Scan records older than 90 days have been purged",
  });
}
