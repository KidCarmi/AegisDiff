/**
 * POST /api/admin/cleanup
 *
 * Deletes scan records older than each user's retention window (default 90 days).
 * Called daily by the cleanup GitHub Actions workflow (.github/workflows/cleanup.yml).
 *
 * Auth: Bearer <CRON_SECRET>
 *   CRON_SECRET must be set in Vercel env vars and stored in GitHub secrets as
 *   AEGISDIFF_CLEANUP_SECRET in the AegisDiff repo. Vercel also injects it
 *   automatically for scheduled Cron invocations.
 *
 *   The old repo-token auth is intentionally removed: any user who knew their
 *   repo ingest token could previously trigger a global scan delete.
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../../lib/db";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret) {
    // Endpoint is disabled when CRON_SECRET is not configured.
    return NextResponse.json(
      { error: "Cleanup not configured — set CRON_SECRET in Vercel env vars" },
      { status: 503 }
    );
  }

  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token || token !== cronSecret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Delete scans older than the per-user retention setting (default 90 days).
  const result = await sql`
    DELETE FROM scans s
    USING repos r
    LEFT JOIN users u ON r.user_id = u.id
    WHERE s.repo_id = r.id
      AND s.created_at < NOW() - (
        COALESCE(u.scan_retention_days, 90) || ' days'
      )::INTERVAL
  `;

  return NextResponse.json({
    ok: true,
    deleted: (result as any).count ?? 0,
    message: "Old scan records purged (per-user retention policy applied)",
  });
}
