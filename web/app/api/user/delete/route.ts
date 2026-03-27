/**
 * DELETE /api/user/delete
 *
 * Permanently deletes the authenticated user's account and all associated data.
 * This is irreversible. Cascades:
 *   - scans (via repos)
 *   - scan_feedback (via scans)
 *   - ignore_rules (via repos)
 *   - audit_log entries
 *   - api_keys
 *   - repos (owned via user_id)
 *   - installations (where installed_by_github_id = user's github_id)
 *   - the users row itself
 *
 * Requires a confirmation body: { confirm: "delete my account" }
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

export async function DELETE(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Require explicit confirmation in the request body
  const body = await req.json().catch(() => null);
  if (body?.confirm !== "delete my account") {
    return NextResponse.json(
      { error: 'Body must contain { "confirm": "delete my account" }' },
      { status: 400 }
    );
  }

  const githubId = (session.user as any).githubId as number;

  try {
    // Delete in dependency order to avoid FK violations.
    // scan_feedback and ignore_rules cascade from repos/scans via ON DELETE CASCADE.
    // We still clean up audit_log and api_keys manually since they reference github_id directly.

    // 1. Audit log entries for this user
    await sql`DELETE FROM audit_log WHERE github_id = ${githubId}`;

    // 2. API keys
    await sql`
      DELETE FROM api_keys WHERE github_id = ${githubId}
    `;

    // 3. scan_feedback rows authored by this user (cross-repo)
    await sql`DELETE FROM scan_feedback WHERE github_id = ${githubId}`;

    // 4. Repos owned via user_id — cascades scans, scan_feedback, ignore_rules
    await sql`
      DELETE FROM repos
      WHERE user_id = (SELECT id FROM users WHERE github_id = ${githubId} LIMIT 1)
    `;

    // 5. Soft-delete installations this user created (keeps repos for other members)
    await sql`
      UPDATE installations
      SET deleted_at = NOW()
      WHERE installed_by_github_id = ${githubId}
        AND deleted_at IS NULL
    `;

    // 6. Delete the user row itself
    await sql`DELETE FROM users WHERE github_id = ${githubId}`;

    return NextResponse.json({ ok: true });
  } catch (err: any) {
    console.error("[user/delete] Error:", err);
    return NextResponse.json({ error: err?.message ?? "Internal error" }, { status: 500 });
  }
}
