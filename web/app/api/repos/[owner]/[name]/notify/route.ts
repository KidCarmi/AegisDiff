/**
 * GET/PATCH /api/repos/[owner]/[name]/notify
 * Notification threshold settings per repo:
 *   - minSeverity:       only fire webhooks when severity >= this (CRITICAL/HIGH/MEDIUM/LOW/INFO)
 *   - notifyNeedsReview: also fire webhooks on NEEDS_REVIEW (default false)
 *   - autoGithubIssue:   open a GitHub Issue on TRUE_POSITIVE (default false)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions, verifyRepoAccess } from "../../../../../../lib/auth";
import { sql } from "../../../../../../lib/db";

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
};

async function guard(req: NextRequest, owner: string, name: string) {
  const session = await getServerSession(authOptions);
  if (!session) return null;
  const ok = await verifyRepoAccess((session.user as any).accessToken, owner, name);
  return ok ? session : null;
}

export async function GET(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const rows = await sql`
    SELECT notify_min_severity AS "minSeverity",
           notify_on_needs_review AS "notifyNeedsReview",
           auto_github_issue AS "autoGithubIssue"
    FROM repos WHERE owner = ${params.owner} AND name = ${params.name} LIMIT 1`;
  return NextResponse.json(rows[0] ?? { minSeverity: "INFO", notifyNeedsReview: false, autoGithubIssue: false });
}

export async function PATCH(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const body = await req.json().catch(() => ({}));
  const minSeverity = typeof body.minSeverity === "string" && body.minSeverity in SEVERITY_RANK
    ? body.minSeverity : undefined;
  const notifyNeedsReview = typeof body.notifyNeedsReview === "boolean" ? body.notifyNeedsReview : undefined;
  const autoGithubIssue = typeof body.autoGithubIssue === "boolean" ? body.autoGithubIssue : undefined;

  await sql`
    UPDATE repos SET
      notify_min_severity    = COALESCE(${minSeverity ?? null}, notify_min_severity),
      notify_on_needs_review = COALESCE(${notifyNeedsReview ?? null}, notify_on_needs_review),
      auto_github_issue      = COALESCE(${autoGithubIssue ?? null}, auto_github_issue)
    WHERE owner = ${params.owner} AND name = ${params.name}`;
  return NextResponse.json({ ok: true });
}
