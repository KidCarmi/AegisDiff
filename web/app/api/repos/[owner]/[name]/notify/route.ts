/**
 * GET/PATCH /api/repos/[owner]/[name]/notify
 * Notification threshold settings per repo:
 *   - minSeverity:       only fire webhooks when severity >= this (CRITICAL/HIGH/MEDIUM/LOW/INFO)
 *   - notifyNeedsReview: also fire webhooks on NEEDS_REVIEW (default false)
 *   - autoGithubIssue:   open a GitHub Issue on TRUE_POSITIVE (default false)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from '../../../../../../lib/auth';
import { requireRepoRole } from '../../../../../../lib/rbac';
import { sql } from "../../../../../../lib/db";

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
};

export async function GET(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, params.owner, params.name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const rows = await sql`
    SELECT notify_min_severity AS "minSeverity",
           notify_on_needs_review AS "notifyNeedsReview",
           auto_github_issue AS "autoGithubIssue"
    FROM repos WHERE owner = ${params.owner} AND name = ${params.name} LIMIT 1`;
  return NextResponse.json(rows[0] ?? { minSeverity: "INFO", notifyNeedsReview: false, autoGithubIssue: false });
}

export async function PATCH(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, params.owner, params.name, "repo:admin"); }
  catch (r) { return r as Response; }

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
