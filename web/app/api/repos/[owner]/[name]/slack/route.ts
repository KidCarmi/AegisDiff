/**
 * GET   /api/repos/[owner]/[name]/slack  — get current Slack webhook
 * PATCH /api/repos/[owner]/[name]/slack  — set/clear Slack webhook
 *
 * The webhook URL is stored per-repo and fired on TRUE_POSITIVE scans.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from '../../../../../../lib/auth';
import { requireRepoRole } from '../../../../../../lib/rbac';
import { sql } from "../../../../../../lib/db";


export const dynamic = "force-dynamic";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ owner: string; name: string }> },
) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const rows = await sql`
    SELECT slack_webhook_url AS "slackWebhookUrl"
    FROM repos WHERE owner = ${owner} AND name = ${name} LIMIT 1
  `;
  const url = (rows[0] as any)?.slackWebhookUrl as string | null;
  // Never return the full webhook URL — mask it
  return NextResponse.json({ configured: !!url, masked: url ? maskUrl(url) : null });
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ owner: string; name: string }> },
) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:admin"); }
  catch (r) { return r as Response; }

  let body: { slackWebhookUrl: string | null };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const url = body.slackWebhookUrl;
  if (url !== null && url !== undefined) {
    if (typeof url !== "string") return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
    if (url && !url.startsWith("https://hooks.slack.com/")) {
      return NextResponse.json({ error: "Must be a Slack webhook URL" }, { status: 400 });
    }
  }

  await sql`
    UPDATE repos SET slack_webhook_url = ${url ?? null}
    WHERE owner = ${owner} AND name = ${name}
  `;
  return NextResponse.json({ ok: true });
}

function maskUrl(url: string): string {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/");
    parts[parts.length - 1] = "****";
    return `${u.origin}${parts.join("/")}`;
  } catch {
    return "****";
  }
}
