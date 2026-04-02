import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../../lib/auth";
import { sql } from "../../../../../../lib/db";
import { requireRepoRole } from "../../../../../../lib/rbac";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const rows = await sql`SELECT teams_webhook_url FROM repos
    WHERE owner = ${owner} AND name = ${name} LIMIT 1`;
  const url = (rows[0] as any)?.teams_webhook_url as string | null;
  const masked = url ? url.replace(/\?.*$/, "?****") : null;
  return NextResponse.json({ configured: !!url, masked });
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:admin"); }
  catch (r) { return r as Response; }

  const body = await req.json().catch(() => null);
  const url: string | null = body?.teamsWebhookUrl ?? null;
  if (url && !url.includes("webhook.office.com") && !url.includes("logic.azure.com"))
    return NextResponse.json({ error: "Must be a Microsoft Teams webhook URL" }, { status: 400 });

  await sql`UPDATE repos SET teams_webhook_url = ${url}
    WHERE owner = ${owner} AND name = ${name}`;
  return NextResponse.json({ ok: true });
}
