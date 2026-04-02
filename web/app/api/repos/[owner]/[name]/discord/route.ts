import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../../lib/auth";
import { sql } from "../../../../../../lib/db";
import { requireRepoRole } from "../../../../../../lib/rbac";

export const dynamic = "force-dynamic";

function maskUrl(url: string) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/");
    parts[parts.length - 1] = "****";
    return `${u.origin}${parts.join("/")}`;
  } catch { return "****"; }
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const rows = await sql`SELECT discord_webhook_url FROM repos
    WHERE owner = ${owner} AND name = ${name} LIMIT 1`;
  const url = (rows[0] as any)?.discord_webhook_url as string | null;
  return NextResponse.json({ configured: !!url, masked: url ? maskUrl(url) : null });
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:admin"); }
  catch (r) { return r as Response; }

  const body = await req.json().catch(() => null);
  const url: string | null = body?.discordWebhookUrl ?? null;
  if (url && !url.startsWith("https://discord.com/api/webhooks/") && !url.startsWith("https://discordapp.com/api/webhooks/"))
    return NextResponse.json({ error: "Must be a Discord webhook URL" }, { status: 400 });

  await sql`UPDATE repos SET discord_webhook_url = ${url}
    WHERE owner = ${owner} AND name = ${name}`;
  return NextResponse.json({ ok: true });
}
