import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions, verifyRepoAccess } from "../../../../../../lib/auth";
import { sql } from "../../../../../../lib/db";

async function guard(req: NextRequest, owner: string, name: string) {
  const session = await getServerSession(authOptions);
  if (!session) return null;
  const ok = await verifyRepoAccess((session.user as any).accessToken, owner, name);
  return ok ? session : null;
}

function maskUrl(url: string) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/");
    parts[parts.length - 1] = "****";
    return `${u.origin}${parts.join("/")}`;
  } catch { return "****"; }
}

export async function GET(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const rows = await sql`SELECT discord_webhook_url FROM repos
    WHERE owner = ${params.owner} AND name = ${params.name} LIMIT 1`;
  const url = (rows[0] as any)?.discord_webhook_url as string | null;
  return NextResponse.json({ configured: !!url, masked: url ? maskUrl(url) : null });
}

export async function PATCH(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const body = await req.json().catch(() => null);
  const url: string | null = body?.discordWebhookUrl ?? null;
  if (url && !url.startsWith("https://discord.com/api/webhooks/") && !url.startsWith("https://discordapp.com/api/webhooks/"))
    return NextResponse.json({ error: "Must be a Discord webhook URL" }, { status: 400 });

  await sql`UPDATE repos SET discord_webhook_url = ${url}
    WHERE owner = ${params.owner} AND name = ${params.name}`;
  return NextResponse.json({ ok: true });
}
