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

export async function GET(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const rows = await sql`SELECT teams_webhook_url FROM repos
    WHERE owner = ${params.owner} AND name = ${params.name} LIMIT 1`;
  const url = (rows[0] as any)?.teams_webhook_url as string | null;
  const masked = url ? url.replace(/\?.*$/, "?****") : null;
  return NextResponse.json({ configured: !!url, masked });
}

export async function PATCH(req: NextRequest, { params }: { params: { owner: string; name: string } }) {
  if (!await guard(req, params.owner, params.name))
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const body = await req.json().catch(() => null);
  const url: string | null = body?.teamsWebhookUrl ?? null;
  if (url && !url.includes("webhook.office.com") && !url.includes("logic.azure.com"))
    return NextResponse.json({ error: "Must be a Microsoft Teams webhook URL" }, { status: 400 });

  await sql`UPDATE repos SET teams_webhook_url = ${url}
    WHERE owner = ${params.owner} AND name = ${params.name}`;
  return NextResponse.json({ ok: true });
}
