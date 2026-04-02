/**
 * GET  /api/v1/key  — return current API key (masked)
 * POST /api/v1/key  — generate / rotate API key
 * DELETE /api/v1/key — revoke API key
 *
 * API keys allow querying /api/v1/scans without a browser session.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { randomBytes, createHash } from "crypto";

export const dynamic = "force-dynamic";

async function requireSession(req: NextRequest) {
  const session = await getServerSession(authOptions);
  return session ?? null;
}

export async function GET(req: NextRequest) {
  const session = await requireSession(req);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const githubId = (session.user as any).githubId as number;

  const rows = await sql`
    SELECT key_prefix, created_at FROM api_keys
    WHERE github_id = ${githubId} AND revoked_at IS NULL
    ORDER BY created_at DESC LIMIT 1`;
  if (rows.length === 0) return NextResponse.json({ key: null });
  const row = rows[0] as any;
  return NextResponse.json({ key: `${row.key_prefix}…(hidden)`, createdAt: row.created_at });
}

export async function POST(req: NextRequest) {
  const session = await requireSession(req);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const githubId = (session.user as any).githubId as number;

  // Revoke existing
  await sql`UPDATE api_keys SET revoked_at = NOW() WHERE github_id = ${githubId} AND revoked_at IS NULL`;

  const raw = `ak_${randomBytes(24).toString("hex")}`;
  const hash = createHash("sha256").update(raw).digest("hex");
  const prefix = raw.slice(0, 10);

  await sql`INSERT INTO api_keys (github_id, key_hash, key_prefix) VALUES (${githubId}, ${hash}, ${prefix})`;
  return NextResponse.json({ key: raw, warning: "Store this key safely — it won't be shown again." });
}

export async function DELETE(req: NextRequest) {
  const session = await requireSession(req);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const githubId = (session.user as any).githubId as number;
  await sql`UPDATE api_keys SET revoked_at = NOW() WHERE github_id = ${githubId} AND revoked_at IS NULL`;
  return NextResponse.json({ ok: true });
}
