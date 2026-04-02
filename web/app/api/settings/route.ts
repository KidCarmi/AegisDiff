/**
 * GET  /api/settings  — fetch current user settings
 * PATCH /api/settings — update settings (scan_retention_days)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../lib/auth";
import { sql } from "../../../lib/db";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const githubId = (session.user as any).githubId as number;

  const rows = await sql`
    SELECT scan_retention_days AS "scanRetentionDays"
    FROM users WHERE github_id = ${githubId} LIMIT 1
  `;
  return NextResponse.json(rows[0] ?? { scanRetentionDays: 30 });
}

export async function PATCH(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const githubId = (session.user as any).githubId as number;

  let body: { scanRetentionDays?: number };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (body.scanRetentionDays !== undefined) {
    const days = Math.max(1, Math.min(365, Math.floor(Number(body.scanRetentionDays))));
    if (!isFinite(days)) return NextResponse.json({ error: "Invalid value" }, { status: 400 });
    await sql`UPDATE users SET scan_retention_days = ${days} WHERE github_id = ${githubId}`;
  }

  return NextResponse.json({ ok: true });
}
