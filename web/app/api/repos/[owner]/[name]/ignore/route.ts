/**
 * GET    /api/repos/[owner]/[name]/ignore  — list ignore rules
 * POST   /api/repos/[owner]/[name]/ignore  — add rule
 * DELETE /api/repos/[owner]/[name]/ignore?id=N — remove rule
 *
 * Ignore rules suppress notifications for matching scans.
 * Matching criteria: cwe_id and/or title keyword.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from '../../../../../../lib/auth';
import { requireRepoRole } from '../../../../../../lib/rbac';
import { sql } from "../../../../../../lib/db";


export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const rows = await sql`
    SELECT ir.id, ir.cwe_id, ir.title_keyword, ir.reason, ir.created_at
    FROM ignore_rules ir
    JOIN repos r ON ir.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
    ORDER BY ir.created_at DESC`;
  return NextResponse.json({ rules: rows });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:admin"); }
  catch (r) { return r as Response; }

  const body = await req.json().catch(() => ({}));
  const cweId: string | null = body.cweId ?? null;
  const titleKeyword: string | null = body.titleKeyword ?? null;
  const reason: string | null = body.reason?.slice(0, 200) ?? null;

  if (!cweId && !titleKeyword)
    return NextResponse.json({ error: "Provide cweId or titleKeyword" }, { status: 400 });

  const repoRows = await sql`SELECT id FROM repos WHERE owner=${owner} AND name=${name} LIMIT 1`;
  if (!repoRows.length) return NextResponse.json({ error: "Repo not found" }, { status: 404 });
  const repoId = (repoRows[0] as any).id;

  await sql`
    INSERT INTO ignore_rules (repo_id, cwe_id, title_keyword, reason)
    VALUES (${repoId}, ${cweId}, ${titleKeyword}, ${reason})`;
  return NextResponse.json({ ok: true }, { status: 201 });
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ owner: string; name: string }> }) {
  const { owner, name } = await params;
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, owner, name, "repo:admin"); }
  catch (r) { return r as Response; }

  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 });

  await sql`
    DELETE FROM ignore_rules ir
    USING repos r
    WHERE ir.id = ${parseInt(id, 10)} AND ir.repo_id = r.id
      AND r.owner = ${owner} AND r.name = ${name}`;
  return NextResponse.json({ ok: true });
}
