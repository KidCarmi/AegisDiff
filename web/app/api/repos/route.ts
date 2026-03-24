/**
 * GET  /api/repos  — list connected repos for the authenticated user
 * POST /api/repos  — connect a new repository (generates ingest token)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { randomUUID } from "crypto";
import { createHash } from "crypto";
import { authOptions, verifyRepoAccess } from "../../../lib/auth";
import { sql } from "../../../lib/db";

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const githubId = (session.user as any).githubId as number;
  const accessToken = (session.user as any).accessToken as string;

  // 1. Repos explicitly connected by this user (manual-token flow)
  const ownedRows = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           r.installation_id IS NOT NULL AS "appInstalled"
    FROM repos r
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
    ORDER BY r.created_at DESC
  `;

  // 2. Repos registered via GitHub App that the user has access to.
  //    We verify GitHub API access to avoid leaking repos to wrong users.
  const appRows = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           TRUE AS "appInstalled"
    FROM repos r
    WHERE r.installation_id IS NOT NULL
      AND r.user_id IS NULL
    ORDER BY r.created_at DESC
    LIMIT 200
  `;

  // Filter app-installed repos to only those the signed-in user can see
  const accessible: any[] = [];
  for (const row of appRows as any[]) {
    const resp = await fetch(
      `https://api.github.com/repos/${row.owner}/${row.name}`,
      {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
        cache: "no-store",
      }
    );
    if (resp.ok) accessible.push(row);
  }

  // Merge, deduplicate by owner/name (owned rows take precedence)
  const seen = new Set<string>();
  const merged: any[] = [];
  for (const r of [...(ownedRows as any[]), ...accessible]) {
    const key = `${r.owner}/${r.name}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(r);
    }
  }

  return NextResponse.json({ repos: merged });
}

export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const githubId = (session.user as any).githubId as number;
  const accessToken = (session.user as any).accessToken as string;

  let body: { owner: string; name: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { owner, name } = body;
  if (!owner || !name || !/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(name)) {
    return NextResponse.json({ error: "Invalid owner or name" }, { status: 400 });
  }

  // Verify the user has access to this repo via GitHub API (RBAC)
  const hasAccess = await verifyRepoAccess(accessToken, owner, name);
  if (!hasAccess) {
    return NextResponse.json(
      { error: "You do not have access to this repository on GitHub" },
      { status: 403 }
    );
  }

  // Get user DB id
  const userRows = await sql`SELECT id FROM users WHERE github_id = ${githubId} LIMIT 1`;
  if (userRows.length === 0) return NextResponse.json({ error: "User not found" }, { status: 404 });
  const userId = (userRows[0] as any).id as number;

  // Generate a unique ingest token for this repo
  const rawToken = randomUUID();
  const tokenHash = createHash("sha256").update(rawToken).digest("hex");

  await sql`
    INSERT INTO repos (user_id, owner, name, token_hash)
    VALUES (${userId}, ${owner}, ${name}, ${tokenHash})
    ON CONFLICT (owner, name) DO NOTHING
  `;

  // Return the raw token ONCE — it is never stored in plain text again
  return NextResponse.json({
    owner,
    name,
    token: rawToken,
    message: "Store this token as AEGISDIFF_REPO_TOKEN in your GitHub Secrets. It will not be shown again.",
  }, { status: 201 });
}
