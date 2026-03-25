/**
 * GET /api/repos/[owner]/[name]/token
 *
 * Returns the derived ingest token for a GitHub App–connected repo so the
 * owner can add it as AEGISDIFF_REPO_TOKEN in their GitHub Actions secrets.
 *
 * For manually-connected repos a 404 is returned — their token was shown once
 * at creation time. Use POST /api/repos to reconnect and get a fresh token.
 *
 * Auth: requires a valid session AND the user must have GitHub read access to
 * the repo (re-verified against the GitHub API on every request).
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { createHmac } from "crypto";
import { authOptions } from "../../../../../../lib/auth";
import { requireRepoRole } from "../../../../../../lib/rbac";
import { sql } from "../../../../../../lib/db";

export async function GET(
  req: NextRequest,
  { params }: { params: { owner: string; name: string } },
) {
  const session = await getServerSession(authOptions);
  try { await requireRepoRole(session, params.owner, params.name, "repo:viewer"); }
  catch (r) { return r as Response; }

  const { owner, name } = params;

  // Validate path params
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(name)) {
    return NextResponse.json({ error: "Invalid owner or name" }, { status: 400 });
  }

  // Only supported for GitHub App–connected repos
  const rows = await sql`
    SELECT installation_id FROM repos
    WHERE owner = ${owner} AND name = ${name}
    LIMIT 1
  `;
  if (rows.length === 0) {
    return NextResponse.json({ error: "Repo not found" }, { status: 404 });
  }
  const row = rows[0] as any;
  if (!row.installation_id) {
    return NextResponse.json(
      { error: "Token retrieval is only available for GitHub App–connected repos" },
      { status: 404 },
    );
  }

  // Derive the same token the webhook handler uses
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "Server misconfiguration" }, { status: 500 });
  }
  const rawToken = createHmac("sha256", secret)
    .update(`${owner}/${name}`)
    .digest("hex");

  return NextResponse.json({ token: rawToken });
}
