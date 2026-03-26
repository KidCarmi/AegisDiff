/**
 * POST /api/repos/sync
 *
 * Syncs GitHub App installations and repos directly from the GitHub API
 * using the signed-in user's OAuth token.
 *
 * This is the fallback path when webhooks fail (wrong URL, missing secret, etc).
 * Safe to call multiple times — all DB writes are idempotent.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { createHmac, createHash } from "crypto";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

function deriveRepoToken(repoSlug: string): string {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET ?? "dev-secret";
  const rawToken = createHmac("sha256", secret).update(repoSlug).digest("hex");
  return createHash("sha256").update(rawToken).digest("hex");
}

async function ghFetch(url: string, accessToken: string) {
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
    },
    cache: "no-store",
  });
  if (!resp.ok) throw new Error(`GitHub API ${resp.status}: ${url}`);
  return resp.json();
}

export async function POST(req: NextRequest) {
  try {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const accessToken = (session.user as any).accessToken as string;
  if (!accessToken) return NextResponse.json({ error: "No access token" }, { status: 400 });

  let installations: any[] = [];
  let page = 1;
  // Paginate through all installations accessible to the user
  while (true) {
    const data = await ghFetch(
      `https://api.github.com/user/installations?per_page=100&page=${page}`,
      accessToken
    );
    installations = installations.concat(data.installations ?? []);
    if ((data.installations ?? []).length < 100) break;
    page++;
  }

  if (installations.length === 0) {
    return NextResponse.json({ synced: 0, message: "No GitHub App installations found for your account." });
  }

  let repoCount = 0;

  for (const inst of installations) {
    // Upsert installation record
    await sql`
      INSERT INTO installations (installation_id, account_login, account_type)
      VALUES (${inst.id}, ${inst.account.login}, ${inst.account.type})
      ON CONFLICT (installation_id) DO UPDATE
        SET deleted_at    = NULL,
            account_login = EXCLUDED.account_login
    `;

    // Fetch repos for this installation (paginated)
    let repos: any[] = [];
    let rPage = 1;
    while (true) {
      const data = await ghFetch(
        `https://api.github.com/user/installations/${inst.id}/repositories?per_page=100&page=${rPage}`,
        accessToken
      );
      repos = repos.concat(data.repositories ?? []);
      if ((data.repositories ?? []).length < 100) break;
      rPage++;
    }

    for (const r of repos) {
      const [owner, name] = (r.full_name as string).split("/");
      const tokenHash = deriveRepoToken(r.full_name);

      await sql`
        INSERT INTO repos (user_id, owner, name, token_hash, installation_id, github_repo_id)
        VALUES (NULL, ${owner}, ${name}, ${tokenHash}, ${inst.id}, ${r.id})
        ON CONFLICT (owner, name) DO UPDATE
          SET installation_id = EXCLUDED.installation_id,
              github_repo_id  = EXCLUDED.github_repo_id,
              token_hash      = EXCLUDED.token_hash,
              deleted_at      = NULL
      `;
      repoCount++;
    }
  }

  return NextResponse.json({
    synced: repoCount,
    installations: installations.length,
    message: `Synced ${repoCount} repo${repoCount !== 1 ? "s" : ""} from ${installations.length} installation${installations.length !== 1 ? "s" : ""}.`,
  });
  } catch (err: any) {
    console.error("[sync] Error:", err);
    return NextResponse.json(
      { error: err?.message ?? "Sync failed — check server logs" },
      { status: 500 }
    );
  }
}
