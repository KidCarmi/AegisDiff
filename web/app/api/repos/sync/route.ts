/**
 * POST /api/repos/sync
 *
 * Syncs GitHub App installations and repos directly from the GitHub API.
 * Uses the GitHub App JWT to call /app/installations, then registers each
 * repo in the DB. Safe to call multiple times — all writes are idempotent.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { createHmac, createHash } from "crypto";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { generateAppJWT, getInstallationToken, ghFetch } from "../../../../lib/github-app";

export const dynamic = "force-dynamic";

function deriveRepoToken(repoSlug: string): string {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!secret) throw new Error("GITHUB_APP_WEBHOOK_SECRET is not set — cannot derive repo token");
  const rawToken = createHmac("sha256", secret).update(repoSlug).digest("hex");
  return createHash("sha256").update(rawToken).digest("hex");
}

export async function POST(req: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const username = (session.user as any).username as string;
    const appJWT = await generateAppJWT();

    // Fetch all installations for this App
    let installations: any[] = [];
    let page = 1;
    while (true) {
      const data = await ghFetch(
        `https://api.github.com/app/installations?per_page=100&page=${page}`,
        appJWT
      );
      installations = installations.concat(Array.isArray(data) ? data : []);
      if ((Array.isArray(data) ? data : []).length < 100) break;
      page++;
    }

    // Only include installations for this user's personal account or their orgs
    const relevant = installations.filter(
      (i) => i.account?.login === username || i.account?.type === "Organization"
    );

    if (relevant.length === 0) {
      return NextResponse.json({
        synced: 0,
        message: `No installations found for @${username}. Make sure you've installed the GitHub App on your account or org.`,
      });
    }

    let repoCount = 0;

    for (const inst of relevant) {
      await sql`
        INSERT INTO installations (installation_id, account_login, account_type)
        VALUES (${inst.id}, ${inst.account.login}, ${inst.account.type})
        ON CONFLICT (installation_id) DO UPDATE
          SET deleted_at    = NULL,
              account_login = EXCLUDED.account_login
      `;

      const installToken = await getInstallationToken(inst.id);

      let repos: any[] = [];
      let rPage = 1;
      while (true) {
        const data = await ghFetch(
          `https://api.github.com/installation/repositories?per_page=100&page=${rPage}`,
          installToken
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
      installations: relevant.length,
      message: `Synced ${repoCount} repo${repoCount !== 1 ? "s" : ""} from ${relevant.length} installation${relevant.length !== 1 ? "s" : ""}.`,
    });
  } catch (err: any) {
    console.error("[sync] Error:", err);
    return NextResponse.json(
      { error: err?.message ?? "Sync failed" },
      { status: 500 }
    );
  }
}
