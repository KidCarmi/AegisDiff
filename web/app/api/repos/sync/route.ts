/**
 * POST /api/repos/sync
 *
 * Syncs GitHub App installations and repos directly from the GitHub API.
 * Uses the GitHub App JWT (GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY) to call
 * /app/installations, then fetches repos per installation.
 *
 * This is the fallback path when webhooks fail (wrong URL, missing secret, etc).
 * Safe to call multiple times — all DB writes are idempotent.
 *
 * Required Vercel env vars:
 *   GITHUB_APP_ID          — numeric GitHub App ID
 *   GITHUB_APP_PRIVATE_KEY — PEM private key (replace newlines with \n in Vercel)
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { createHmac, createHash } from "crypto";
import { SignJWT } from "jose";
import { createPrivateKey } from "crypto";
import { authOptions } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";

function deriveRepoToken(repoSlug: string): string {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET ?? "dev-secret";
  const rawToken = createHmac("sha256", secret).update(repoSlug).digest("hex");
  return createHash("sha256").update(rawToken).digest("hex");
}

/** Generate a GitHub App JWT valid for 8 minutes. */
async function generateAppJWT(): Promise<string> {
  const appId = process.env.GITHUB_APP_ID;
  const rawKey = process.env.GITHUB_APP_PRIVATE_KEY;
  if (!appId || !rawKey) {
    throw new Error(
      "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set in Vercel environment variables."
    );
  }
  // Vercel stores multiline secrets with literal \n — restore real newlines.
  // createPrivateKey handles both PKCS#1 (BEGIN RSA PRIVATE KEY) and
  // PKCS#8 (BEGIN PRIVATE KEY) formats; jose accepts the KeyObject directly.
  const pem = rawKey.replace(/\\n/g, "\n");
  const privateKey = createPrivateKey(pem);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: appId })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt(now - 60)
    .setExpirationTime(now + 480)
    .sign(privateKey);
}

async function ghFetch(url: string, token: string) {
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
    },
    cache: "no-store",
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`GitHub API ${resp.status} ${url}: ${body.slice(0, 200)}`);
  }
  return resp.json();
}

export async function POST(req: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const username = (session.user as any).username as string;

    // Generate short-lived GitHub App JWT
    const appJWT = await generateAppJWT();

    // Fetch all installations for this App (paginated)
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

    // Filter to installations accessible to this user
    // (personal account installs where account_login = username,
    //  or org installs — we register all and let RBAC filter on display)
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
      // Upsert installation record
      await sql`
        INSERT INTO installations (installation_id, account_login, account_type)
        VALUES (${inst.id}, ${inst.account.login}, ${inst.account.type})
        ON CONFLICT (installation_id) DO UPDATE
          SET deleted_at    = NULL,
              account_login = EXCLUDED.account_login
      `;

      // Get an installation access token to list repos
      const tokenData = await ghFetch(
        `https://api.github.com/app/installations/${inst.id}/access_tokens`,
        appJWT
      ) as { token: string };
      const installToken = tokenData.token;

      // Fetch repos for this installation
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
      { error: err?.message ?? "Sync failed — check server logs" },
      { status: 500 }
    );
  }
}
