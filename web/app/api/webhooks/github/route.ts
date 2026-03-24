/**
 * POST /api/webhooks/github
 *
 * Receives GitHub App webhook events.  Only the following events are processed:
 *
 *   installation              — app installed / uninstalled
 *   installation_repositories — repos added / removed from an installation
 *   pull_request              — PR opened / synchronize / reopened → trigger scan
 *
 * Security: every request is verified with HMAC-SHA256 using the
 * GITHUB_APP_WEBHOOK_SECRET environment variable before any payload
 * is processed.
 *
 * Analysis is NOT run here (Vercel 10s timeout).  Instead we fire a
 * repository_dispatch event to the AegisDiff engine repo where a
 * GitHub Actions workflow handles the heavy lifting with our own API keys.
 */
import { NextRequest, NextResponse } from "next/server";
import { createHmac, createHash, timingSafeEqual } from "crypto";
import { sql } from "../../../../lib/db";

/**
 * Derive a stable, per-repo ingest token from the webhook secret.
 * token = HMAC-SHA256(GITHUB_APP_WEBHOOK_SECRET, "owner/name")
 * token_hash = SHA256(token)
 *
 * This lets us reconstruct the raw token at dispatch time without storing it.
 */
function deriveRepoToken(repoSlug: string): { rawToken: string; tokenHash: string } {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET ?? "dev-secret";
  const rawToken = createHmac("sha256", secret).update(repoSlug).digest("hex");
  const tokenHash = createHash("sha256").update(rawToken).digest("hex");
  return { rawToken, tokenHash };
}

// ── Signature verification ────────────────────────────────────────────────────

function verifySignature(payload: string, signature: string | null, secret: string): boolean {
  if (!signature?.startsWith("sha256=")) return false;
  const expected = "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
  try {
    return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ── Repository dispatch → engine repo ────────────────────────────────────────

async function triggerAnalysis(
  installationId: number,
  repo: string,
  prNumber: number,
  headSha: string,
  ingestToken: string,
): Promise<void> {
  const engineToken = process.env.AEGISDIFF_ENGINE_TOKEN;
  const engineRepo = process.env.AEGISDIFF_ENGINE_REPO ?? "KidCarmi/AegisDiff";
  const ingestUrl = process.env.AEGISDIFF_INGEST_URL;

  if (!engineToken) {
    console.error("[webhook] AEGISDIFF_ENGINE_TOKEN not set — cannot trigger analysis");
    return;
  }

  const resp = await fetch(`https://api.github.com/repos/${engineRepo}/dispatches`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${engineToken}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      event_type: "analyze_pr",
      client_payload: {
        installation_id: installationId,
        repo,
        pr_number: prNumber,
        head_sha: headSha,
        ingest_url: ingestUrl,
        ingest_token: ingestToken,
      },
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.error(`[webhook] repository_dispatch failed (${resp.status}): ${text}`);
  } else {
    console.log(`[webhook] Triggered analysis for ${repo}#${prNumber}`);
  }
}

// ── Event handlers ────────────────────────────────────────────────────────────

async function handleInstallation(payload: any): Promise<void> {
  const { action, installation, repositories } = payload;

  if (action === "deleted") {
    await sql`
      UPDATE installations
      SET deleted_at = NOW()
      WHERE installation_id = ${installation.id}
    `;
    console.log(`[webhook] Installation ${installation.id} uninstalled`);
    return;
  }

  if (action === "created") {
    await sql`
      INSERT INTO installations (installation_id, account_login, account_type)
      VALUES (${installation.id}, ${installation.account.login}, ${installation.account.type})
      ON CONFLICT (installation_id) DO UPDATE
        SET deleted_at = NULL,
            account_login = EXCLUDED.account_login
    `;
    console.log(`[webhook] Installation ${installation.id} created for ${installation.account.login}`);

    // Register any repos included in the install event
    if (Array.isArray(repositories)) {
      await registerRepos(installation.id, repositories);
    }
  }
}

async function handleInstallationRepositories(payload: any): Promise<void> {
  const { action, installation, repositories_added, repositories_removed } = payload;

  if (action === "added" && Array.isArray(repositories_added)) {
    await registerRepos(installation.id, repositories_added);
  }

  if (action === "removed" && Array.isArray(repositories_removed)) {
    for (const r of repositories_removed) {
      const [owner, name] = (r.full_name as string).split("/");
      await sql`
        UPDATE repos
        SET deleted_at = NOW()
        WHERE owner = ${owner} AND name = ${name} AND installation_id = ${installation.id}
      `;
      console.log(`[webhook] Repo ${r.full_name} removed from installation ${installation.id}`);
    }
  }
}

async function registerRepos(installationId: number, repositories: any[]): Promise<void> {
  for (const r of repositories) {
    const [owner, name] = (r.full_name as string).split("/");

    // Check if we already have this repo from a manual-token registration
    const existing = await sql`
      SELECT id FROM repos WHERE owner = ${owner} AND name = ${name} LIMIT 1
    `;

    const { tokenHash } = deriveRepoToken(`${owner}/${name}`);

    if (existing.length > 0) {
      // Update existing row to link the installation and fix token if it was a placeholder
      await sql`
        UPDATE repos
        SET installation_id = ${installationId},
            github_repo_id  = ${r.id},
            token_hash      = ${tokenHash}
        WHERE owner = ${owner} AND name = ${name}
      `;
    } else {
      // Create a new row — no user_id (app-installed repos aren't owned by a
      // specific dashboard user until someone signs in and views them)
      await sql`
        INSERT INTO repos (user_id, owner, name, token_hash, installation_id, github_repo_id)
        VALUES (
          NULL,
          ${owner},
          ${name},
          ${tokenHash},
          ${installationId},
          ${r.id}
        )
        ON CONFLICT (owner, name) DO UPDATE
          SET installation_id = EXCLUDED.installation_id,
              github_repo_id  = EXCLUDED.github_repo_id,
              token_hash      = EXCLUDED.token_hash
      `;
    }

    console.log(`[webhook] Registered repo ${r.full_name} under installation ${installationId}`);
  }
}

async function handlePullRequest(payload: any): Promise<void> {
  const { action, pull_request, repository, installation } = payload;

  if (!["opened", "synchronize", "reopened"].includes(action)) return;
  if (!installation?.id) {
    console.warn("[webhook] pull_request event missing installation — skipping");
    return;
  }

  const repo = repository.full_name as string;
  const prNumber = pull_request.number as number;
  const headSha = pull_request.head.sha as string;

  // Derive the per-repo ingest token (deterministic from webhook secret + repo slug)
  // This matches the token_hash stored during installation registration.
  const [owner, name] = repo.split("/");
  const { rawToken, tokenHash } = deriveRepoToken(repo);

  // Also ensure the stored token_hash is up-to-date (migrates old placeholder rows)
  await sql`
    UPDATE repos
    SET token_hash = ${tokenHash}
    WHERE owner = ${owner} AND name = ${name}
      AND (token_hash LIKE 'app-install-%' OR token_hash != ${tokenHash})
  `;

  await triggerAnalysis(installation.id, repo, prNumber, headSha, rawToken);
}

// ── Main handler ──────────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  const webhookSecret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!webhookSecret) {
    console.error("[webhook] GITHUB_APP_WEBHOOK_SECRET not configured");
    return NextResponse.json({ error: "Webhook not configured" }, { status: 500 });
  }

  const rawBody = await req.text();
  const signature = req.headers.get("x-hub-signature-256");

  if (!verifySignature(rawBody, signature, webhookSecret)) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const event = req.headers.get("x-github-event");

  try {
    switch (event) {
      case "installation":
        await handleInstallation(payload);
        break;
      case "installation_repositories":
        await handleInstallationRepositories(payload);
        break;
      case "pull_request":
        await handlePullRequest(payload);
        break;
      case "ping":
        console.log("[webhook] Ping received — webhook configured correctly");
        break;
      default:
        // Ignore unsubscribed events silently
        break;
    }
  } catch (err) {
    console.error(`[webhook] Error handling ${event}:`, err);
    // Return 200 so GitHub does not retry — we logged the error
    return NextResponse.json({ error: "Handler error", event }, { status: 200 });
  }

  return NextResponse.json({ ok: true });
}
