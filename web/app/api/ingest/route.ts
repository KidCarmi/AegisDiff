/**
 * POST /api/ingest
 *
 * Receives scan metadata from GitHub Actions.
 * Stores only metadata — no code, no diffs, no evidence.
 *
 * Auth — two mechanisms accepted:
 *   1. GitHub Actions OIDC JWT (zero-config, recommended)
 *   2. Per-repo Bearer token (legacy / manual-connect repos)
 *
 * After inserting the scan, fires any configured webhooks
 * (Slack, Discord, MS Teams) and optionally creates a GitHub Issue,
 * respecting per-repo notification thresholds.
 */
import { NextRequest, NextResponse } from "next/server";
import { createHash, createHmac } from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { sql } from "../../../lib/db";
import type { IngestPayload } from "../../../lib/types";

const ALLOWED_VERDICTS = new Set(["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ERROR"]);
const SEVERITY_RANK: Record<string, number> = {
  INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4, "N/A": -1,
};

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS = createRemoteJWKSet(new URL(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`));

async function verifyOIDC(token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, GITHUB_JWKS, {
      issuer: GITHUB_OIDC_ISSUER, audience: "aegisdiff",
    });
    return (payload["repository"] as string) ?? null;
  } catch { return null; }
}

// ── Webhook helpers ──────────────────────────────────────────────────────────

function shouldNotify(
  verdict: string,
  severity: string | null,
  minSeverity: string,
  notifyNeedsReview: boolean,
): boolean {
  if (verdict === "FALSE_POSITIVE" || verdict === "ERROR") return false;
  if (verdict === "NEEDS_REVIEW" && !notifyNeedsReview) return false;
  const sevRank = SEVERITY_RANK[severity ?? "INFO"] ?? 0;
  const minRank = SEVERITY_RANK[minSeverity] ?? 0;
  return sevRank >= minRank;
}

function buildSlackPayload(owner: string, name: string, payload: IngestPayload) {
  const prLink = payload.pr_url
    ? `<${payload.pr_url}|PR #${payload.pr_number}>`
    : `commit \`${payload.commit_sha?.slice(0, 7)}\``;
  const isTP = payload.verdict === "TRUE_POSITIVE";
  return {
    text: `${isTP ? "🚨" : "⚠️"} *AegisDiff — ${isTP ? "Security Issue" : "Needs Review"}*`,
    blocks: [{
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${isTP ? "🚨" : "⚠️"} *${payload.title ?? "Security finding"}*\n*Repo:* \`${owner}/${name}\` · ${prLink}\n*Severity:* ${payload.severity ?? "N/A"} · *CWE:* ${payload.cwe_id ?? "N/A"} · *Confidence:* ${Math.round((payload.confidence ?? 0) * 100)}%`,
      },
    }],
  };
}

function buildDiscordPayload(owner: string, name: string, payload: IngestPayload) {
  const isTP = payload.verdict === "TRUE_POSITIVE";
  const color = isTP ? 0xe74c3c : 0xf39c12; // red or orange
  return {
    embeds: [{
      title: `${isTP ? "🚨" : "⚠️"} ${payload.title ?? "Security finding"}`,
      description: `**Repo:** \`${owner}/${name}\`\n**Verdict:** ${payload.verdict}\n**Severity:** ${payload.severity ?? "N/A"} · **CWE:** ${payload.cwe_id ?? "N/A"}`,
      color,
      fields: [
        { name: "Confidence", value: `${Math.round((payload.confidence ?? 0) * 100)}%`, inline: true },
        { name: "PR", value: payload.pr_url ? `[PR #${payload.pr_number}](${payload.pr_url})` : `\`${payload.commit_sha?.slice(0, 7)}\``, inline: true },
      ],
      footer: { text: "AegisDiff Security Triage" },
    }],
  };
}

function buildTeamsPayload(owner: string, name: string, payload: IngestPayload) {
  const isTP = payload.verdict === "TRUE_POSITIVE";
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: isTP ? "FF0000" : "FFA500",
    summary: payload.title ?? "AegisDiff Security Finding",
    sections: [{
      activityTitle: `${isTP ? "🚨" : "⚠️"} ${payload.title ?? "Security finding"}`,
      activitySubtitle: `${owner}/${name}`,
      facts: [
        { name: "Verdict", value: payload.verdict },
        { name: "Severity", value: payload.severity ?? "N/A" },
        { name: "CWE", value: payload.cwe_id ?? "N/A" },
        { name: "Confidence", value: `${Math.round((payload.confidence ?? 0) * 100)}%` },
        ...(payload.pr_url ? [{ name: "PR", value: `[#${payload.pr_number}](${payload.pr_url})` }] : []),
      ],
    }],
  };
}

async function fireWebhook(url: string, body: object, label: string) {
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).catch((e) => console.error(`[ingest] ${label} webhook failed:`, e));
}

/** Create a GitHub Issue via App installation token. */
async function createGitHubIssue(
  installationId: number,
  owner: string,
  repo: string,
  payload: IngestPayload,
) {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY;
  if (!appId || !privateKey) return;

  try {
    // Mint a short-lived installation token (RS256 JWT)
    const now = Math.floor(Date.now() / 1000);
    const { SignJWT } = await import("jose");
    const key = await import("crypto").then(({ createPrivateKey }) => createPrivateKey(privateKey));
    const appJwt = await new SignJWT({ iss: appId })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt(now - 60)
      .setExpirationTime(now + 600)
      .sign(key);

    const tokenResp = await fetch(
      `https://api.github.com/app/installations/${installationId}/access_tokens`,
      { method: "POST", headers: { Authorization: `Bearer ${appJwt}`, Accept: "application/vnd.github+json" } },
    );
    if (!tokenResp.ok) return;
    const { token } = await tokenResp.json();

    const body = [
      `**AegisDiff** detected a security issue in this pull request.`,
      ``,
      `| Field | Value |`,
      `|---|---|`,
      `| **Verdict** | ${payload.verdict} |`,
      `| **Severity** | ${payload.severity ?? "N/A"} |`,
      `| **CWE** | ${payload.cwe_id ?? "N/A"} |`,
      `| **Confidence** | ${Math.round((payload.confidence ?? 0) * 100)}% |`,
      `| **Commit** | \`${payload.commit_sha?.slice(0, 7)}\` |`,
      ...(payload.pr_url ? [`| **PR** | [#${payload.pr_number}](${payload.pr_url}) |`] : []),
      ``,
      `> Evidence is in the PR comment — source code is never stored by AegisDiff.`,
    ].join("\n");

    await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
      body: JSON.stringify({
        title: `[Security] ${payload.title ?? "Vulnerability detected by AegisDiff"}`,
        body,
        labels: ["security"],
      }),
    });
  } catch (e) {
    console.error("[ingest] GitHub Issue creation failed:", e);
  }
}

// ── Main handler ─────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return NextResponse.json({ error: "Missing authorization" }, { status: 401 });

  let repoId: number;

  // 1. OIDC path
  const oidcRepo = await verifyOIDC(token);
  if (oidcRepo) {
    const [owner, name] = oidcRepo.split("/");
    const rows = await sql`SELECT id FROM repos WHERE owner = ${owner} AND name = ${name} LIMIT 1`;
    if (rows.length === 0) {
      const installRows = await sql`SELECT id FROM installations WHERE account_login = ${owner} AND deleted_at IS NULL LIMIT 1`;
      if (installRows.length === 0)
        return NextResponse.json({ error: "Repo not connected to AegisDiff" }, { status: 403 });
      const inserted = await sql`
        INSERT INTO repos (owner, name, token_hash)
        VALUES (${owner}, ${name}, ${"oidc-" + createHash("sha256").update(oidcRepo).digest("hex")})
        ON CONFLICT (owner, name) DO UPDATE SET owner = EXCLUDED.owner
        RETURNING id`;
      repoId = (inserted[0] as any).id;
    } else {
      repoId = (rows[0] as any).id;
    }
  } else {
    // 2. Legacy token path
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const rows = await sql`SELECT id FROM repos WHERE token_hash = ${tokenHash} LIMIT 1`;
    if (rows.length === 0) return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    repoId = (rows[0] as any).id;
  }

  // Parse & validate — accept a single payload or an array (chunked analysis)
  let payloads: IngestPayload[];
  try {
    const raw = await req.json();
    payloads = Array.isArray(raw) ? raw : [raw];
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (payloads.length === 0)
    return NextResponse.json({ error: "Empty payload array" }, { status: 400 });

  // Validate each item
  for (const p of payloads) {
    if (!ALLOWED_VERDICTS.has(p.verdict))
      return NextResponse.json({ error: "Invalid verdict" }, { status: 400 });
    if (!p.commit_sha || typeof p.commit_sha !== "string")
      return NextResponse.json({ error: "Missing commit_sha" }, { status: 400 });
  }

  // Fetch repo config once (same for all findings in this batch)
  const repoMeta = await sql`
    SELECT owner, name, installation_id,
           slack_webhook_url, discord_webhook_url, teams_webhook_url,
           COALESCE(notify_min_severity, 'INFO') AS notify_min_severity,
           COALESCE(notify_on_needs_review, false) AS notify_on_needs_review,
           COALESCE(auto_github_issue, false) AS auto_github_issue
    FROM repos WHERE id = ${repoId} LIMIT 1`;
  const meta = repoMeta[0] as any ?? {};

  // Insert one scan row per finding
  for (const payload of payloads) {
    const confidence = typeof payload.confidence === "number" && isFinite(payload.confidence)
      ? Math.max(0, Math.min(1, payload.confidence)) : null;
    const title = payload.title?.slice(0, 80) ?? null;

    await sql`
      INSERT INTO scans (repo_id, pr_number, commit_sha, pr_url, verdict, severity, cwe_id, confidence, title, provider, scan_ms)
      VALUES (${repoId}, ${payload.pr_number ?? null}, ${payload.commit_sha.slice(0, 40)},
              ${payload.pr_url ?? null}, ${payload.verdict}, ${payload.severity ?? null},
              ${payload.cwe_id ?? null}, ${confidence}, ${title},
              ${payload.provider ?? null}, ${payload.scan_ms ?? null})`;
  }

  // Audit log — one entry summarising the batch
  try {
    const githubIdRows = await sql`SELECT u.github_id FROM users u JOIN repos r ON r.user_id = u.id WHERE r.id = ${repoId} LIMIT 1`;
    if (githubIdRows.length > 0) {
      const primary = payloads.reduce((best, p) =>
        (SEVERITY_RANK[p.severity ?? "N/A"] ?? -1) > (SEVERITY_RANK[best.severity ?? "N/A"] ?? -1) ? p : best
      );
      await sql`INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
        VALUES (${(githubIdRows[0] as any).github_id}, 'scan_ingested', ${meta.owner}, ${meta.name},
                ${JSON.stringify({ count: payloads.length, verdict: primary.verdict, severity: primary.severity, cwe_id: primary.cwe_id })})`;
    }
  } catch { /* audit failure is non-fatal */ }

  // Webhooks — fire once for the most severe actionable finding in the batch
  const notifiable = payloads
    .filter((p) => shouldNotify(p.verdict, p.severity ?? null, meta.notify_min_severity, meta.notify_on_needs_review))
    .sort((a, b) => (SEVERITY_RANK[b.severity ?? "N/A"] ?? -1) - (SEVERITY_RANK[a.severity ?? "N/A"] ?? -1));

  if (notifiable.length > 0) {
    const primary = notifiable[0];
    const owner = meta.owner as string;
    const name = meta.name as string;

    if (meta.slack_webhook_url)
      fireWebhook(meta.slack_webhook_url, buildSlackPayload(owner, name, primary), "Slack");
    if (meta.discord_webhook_url)
      fireWebhook(meta.discord_webhook_url, buildDiscordPayload(owner, name, primary), "Discord");
    if (meta.teams_webhook_url)
      fireWebhook(meta.teams_webhook_url, buildTeamsPayload(owner, name, primary), "Teams");

    // GitHub Issues — only on TRUE_POSITIVE, only if GitHub App installed
    if (primary.verdict === "TRUE_POSITIVE" && meta.auto_github_issue && meta.installation_id) {
      createGitHubIssue(meta.installation_id, owner, name, primary);
    }
  }

  return NextResponse.json({ ok: true, count: payloads.length }, { status: 201 });
}
