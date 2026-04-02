/**
 * GET /api/llm-token
 *
 * Platform key distribution — zero-config AI for AegisDiff users.
 *
 * Authenticated GitHub Actions runners exchange their OIDC JWT for
 * AegisDiff's own OpenRouter API keys. The runner makes LLM calls
 * directly — source code never reaches AegisDiff servers.
 *
 * Auth:   GitHub Actions OIDC JWT (audience: "aegisdiff")
 * Limit:  FREE_TIER_DAILY_LIMIT scans per repo per 24 h (overridable
 *         per-repo by platform admin via /api/admin/rate-limit)
 * Bypass: User's own OPENROUTER_API_KEY — entrypoint skips
 *         this endpoint entirely when user keys are present.
 *
 * Rate limit is enforced atomically via the llm_token_issuances table
 * (INSERT ... WHERE count < limit CTE) to prevent TOCTOU bypass.
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../lib/db";
import { verifyOIDC } from "../../../lib/oidc";

export const dynamic = "force-dynamic";

const FREE_TIER_DAILY_LIMIT = 100;

export async function GET(req: NextRequest) {
  // ── 1. Authenticate via OIDC ───────────────────────────────────────────
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return NextResponse.json(
      { error: "Missing Authorization header" },
      { status: 401 }
    );
  }

  const repo = await verifyOIDC(token);
  if (!repo) {
    return NextResponse.json(
      { error: "Invalid or expired OIDC token" },
      { status: 401 }
    );
  }

  const parts = repo.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return NextResponse.json({ error: "Invalid OIDC repo claim" }, { status: 400 });
  }
  const [owner, name] = parts;

  // ── 2. Atomic rate limit via llm_token_issuances ───────────────────────
  // A single CTE atomically reads the count and conditionally inserts a new
  // issuance row — preventing TOCTOU where concurrent PRs could all read
  // count=0 before any scan is persisted.
  const result = await sql`
    WITH limit_row AS (
      SELECT COALESCE(MAX(custom_daily_limit), ${FREE_TIER_DAILY_LIMIT}) AS lim
      FROM repos
      WHERE owner = ${owner} AND name = ${name}
    ),
    current_count AS (
      SELECT COUNT(*)::int AS cnt
      FROM llm_token_issuances
      WHERE repo_owner = ${owner}
        AND repo_name  = ${name}
        AND issued_at  > NOW() - INTERVAL '24 hours'
    ),
    ins AS (
      INSERT INTO llm_token_issuances (repo_owner, repo_name)
      SELECT ${owner}, ${name}
      WHERE (SELECT cnt FROM current_count) < (SELECT lim FROM limit_row)
      RETURNING id
    )
    SELECT
      (SELECT cnt FROM current_count)  AS count_before,
      (SELECT lim FROM limit_row)      AS effective_limit,
      (SELECT id  FROM ins)            AS inserted_id
  `;

  const row = result[0] as any;
  const countBefore    = parseInt(row?.count_before   ?? "0", 10);
  const effectiveLimit = parseInt(row?.effective_limit ?? String(FREE_TIER_DAILY_LIMIT), 10);
  const insertedId     = row?.inserted_id;

  if (insertedId == null) {
    return NextResponse.json(
      {
        error:
          `Rate limit reached: ${effectiveLimit} scans/day. ` +
          `Add OPENROUTER_API_KEY or GROQ_API_KEY to your repo secrets for unlimited scans.`,
        scans_today: countBefore,
        limit: effectiveLimit,
      },
      { status: 429 }
    );
  }

  // ── 3. Check platform keys are configured ─────────────────────────────
  const openrouterKeys = [
    process.env.PLATFORM_OPENROUTER_API_KEY,
    process.env.PLATFORM_OPENROUTER_API_KEY_2,
    process.env.PLATFORM_OPENROUTER_API_KEY_3,
  ].filter(Boolean) as string[];

  const groqKeys = [
    process.env.PLATFORM_GROQ_API_KEY,
    process.env.PLATFORM_GROQ_API_KEY_2,
    process.env.PLATFORM_GROQ_API_KEY_3,
  ].filter(Boolean) as string[];

  if (openrouterKeys.length === 0 && groqKeys.length === 0) {
    return NextResponse.json(
      { error: "Platform AI keys not configured — contact support." },
      { status: 503 }
    );
  }

  // ── 4. Audit log ───────────────────────────────────────────────────────
  sql`
    INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
    VALUES (
      0,
      'llm_key_issued',
      ${owner},
      ${name},
      ${JSON.stringify({ issuances_today: countBefore + 1, limit: effectiveLimit })}
    )
  `.catch(() => {});

  // ── 5. Return keys (expires in 10 minutes — enough for one scan) ───────
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  return NextResponse.json({
    openrouter_keys: openrouterKeys,
    groq_keys:       groqKeys,
    expires_at:      expiresAt,
    scans_today:     countBefore + 1,
    limit:           effectiveLimit,
  });
}
