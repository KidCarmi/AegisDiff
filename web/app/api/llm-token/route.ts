/**
 * GET /api/llm-token
 *
 * Platform key distribution — zero-config AI for AegisDiff users.
 *
 * Authenticated GitHub Actions runners exchange their OIDC JWT for
 * AegisDiff's own Gemini/Groq API keys. The runner makes LLM calls
 * directly — source code never reaches AegisDiff servers.
 *
 * Auth:   GitHub Actions OIDC JWT (audience: "aegisdiff")
 * Limit:  FREE_TIER_DAILY_LIMIT scans per repo per 24 h (overridable
 *         per-repo by platform admin via /api/admin/rate-limit)
 * Bypass: User's own GEMINI_API_KEY / GROQ_API_KEY — entrypoint skips
 *         this endpoint entirely when user keys are present.
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../lib/db";
import { verifyOIDC } from "../../../lib/oidc";

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

  const [owner, name] = repo.split("/");

  // ── 2. Rate limit — count scans + respect custom_daily_limit override ──
  const countRows = await sql`
    SELECT
      COUNT(s.id)              AS count,
      r.custom_daily_limit     AS custom_limit
    FROM repos r
    LEFT JOIN scans s ON s.repo_id = r.id
      AND s.created_at > NOW() - INTERVAL '24 hours'
    WHERE r.owner = ${owner}
      AND r.name  = ${name}
    GROUP BY r.id, r.custom_daily_limit
  `;
  const scansToday = parseInt((countRows[0] as any)?.count ?? "0", 10);
  const customLimit = (countRows[0] as any)?.custom_limit;
  const effectiveLimit =
    customLimit !== null && customLimit !== undefined
      ? parseInt(customLimit, 10)
      : FREE_TIER_DAILY_LIMIT;

  if (scansToday >= effectiveLimit) {
    return NextResponse.json(
      {
        error:
          `Rate limit reached: ${effectiveLimit} scans/day. ` +
          `Add GEMINI_API_KEY or GROQ_API_KEY to your repo secrets for unlimited scans.`,
        scans_today: scansToday,
        limit: effectiveLimit,
      },
      { status: 429 }
    );
  }

  // ── 3. Check platform keys are configured ─────────────────────────────
  const geminiKey = process.env.PLATFORM_GEMINI_API_KEY ?? "";
  const groqKeys = [
    process.env.PLATFORM_GROQ_API_KEY,
    process.env.PLATFORM_GROQ_API_KEY_2,
    process.env.PLATFORM_GROQ_API_KEY_3,
    process.env.PLATFORM_GROQ_API_KEY_4,
    process.env.PLATFORM_GROQ_API_KEY_5,
    process.env.PLATFORM_GROQ_API_KEY_6,
  ].filter(Boolean) as string[];

  if (groqKeys.length === 0) {
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
      ${JSON.stringify({ scans_today: scansToday, limit: effectiveLimit })}
    )
  `.catch(() => {});

  // ── 5. Return keys (expires in 10 minutes — enough for one scan) ───────
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  return NextResponse.json({
    gemini_key:  geminiKey || null,
    groq_keys:   groqKeys,
    expires_at:  expiresAt,
    scans_today: scansToday,
    limit:       effectiveLimit,
  });
}
