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
 * Limit:  FREE_TIER_DAILY_LIMIT scans per repo per 24 h
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

  // ── 2. Rate limit — count scans for this repo in the last 24 hours ─────
  const countRows = await sql`
    SELECT COUNT(*) AS count
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${owner}
      AND r.name  = ${name}
      AND s.created_at > NOW() - INTERVAL '24 hours'
  `;
  const scansToday = parseInt((countRows[0] as any)?.count ?? "0", 10);

  if (scansToday >= FREE_TIER_DAILY_LIMIT) {
    return NextResponse.json(
      {
        error:
          `Rate limit reached: ${FREE_TIER_DAILY_LIMIT} scans/day on the free tier. ` +
          `Add GEMINI_API_KEY or GROQ_API_KEY to your repo secrets for unlimited scans.`,
        scans_today: scansToday,
        limit: FREE_TIER_DAILY_LIMIT,
      },
      { status: 429 }
    );
  }

  // ── 3. Check platform keys are configured ─────────────────────────────
  const geminiKey = process.env.PLATFORM_GEMINI_API_KEY ?? "";
  const groqKey   = process.env.PLATFORM_GROQ_API_KEY   ?? "";

  if (!geminiKey && !groqKey) {
    return NextResponse.json(
      { error: "Platform AI keys not configured — contact support." },
      { status: 503 }
    );
  }

  // ── 4. Audit log ───────────────────────────────────────────────────────
  // Non-fatal — don't let a logging failure block the response
  sql`
    INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
    VALUES (
      0,
      'llm_key_issued',
      ${owner},
      ${name},
      ${JSON.stringify({ scans_today: scansToday, limit: FREE_TIER_DAILY_LIMIT })}
    )
  `.catch(() => {});

  // ── 5. Return keys (expires in 10 minutes — enough for one scan) ───────
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  return NextResponse.json({
    gemini_key:   geminiKey || null,
    groq_key:     groqKey   || null,
    expires_at:   expiresAt,
    scans_today:  scansToday,
    limit:        FREE_TIER_DAILY_LIMIT,
  });
}
