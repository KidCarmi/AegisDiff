/**
 * POST /api/ingest
 *
 * Receives scan metadata from GitHub Actions.
 * Stores only metadata — no code, no diffs, no evidence.
 *
 * Auth — two mechanisms accepted:
 *
 *   1. GitHub Actions OIDC JWT (zero-config, recommended)
 *      CI requests a JWT from GitHub with audience "aegisdiff".
 *      We verify it against GitHub's JWKS and extract the `repository`
 *      claim to identify the repo.  No secrets required in the target repo.
 *
 *   2. Per-repo Bearer token (legacy / manual-connect repos)
 *      SHA-256 hash of the token is compared against repos.token_hash.
 */
import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { sql } from "../../../lib/db";
import type { IngestPayload } from "../../../lib/types";

const ALLOWED_VERDICTS = new Set(["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ERROR"]);

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS = createRemoteJWKSet(
  new URL(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`),
);

/** Verify a GitHub Actions OIDC token. Returns "owner/name" or null. */
async function verifyOIDC(token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, GITHUB_JWKS, {
      issuer: GITHUB_OIDC_ISSUER,
      audience: "aegisdiff",
    });
    const repo = payload["repository"] as string | undefined;
    return repo ?? null;
  } catch {
    return null;
  }
}

export async function POST(req: NextRequest) {
  // ── Auth ──────────────────────────────────────────────────────────────────
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return NextResponse.json({ error: "Missing authorization" }, { status: 401 });
  }

  let repoId: number;

  // Try OIDC first (GitHub Actions zero-config path)
  const oidcRepo = await verifyOIDC(token);
  if (oidcRepo) {
    const [owner, name] = oidcRepo.split("/");
    const rows = await sql`
      SELECT id FROM repos WHERE owner = ${owner} AND name = ${name} LIMIT 1
    `;
    if (rows.length === 0) {
      // Repo not connected yet — auto-register it if it has a GitHub App installation
      const installRows = await sql`
        SELECT i.id FROM installations i
        WHERE i.account_login = ${owner} AND i.deleted_at IS NULL
        LIMIT 1
      `;
      if (installRows.length === 0) {
        return NextResponse.json({ error: "Repo not connected to AegisDiff" }, { status: 403 });
      }
      // Insert minimal repo row so scans can be stored
      const inserted = await sql`
        INSERT INTO repos (owner, name, token_hash)
        VALUES (${owner}, ${name}, ${"oidc-" + createHash("sha256").update(oidcRepo).digest("hex")})
        ON CONFLICT (owner, name) DO UPDATE SET owner = EXCLUDED.owner
        RETURNING id
      `;
      repoId = (inserted[0] as any).id as number;
    } else {
      repoId = (rows[0] as any).id as number;
    }
  } else {
    // Fall back to hashed per-repo token
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const rows = await sql`
      SELECT id FROM repos WHERE token_hash = ${tokenHash} LIMIT 1
    `;
    if (rows.length === 0) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }
    repoId = (rows[0] as any).id as number;
  }

  // ── Parse & validate payload ──────────────────────────────────────────────
  let payload: IngestPayload;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!ALLOWED_VERDICTS.has(payload.verdict)) {
    return NextResponse.json({ error: "Invalid verdict" }, { status: 400 });
  }

  if (!payload.commit_sha || typeof payload.commit_sha !== "string") {
    return NextResponse.json({ error: "Missing commit_sha" }, { status: 400 });
  }

  // Sanitize: confidence must be a finite number in [0, 1]
  const confidence =
    typeof payload.confidence === "number" && isFinite(payload.confidence)
      ? Math.max(0, Math.min(1, payload.confidence))
      : null;

  // Truncate title to 80 chars (no code content should slip through)
  const title = payload.title?.slice(0, 80) ?? null;

  // ── Insert scan record (metadata only, no code) ───────────────────────────
  await sql`
    INSERT INTO scans (
      repo_id, pr_number, commit_sha, pr_url,
      verdict, severity, cwe_id, confidence, title, provider, scan_ms
    ) VALUES (
      ${repoId},
      ${payload.pr_number ?? null},
      ${payload.commit_sha.slice(0, 40)},
      ${payload.pr_url ?? null},
      ${payload.verdict},
      ${payload.severity ?? null},
      ${payload.cwe_id ?? null},
      ${confidence},
      ${title},
      ${payload.provider ?? null},
      ${payload.scan_ms ?? null}
    )
  `;

  return NextResponse.json({ ok: true }, { status: 201 });
}
