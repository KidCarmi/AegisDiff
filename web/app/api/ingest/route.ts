/**
 * POST /api/ingest
 *
 * Receives scan metadata from GitHub Actions.
 * Authenticated via AEGISDIFF_REPO_TOKEN (per-repo Bearer token).
 * Stores only metadata — no code, no diffs, no evidence.
 */
import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { sql } from "../../../lib/db";
import type { IngestPayload } from "../../../lib/types";

const ALLOWED_VERDICTS = new Set(["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "ERROR"]);
const ALLOWED_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "N/A", null, undefined]);

export async function POST(req: NextRequest) {
  // ── Auth ──────────────────────────────────────────────────────────────────
  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return NextResponse.json({ error: "Missing authorization" }, { status: 401 });
  }

  // Look up repo by hashed token
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const repoRows = await sql`
    SELECT id FROM repos WHERE token_hash = ${tokenHash} LIMIT 1
  `;

  if (repoRows.length === 0) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }
  const repoId = (repoRows[0] as any).id as number;

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
