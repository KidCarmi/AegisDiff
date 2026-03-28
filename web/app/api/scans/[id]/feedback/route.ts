/**
 * POST /api/scans/[id]/feedback
 *
 * Records a developer verdict correction for a scan.
 * - Requires repo:developer or higher role for the repo that owns the scan.
 * - If correcting a TRUE_POSITIVE → auto-upserts an ignore rule.
 * - All corrections are written to audit_log.
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../lib/auth";
import { requireRepoRole } from "../../../../../lib/rbac";
import { sql } from "../../../../../lib/db";
import type { VerdictType } from "../../../../../lib/types";

const VALID_VERDICTS: VerdictType[] = [
  "TRUE_POSITIVE",
  "FALSE_POSITIVE",
  "NEEDS_REVIEW",
  "ERROR",
];

export async function POST(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const scanId = params.id;
    // Basic UUID format check
    if (!/^[0-9a-f-]{36}$/.test(scanId)) {
      return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 });
    }

    const body = await req.json().catch(() => null);
    const correct_verdict: VerdictType = body?.correct_verdict;
    const reason: string | undefined = typeof body?.reason === "string" ? body.reason : undefined;

    if (!correct_verdict || !VALID_VERDICTS.includes(correct_verdict)) {
      return NextResponse.json(
        { error: "correct_verdict must be one of: " + VALID_VERDICTS.join(", ") },
        { status: 400 }
      );
    }

    // Look up the scan + its repo to enforce RBAC
    const scanRows = await sql`
      SELECT
        s.id,
        s.verdict     AS original_verdict,
        s.cwe_id,
        s.title,
        r.owner       AS repo_owner,
        r.name        AS repo_name,
        r.id          AS repo_id
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      WHERE s.id = ${scanId}
      LIMIT 1
    `;

    if (!scanRows.length) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const scan = scanRows[0] as any;
    const { repo_owner, repo_name, repo_id, original_verdict, cwe_id, title } = scan;

    // Enforce repo:developer minimum role
    try {
      await requireRepoRole(session, repo_owner, repo_name, "repo:developer");
    } catch (r) {
      return r as Response;
    }

    const githubId = (session.user as any).githubId as number;

    // Upsert feedback — one correction per (scan_id, github_id); later submissions win
    await sql`
      INSERT INTO scan_feedback (scan_id, github_id, correct_verdict, reason)
      VALUES (${scanId}, ${githubId}, ${correct_verdict}, ${reason ?? null})
      ON CONFLICT (scan_id, github_id)
      DO UPDATE SET
        correct_verdict = EXCLUDED.correct_verdict,
        reason          = EXCLUDED.reason,
        created_at      = NOW()
    `;

    // If a TRUE_POSITIVE is corrected to FALSE_POSITIVE → auto-add ignore rule
    if (original_verdict === "TRUE_POSITIVE" && correct_verdict === "FALSE_POSITIVE") {
      if (cwe_id && cwe_id !== "N/A") {
        await sql`
          INSERT INTO ignore_rules (repo_id, cwe_id, reason)
          VALUES (${repo_id}, ${cwe_id}, ${reason ?? "Marked false positive via feedback"})
          ON CONFLICT DO NOTHING
        `;
      } else if (title) {
        // Fall back to title keyword suppression
        await sql`
          INSERT INTO ignore_rules (repo_id, title_keyword, reason)
          VALUES (${repo_id}, ${title}, ${reason ?? "Marked false positive via feedback"})
          ON CONFLICT DO NOTHING
        `;
      }
    }

    // Audit log
    await sql`
      INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
      VALUES (
        ${githubId},
        'scan_feedback',
        ${repo_owner},
        ${repo_name},
        ${JSON.stringify({ scan_id: scanId, original_verdict, correct_verdict, reason: reason ?? null })}
      )
    `;

    return NextResponse.json({ ok: true });
  } catch (err: any) {
    console.error("[feedback] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
