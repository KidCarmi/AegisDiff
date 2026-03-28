/**
 * POST /api/scans/[id]/rescan
 *
 * Trigger a fresh analysis for the same PR without needing a new commit.
 * Rate-limited to 3 rescans per PR per hour.
 *
 * Phase 6 — Re-scan on Demand
 */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "../../../../../lib/auth";
import { requireRepoRole } from "../../../../../lib/rbac";
import { sql } from "../../../../../lib/db";
import { createHmac } from "crypto";
import { generateAppJWT, getInstallationToken } from "../../../../../lib/github-app";

const MAX_RESCANS_PER_HOUR = 3;

function deriveRepoToken(repoSlug: string): string {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!secret) throw new Error("GITHUB_APP_WEBHOOK_SECRET is not set — cannot derive repo token");
  return createHmac("sha256", secret).update(repoSlug).digest("hex");
}

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
    if (!/^[0-9a-f-]{36}$/.test(scanId)) {
      return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 });
    }

    // Look up the scan to get repo + PR context
    const scanRows = await sql`
      SELECT
        s.id,
        s.pr_number,
        s.commit_sha,
        r.owner,
        r.name,
        r.installation_id
      FROM scans s
      JOIN repos r ON s.repo_id = r.id
      WHERE s.id = ${scanId}
      LIMIT 1
    `;

    if (!scanRows.length) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const scan = scanRows[0] as any;
    const { owner, name, pr_number, commit_sha, installation_id } = scan;

    if (!pr_number) {
      return NextResponse.json(
        { error: "Cannot rescan — no PR number associated with this scan" },
        { status: 400 }
      );
    }

    // Require repo:developer or higher
    try {
      await requireRepoRole(session, owner, name, "repo:developer");
    } catch (r) {
      return r as Response;
    }

    const githubId = (session.user as any).githubId as number;
    const repo = `${owner}/${name}`;

    // Rate-limit: max 3 rescans per PR per hour
    const recentRescans = await sql`
      SELECT COUNT(*) AS cnt
      FROM audit_log
      WHERE action = 'rescan_triggered'
        AND repo_owner = ${owner}
        AND repo_name  = ${name}
        AND (details->>'pr_number')::int = ${pr_number}
        AND created_at > NOW() - INTERVAL '1 hour'
    `;
    const cnt = Number((recentRescans[0] as any).cnt);
    if (cnt >= MAX_RESCANS_PER_HOUR) {
      return NextResponse.json(
        { error: `Rate limit: max ${MAX_RESCANS_PER_HOUR} rescans per PR per hour` },
        { status: 429 }
      );
    }

    // Trigger repository_dispatch on the engine repo
    const engineToken = process.env.AEGISDIFF_ENGINE_TOKEN;
    const engineRepo = process.env.AEGISDIFF_ENGINE_REPO ?? "KidCarmi/AegisDiff";
    const ingestUrl = process.env.AEGISDIFF_INGEST_URL;

    if (!engineToken) {
      return NextResponse.json(
        { error: "Rescan not available — engine token not configured" },
        { status: 503 }
      );
    }

    const ingestToken = deriveRepoToken(repo);

    // Fetch current PR HEAD SHA — the stored commit_sha may be stale if the
    // PR received new commits since the original scan.
    let headSha = commit_sha;
    if (installation_id) {
      try {
        const jwt = await generateAppJWT();
        const installToken = await getInstallationToken(jwt, installation_id);
        const prResp = await fetch(
          `https://api.github.com/repos/${owner}/${name}/pulls/${pr_number}`,
          {
            headers: {
              Authorization: `Bearer ${installToken}`,
              Accept: "application/vnd.github+json",
            },
          }
        );
        if (prResp.ok) {
          const prData = await prResp.json();
          headSha = prData.head?.sha ?? commit_sha;
        }
      } catch {
        // Non-fatal — fall back to stored SHA
      }
    }

    const dispatchResp = await fetch(
      `https://api.github.com/repos/${engineRepo}/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${engineToken}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          event_type: "analyze_pr",
          client_payload: {
            installation_id: installation_id,
            repo,
            pr_number,
            head_sha: headSha,
            ingest_url: ingestUrl,
            ingest_token: ingestToken,
          },
        }),
      }
    );

    if (!dispatchResp.ok) {
      const text = await dispatchResp.text().catch(() => "");
      console.error(`[rescan] dispatch failed (${dispatchResp.status}): ${text}`);
      return NextResponse.json({ error: "Failed to queue rescan" }, { status: 502 });
    }

    // Audit log
    await sql`
      INSERT INTO audit_log (github_id, action, repo_owner, repo_name, details)
      VALUES (
        ${githubId},
        'rescan_triggered',
        ${owner},
        ${name},
        ${JSON.stringify({ scan_id: scanId, pr_number, head_sha: headSha })}
      )
    `;

    return NextResponse.json({ ok: true, message: "Re-scan queued — results in ~90s" });
  } catch (err: any) {
    console.error("[rescan] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
