/**
 * GET /api/cron/weekly-digest
 *
 * Vercel Cron job — fires every Monday at 09:00 UTC.
 * Sends a weekly security digest to all repos with configured webhooks
 * (Slack, Discord, or MS Teams).
 *
 * Protected by the CRON_SECRET environment variable set by Vercel.
 * Vercel automatically adds the Authorization header on cron invocations.
 *
 * See: https://vercel.com/docs/cron-jobs/manage-cron-jobs
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../../lib/db";

// Severity ordering for summary display
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

interface RepoDigest {
  owner: string;
  name: string;
  slack_webhook_url: string | null;
  discord_webhook_url: string | null;
  teams_webhook_url: string | null;
  total: number;
  true_positives: number;
  needs_review: number;
  false_positives: number;
  top_cwe: string | null;
  top_severity: string | null;
  sla_breaches: number;
}

async function buildDigests(): Promise<RepoDigest[]> {
  const rows = await sql`
    SELECT
      r.owner,
      r.name,
      r.slack_webhook_url,
      r.discord_webhook_url,
      r.teams_webhook_url,
      COUNT(s.id)                                                    AS total,
      COUNT(s.id) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')         AS true_positives,
      COUNT(s.id) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')          AS needs_review,
      COUNT(s.id) FILTER (WHERE s.verdict = 'FALSE_POSITIVE')        AS false_positives,
      -- Top CWE by TRUE_POSITIVE count
      (
        SELECT s2.cwe_id FROM scans s2
        WHERE s2.repo_id = r.id
          AND s2.verdict = 'TRUE_POSITIVE'
          AND s2.created_at > NOW() - INTERVAL '7 days'
          AND s2.cwe_id IS NOT NULL AND s2.cwe_id != 'N/A'
        GROUP BY s2.cwe_id ORDER BY COUNT(*) DESC LIMIT 1
      ) AS top_cwe,
      -- Highest severity seen
      (
        SELECT s3.severity FROM scans s3
        WHERE s3.repo_id = r.id
          AND s3.verdict = 'TRUE_POSITIVE'
          AND s3.created_at > NOW() - INTERVAL '7 days'
          AND s3.severity IS NOT NULL
        ORDER BY CASE s3.severity
          WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
          WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC
        LIMIT 1
      ) AS top_severity,
      -- SLA breaches: CRITICAL/HIGH TRUE_POSITIVE > 7 days, not dismissed
      (
        SELECT COUNT(*) FROM scans sb
        WHERE sb.repo_id = r.id
          AND sb.verdict = 'TRUE_POSITIVE'
          AND sb.severity IN ('CRITICAL', 'HIGH')
          AND sb.created_at < NOW() - INTERVAL '7 days'
          AND NOT EXISTS (
            SELECT 1 FROM scan_feedback sf
            WHERE sf.scan_id = sb.id AND sf.correct_verdict = 'FALSE_POSITIVE'
          )
      ) AS sla_breaches
    FROM repos r
    LEFT JOIN scans s ON s.repo_id = r.id
      AND s.created_at > NOW() - INTERVAL '7 days'
    WHERE
      r.deleted_at IS NULL
      AND (
        r.slack_webhook_url IS NOT NULL
        OR r.discord_webhook_url IS NOT NULL
        OR r.teams_webhook_url IS NOT NULL
      )
    GROUP BY r.id, r.owner, r.name,
             r.slack_webhook_url, r.discord_webhook_url, r.teams_webhook_url
    HAVING COUNT(s.id) > 0
       OR (
         SELECT COUNT(*) FROM scans sb2
         WHERE sb2.repo_id = r.id
           AND sb2.verdict = 'TRUE_POSITIVE'
           AND sb2.severity IN ('CRITICAL', 'HIGH')
           AND sb2.created_at < NOW() - INTERVAL '7 days'
           AND NOT EXISTS (
             SELECT 1 FROM scan_feedback sf2
             WHERE sf2.scan_id = sb2.id AND sf2.correct_verdict = 'FALSE_POSITIVE'
           )
       ) > 0
  `;

  return rows.map((r: any) => ({
    ...r,
    total: parseInt(r.total, 10),
    true_positives: parseInt(r.true_positives, 10),
    needs_review: parseInt(r.needs_review, 10),
    false_positives: parseInt(r.false_positives, 10),
    sla_breaches: parseInt(r.sla_breaches, 10),
  }));
}

const BASE_URL = (process.env.NEXTAUTH_URL ?? "https://aegis-diff.vercel.app").replace(/\/$/, "");

function buildSlackPayload(d: RepoDigest): object {
  const repoSlug = `${d.owner}/${d.name}`;
  const dashUrl = `${BASE_URL}/repos/${d.owner}/${d.name}`;
  const slaBlock = d.sla_breaches > 0
    ? `\n:rotating_light: *${d.sla_breaches} CRITICAL/HIGH finding${d.sla_breaches > 1 ? "s" : ""} unresolved >7 days*`
    : "";

  return {
    text: `AegisDiff Weekly Digest — ${repoSlug}`,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `AegisDiff Weekly Digest — ${repoSlug}` },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: [
            `*Last 7 days:*`,
            `• ${d.true_positives} true positive${d.true_positives !== 1 ? "s" : ""}`,
            `• ${d.needs_review} need${d.needs_review !== 1 ? "" : "s"} review`,
            `• ${d.false_positives} false positive${d.false_positives !== 1 ? "s" : ""}`,
            d.top_cwe ? `• Top vulnerability: ${d.top_cwe} (${d.top_severity ?? "unknown"})` : null,
            slaBlock,
          ].filter(Boolean).join("\n"),
        },
        accessory: {
          type: "button",
          text: { type: "plain_text", text: "View Dashboard" },
          url: dashUrl,
        },
      },
    ],
  };
}

function buildDiscordPayload(d: RepoDigest): object {
  const repoSlug = `${d.owner}/${d.name}`;
  const dashUrl = `${BASE_URL}/repos/${d.owner}/${d.name}`;
  const color = d.sla_breaches > 0 ? 0xff0000 : d.true_positives > 0 ? 0xfbbf24 : 0x4ade80;

  const lines = [
    `**Last 7 days**`,
    `• ${d.true_positives} true positives`,
    `• ${d.needs_review} needs review`,
    `• ${d.false_positives} false positives`,
  ];
  if (d.top_cwe) lines.push(`• Top: ${d.top_cwe} (${d.top_severity})`);
  if (d.sla_breaches > 0) {
    lines.push(`\n🚨 **${d.sla_breaches} CRITICAL/HIGH unresolved >7 days**`);
  }

  return {
    embeds: [
      {
        title: `AegisDiff Weekly Digest — ${repoSlug}`,
        url: dashUrl,
        color,
        description: lines.join("\n"),
        footer: { text: `AegisDiff • ${BASE_URL.replace(/^https?:\/\//, "")}` },
      },
    ],
  };
}

function buildTeamsPayload(d: RepoDigest): object {
  const repoSlug = `${d.owner}/${d.name}`;
  const dashUrl = `${BASE_URL}/repos/${d.owner}/${d.name}`;

  const facts = [
    { name: "True Positives", value: String(d.true_positives) },
    { name: "Needs Review", value: String(d.needs_review) },
    { name: "False Positives", value: String(d.false_positives) },
  ];
  if (d.top_cwe) facts.push({ name: "Top Vulnerability", value: `${d.top_cwe} (${d.top_severity})` });
  if (d.sla_breaches > 0) facts.push({ name: "SLA Breaches", value: `${d.sla_breaches} unresolved >7 days` });

  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: d.sla_breaches > 0 ? "FF0000" : "fbbf24",
    summary: `AegisDiff Weekly Digest — ${repoSlug}`,
    sections: [
      {
        activityTitle: `AegisDiff Weekly Digest`,
        activitySubtitle: repoSlug,
        facts,
        potentialAction: [
          {
            "@type": "OpenUri",
            name: "View Dashboard",
            targets: [{ os: "default", uri: dashUrl }],
          },
        ],
      },
    ],
  };
}

async function fireWebhook(url: string, payload: object): Promise<boolean> {
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

export async function GET(req: NextRequest) {
  // Verify Vercel Cron secret
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const authHeader = req.headers.get("authorization");
    if (authHeader !== `Bearer ${cronSecret}`) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
  }

  try {
    const digests = await buildDigests();

    let fired = 0;
    let errors = 0;

    for (const digest of digests) {
      const jobs: Promise<boolean>[] = [];

      if (digest.slack_webhook_url) {
        jobs.push(fireWebhook(digest.slack_webhook_url, buildSlackPayload(digest)));
      }
      if (digest.discord_webhook_url) {
        jobs.push(fireWebhook(digest.discord_webhook_url, buildDiscordPayload(digest)));
      }
      if (digest.teams_webhook_url) {
        jobs.push(fireWebhook(digest.teams_webhook_url, buildTeamsPayload(digest)));
      }

      const results = await Promise.all(jobs);
      fired += results.filter(Boolean).length;
      errors += results.filter((r) => !r).length;
    }

    console.log(
      `[weekly-digest] Sent digests for ${digests.length} repos — ` +
      `${fired} webhooks fired, ${errors} failed`
    );

    return NextResponse.json({
      ok: true,
      repos: digests.length,
      webhooks_fired: fired,
      errors,
    });
  } catch (err: any) {
    console.error("[weekly-digest] Error:", err);
    return NextResponse.json({ error: err?.message ?? "Internal error" }, { status: 500 });
  }
}
