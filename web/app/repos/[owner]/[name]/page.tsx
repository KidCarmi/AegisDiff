import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../../lib/auth";
import { sql } from "../../../../lib/db";
import { VerdictBadge } from "../../../../components/VerdictBadge";
import type { Scan } from "../../../../lib/types";

interface Props { params: { owner: string; name: string } }

async function getRepoStats(owner: string, name: string) {
  const rows = await sql`
    SELECT
      COUNT(*)                                              AS total,
      COUNT(*) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')  AS tp,
      COUNT(*) FILTER (WHERE s.verdict = 'FALSE_POSITIVE') AS fp,
      COUNT(*) FILTER (WHERE s.verdict = 'NEEDS_REVIEW')   AS nr,
      ROUND(AVG(s.confidence) * 100)                       AS avg_conf
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
      AND s.created_at > NOW() - INTERVAL '30 days'`;
  return rows[0] as any;
}

async function getTopCWEs(owner: string, name: string) {
  return sql`
    SELECT s.cwe_id, COUNT(*) AS cnt
    FROM scans s JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
      AND s.cwe_id IS NOT NULL AND s.cwe_id != 'N/A'
      AND s.verdict = 'TRUE_POSITIVE'
    GROUP BY s.cwe_id ORDER BY cnt DESC LIMIT 5`;
}

async function getRecentScans(owner: string, name: string): Promise<Scan[]> {
  return sql`
    SELECT s.id, r.owner AS "repoOwner", r.name AS "repoName",
      s.pr_number AS "prNumber", s.commit_sha AS "commitSha",
      s.pr_url AS "prUrl", s.verdict, s.severity, s.cwe_id AS "cweId",
      s.confidence, s.title, s.provider, s.scan_ms AS "scanMs",
      s.created_at AS "createdAt"
    FROM scans s JOIN repos r ON s.repo_id = r.id
    WHERE r.owner = ${owner} AND r.name = ${name}
    ORDER BY s.created_at DESC LIMIT 30` as unknown as Scan[];
}

async function getNotifySettings(owner: string, name: string) {
  const rows = await sql`
    SELECT notify_min_severity AS "minSeverity",
           notify_on_needs_review AS "notifyNeedsReview",
           auto_github_issue AS "autoGithubIssue",
           slack_webhook_url IS NOT NULL AS "slackOn",
           discord_webhook_url IS NOT NULL AS "discordOn",
           teams_webhook_url IS NOT NULL AS "teamsOn"
    FROM repos WHERE owner = ${owner} AND name = ${name} LIMIT 1`;
  return rows[0] as any ?? {};
}

function timeAgo(d: string) {
  const m = Math.floor((Date.now() - new Date(d).getTime()) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "text-red-700 font-bold", HIGH: "text-orange-600 font-semibold",
  MEDIUM: "text-yellow-600", LOW: "text-blue-600", INFO: "text-gray-400",
};

export default async function RepoDetailPage({ params }: Props) {
  const { owner, name } = params;
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const accessToken = (session.user as any).accessToken as string;
  const ok = await verifyRepoAccess(accessToken, owner, name);
  if (!ok) notFound();

  const [stats, cwes, scans, notify] = await Promise.all([
    getRepoStats(owner, name),
    getTopCWEs(owner, name),
    getRecentScans(owner, name),
    getNotifySettings(owner, name),
  ]);

  const statCards = [
    { label: "Total Scans (30d)", value: stats?.total ?? "0", color: "text-gray-900" },
    { label: "True Positives", value: stats?.tp ?? "0", color: "text-red-600" },
    { label: "False Positives", value: stats?.fp ?? "0", color: "text-green-600" },
    { label: "Avg Confidence", value: stats?.avg_conf ? `${stats.avg_conf}%` : "—", color: "text-blue-600" },
  ];

  const integrations = [
    { label: "Slack", icon: "💬", on: notify.slackOn, href: `slack` },
    { label: "Discord", icon: "🎮", on: notify.discordOn, href: `discord` },
    { label: "MS Teams", icon: "🟦", on: notify.teamsOn, href: `teams` },
    { label: "GitHub Issues", icon: "🐛", on: notify.autoGithubIssue, href: `notify` },
    { label: "Thresholds", icon: "🔔", on: false, href: `notify` },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <a href="/repos" className="text-sm text-blue-600 hover:underline">← Repos</a>
          <h1 className="mt-1 text-2xl font-bold text-gray-900 font-mono">{owner}/{name}</h1>
          <p className="text-sm text-gray-500 mt-0.5">Last 30 days · {scans.length} recent scans</p>
        </div>
        <div className="flex gap-2">
          <a href={`https://github.com/${owner}/${name}`} target="_blank" rel="noopener noreferrer"
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50">
            GitHub ↗
          </a>
          <a href={`/api/scans/export?repo=${owner}/${name}`}
            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50" download>
            ↓ Export CSV
          </a>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {statCards.map((s) => (
          <div key={s.label} className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Recent scans */}
        <div className="lg:col-span-2 space-y-2">
          <h2 className="text-base font-semibold text-gray-800">Recent Scans</h2>
          {scans.length === 0 ? (
            <div className="rounded-lg border border-dashed border-gray-200 p-8 text-center">
              <p className="text-sm text-gray-400">No scans yet — open a pull request.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {scans.map((s) => (
                <a key={s.id} href={`/scans/${s.id}`} className="block rounded-xl border border-gray-200 bg-white px-4 py-3 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 text-xs text-gray-400">
                        {s.prNumber && <span>PR #{s.prNumber}</span>}
                        <span className="font-mono">{s.commitSha.slice(0, 7)}</span>
                        <span>·</span>
                        <span>{timeAgo(s.createdAt)}</span>
                      </div>
                      {s.title && <p className="text-sm text-gray-800 font-medium truncate mt-0.5">{s.title}</p>}
                      <div className="flex gap-2 mt-1 text-xs">
                        {s.severity && s.severity !== "N/A" && (
                          <span className={SEV_COLOR[s.severity] ?? "text-gray-400"}>{s.severity}</span>
                        )}
                        {s.cweId && s.cweId !== "N/A" && (
                          <span className="font-mono bg-gray-100 px-1 rounded">{s.cweId}</span>
                        )}
                      </div>
                    </div>
                    <VerdictBadge verdict={s.verdict} />
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Top CWEs */}
          {(cwes as any[]).length > 0 && (
            <div className="rounded-xl border border-gray-200 bg-white p-4">
              <h3 className="text-sm font-semibold text-gray-700 mb-3">Top CWEs (all-time)</h3>
              <div className="space-y-2">
                {(cwes as any[]).map((c) => (
                  <div key={c.cwe_id} className="flex items-center justify-between">
                    <span className="font-mono text-xs text-gray-700">{c.cwe_id}</span>
                    <span className="text-xs text-red-600 font-semibold">{c.cnt}×</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Integrations */}
          <div className="rounded-xl border border-gray-200 bg-white p-4">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Notifications</h3>
            <div className="space-y-1.5">
              {integrations.map((i) => (
                <a key={i.label} href={`/repos/${owner}/${name}/${i.href}`}
                  className="flex items-center justify-between rounded-lg px-3 py-2 hover:bg-gray-50 transition-colors">
                  <span className="flex items-center gap-2 text-sm text-gray-700">
                    <span>{i.icon}</span>{i.label}
                  </span>
                  {i.on
                    ? <span className="text-xs text-green-600 font-medium">✓ On</span>
                    : <span className="text-xs text-gray-400">Configure →</span>
                  }
                </a>
              ))}
            </div>
          </div>

          {/* Badge */}
          <div className="rounded-xl border border-gray-200 bg-white p-4">
            <h3 className="text-sm font-semibold text-gray-700 mb-2">README Badge</h3>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={`/api/badge/${owner}/${name}`} alt="AegisDiff badge" className="mb-2" />
            <pre className="text-[10px] text-gray-500 bg-gray-50 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
              {`[![AegisDiff](/api/badge/${owner}/${name})](https://aegis-diff.vercel.app/repos/${owner}/${name})`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
