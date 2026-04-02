import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions } from "../../../lib/auth";
import { sql } from "../../../lib/db";
import { VerdictBadge } from "../../../components/VerdictBadge";
import { RescanButton } from "../../../components/RescanButton";
import { SEVERITY_COLORS } from "../../../lib/types";
import type { Scan } from "../../../lib/types";
import { hasMinRole, resolveRole } from "../../../lib/rbac";

async function getScan(id: string, githubId: number, username: string): Promise<Scan | null> {
  const rows = await sql`
    SELECT
      s.id,
      r.owner  AS "repoOwner",
      r.name   AS "repoName",
      s.pr_number    AS "prNumber",
      s.commit_sha   AS "commitSha",
      s.pr_url       AS "prUrl",
      s.verdict,
      s.severity,
      s.cwe_id       AS "cweId",
      s.confidence,
      s.title,
      s.provider,
      s.scan_ms      AS "scanMs",
      s.created_at   AS "createdAt"
    FROM scans s
    JOIN repos r ON s.repo_id = r.id
    WHERE s.id = ${id}
      AND (
        r.id IN (
          SELECT r2.id FROM repos r2
          JOIN users u ON r2.user_id = u.id
          WHERE u.github_id = ${githubId}
        )
        OR (r.installation_id IS NOT NULL AND r.owner = ${username})
      )
    LIMIT 1
  `;
  return (rows[0] as unknown as Scan) ?? null;
}

function confidenceClass(conf: number): string {
  if (conf >= 0.9) return "bg-green-100 text-green-800";
  if (conf >= 0.7) return "bg-yellow-100 text-yellow-800";
  if (conf >= 0.5) return "bg-orange-100 text-orange-800";
  return "bg-red-100 text-red-800";
}

function confidenceLabel(conf: number): string {
  if (conf >= 0.9) return "Very High";
  if (conf >= 0.7) return "High";
  if (conf >= 0.5) return "Medium";
  return "Low";
}

interface Props {
  params: Promise<{ id: string }>;
}

export default async function ScanDetailPage({ params }: Props) {
  const { id } = await params;
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const accessToken = (session.user as any).accessToken as string;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";
  const scan = await getScan(id, githubId, username);
  if (!scan) notFound();

  // Resolve whether user can trigger rescan (repo:developer+)
  const role = await resolveRole(githubId, accessToken, scan.repoOwner, scan.repoName).catch(() => null);
  const canRescan = hasMinRole(role, "repo:developer") && !!scan.prNumber;

  const sha = scan.commitSha.slice(0, 7);
  const repoSlug = `${scan.repoOwner}/${scan.repoName}`;
  const severityClass = SEVERITY_COLORS[scan.severity ?? "N/A"] ?? "text-gray-400";
  const cweNum = scan.cweId?.match(/\d+/)?.[0];

  return (
    <div className="max-w-2xl">
      <div className="mb-6">
        <a href="/dashboard" className="text-sm text-blue-600 hover:underline">← Dashboard</a>
      </div>

      <div className="flex items-start justify-between gap-4 mb-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-gray-900 dark:text-gray-50 mb-1">Scan Detail</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            <span className="font-mono">{repoSlug}</span>
            {scan.prNumber && (
              scan.prUrl ? (
                <> · <a href={scan.prUrl} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">PR #{scan.prNumber}</a></>
              ) : (
                <> · PR #{scan.prNumber}</>
              )
            )}
            {" · "}<span className="font-mono">{sha}</span>
          </p>
        </div>
        {/* Phase 6 — Re-scan button */}
        {canRescan && <RescanButton scanId={scan.id} />}
      </div>

      <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6 shadow-sm space-y-5">
        {/* Verdict + confidence */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <VerdictBadge verdict={scan.verdict} />
          {scan.confidence != null && (
            <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium ${confidenceClass(scan.confidence)}`}>
              {Math.round(scan.confidence * 100)}% confidence
              <span className="text-xs opacity-70">({confidenceLabel(scan.confidence)})</span>
            </span>
          )}
        </div>

        {/* Title */}
        {scan.title && (
          <p className="font-semibold text-gray-900 dark:text-gray-50 text-base">{scan.title}</p>
        )}

        {/* Meta table */}
        <table className="w-full text-sm text-left">
          <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
            {scan.severity && (
              <tr>
                <td className="py-2 pr-4 font-medium text-gray-500 dark:text-gray-400 w-36">Severity</td>
                <td className={`py-2 font-semibold ${severityClass}`}>{scan.severity}</td>
              </tr>
            )}
            {scan.cweId && scan.cweId !== "N/A" && (
              <tr>
                <td className="py-2 pr-4 font-medium text-gray-500 dark:text-gray-400">CWE</td>
                <td className="py-2">
                  {cweNum ? (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-blue-600 hover:underline"
                    >
                      {scan.cweId} ↗
                    </a>
                  ) : (
                    <span className="font-mono text-gray-900 dark:text-gray-50">{scan.cweId}</span>
                  )}
                </td>
              </tr>
            )}
            <tr>
              <td className="py-2 pr-4 font-medium text-gray-500 dark:text-gray-400">Analyzed by</td>
              <td className="py-2 font-mono text-gray-900 dark:text-gray-50 capitalize">{scan.provider ?? "unknown"}</td>
            </tr>
            {scan.scanMs != null && (
              <tr>
                <td className="py-2 pr-4 font-medium text-gray-500 dark:text-gray-400">Scan duration</td>
                <td className="py-2 font-mono text-gray-900 dark:text-gray-50">{scan.scanMs}ms</td>
              </tr>
            )}
            <tr>
              <td className="py-2 pr-4 font-medium text-gray-500 dark:text-gray-400">Timestamp</td>
              <td className="py-2 text-gray-900 dark:text-gray-50">{new Date(scan.createdAt).toLocaleString()}</td>
            </tr>
          </tbody>
        </table>

        {/* Evidence link */}
        {scan.prUrl && (
          <div className="pt-2 border-t border-gray-100 dark:border-gray-800 space-y-2">
            <a
              href={scan.prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-gray-900 dark:bg-gray-100 px-4 py-2 text-sm font-medium text-white dark:text-gray-900 hover:bg-gray-700 dark:hover:bg-gray-200 transition-colors"
            >
              View evidence & full analysis on GitHub →
            </a>
            <p className="text-xs text-gray-400 dark:text-gray-500">
              Code quotes and remediation guidance are in the GitHub PR comment.
              They are never stored in this database.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
