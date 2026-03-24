import { getServerSession } from "next-auth/next";
import { redirect, notFound } from "next/navigation";
import { authOptions, verifyRepoAccess } from "../../../lib/auth";
import { sql } from "../../../lib/db";
import { VerdictBadge } from "../../../components/VerdictBadge";
import type { Scan } from "../../../lib/types";

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

interface Props {
  params: { id: string };
}

export default async function ScanDetailPage({ params }: Props) {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";
  const scan = await getScan(params.id, githubId, username);
  if (!scan) notFound();

  const sha = scan.commitSha.slice(0, 7);
  const repoSlug = `${scan.repoOwner}/${scan.repoName}`;

  return (
    <div className="max-w-2xl">
      <div className="mb-6">
        <a href="/dashboard" className="text-sm text-blue-600 hover:underline">← Dashboard</a>
      </div>

      <h1 className="text-xl font-bold text-gray-900 mb-1">Scan Detail</h1>
      <p className="text-sm text-gray-500 mb-6">
        <span className="font-mono">{repoSlug}</span>
        {scan.prNumber && ` · PR #${scan.prNumber}`}
        {" · "}<span className="font-mono">{sha}</span>
      </p>

      <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <VerdictBadge verdict={scan.verdict} />
          {scan.confidence != null && (
            <span className="text-sm text-gray-500">
              {Math.round(scan.confidence * 100)}% confidence
            </span>
          )}
        </div>

        {scan.title && (
          <p className="font-semibold text-gray-900">{scan.title}</p>
        )}

        <table className="w-full text-sm text-left">
          <tbody className="divide-y divide-gray-100">
            {[
              ["Severity", scan.severity ?? "N/A"],
              ["CWE", scan.cweId ?? "N/A"],
              ["Analyzed by", scan.provider ?? "unknown"],
              ["Scan duration", scan.scanMs != null ? `${scan.scanMs}ms` : "—"],
              ["Timestamp", new Date(scan.createdAt).toLocaleString()],
            ].map(([label, value]) => (
              <tr key={label}>
                <td className="py-2 pr-4 font-medium text-gray-500">{label}</td>
                <td className="py-2 font-mono text-gray-900">{value}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {scan.prUrl && (
          <div className="pt-2 border-t border-gray-100">
            <a
              href={scan.prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700"
            >
              View full evidence on GitHub →
            </a>
            <p className="mt-2 text-xs text-gray-400">
              Evidence (code quotes) is only stored in the GitHub PR comment — never in our database.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
