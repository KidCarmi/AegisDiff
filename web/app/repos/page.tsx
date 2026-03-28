import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { RepoSetup } from "./RepoSetup";
import { SyncButton } from "./SyncButton";

interface RepoRow {
  id: number;
  owner: string;
  name: string;
  createdAt: string;
  appInstalled: boolean;
  totalScans: string;
  truePositives: string;
  lastScanAt: string | null;
}

/** Security score 0–100: penalises TPs, rewards clean scans. */
function securityScore(total: number, tp: number): number | null {
  if (total === 0) return null;
  const tpRate = tp / total;
  return Math.max(0, Math.round(100 - tpRate * 100));
}

function scoreColor(score: number) {
  if (score >= 80) return "text-green-600";
  if (score >= 50) return "text-yellow-600";
  return "text-red-600";
}

async function getRepos(githubId: number, username: string): Promise<RepoRow[]> {
  const owned = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           (r.installation_id IS NOT NULL) AS "appInstalled",
           COUNT(s.id)::text AS "totalScans",
           COUNT(s.id) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')::text AS "truePositives",
           MAX(s.created_at)::text AS "lastScanAt"
    FROM repos r
    JOIN users u ON r.user_id = u.id
    LEFT JOIN scans s ON s.repo_id = r.id AND s.created_at > NOW() - INTERVAL '30 days'
    WHERE u.github_id = ${githubId}
    GROUP BY r.id ORDER BY r.created_at DESC`;

  // App-installed repos: match via installations table so org installs
  // (where r.owner = orgName ≠ username) are included too.
  const appRepos = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           TRUE AS "appInstalled",
           COUNT(s.id)::text AS "totalScans",
           COUNT(s.id) FILTER (WHERE s.verdict = 'TRUE_POSITIVE')::text AS "truePositives",
           MAX(s.created_at)::text AS "lastScanAt"
    FROM repos r
    JOIN installations i ON i.installation_id = r.installation_id
    LEFT JOIN scans s ON s.repo_id = r.id AND s.created_at > NOW() - INTERVAL '30 days'
    WHERE r.installation_id IS NOT NULL
      AND r.user_id IS NULL
      AND i.deleted_at IS NULL
      AND (i.account_login = ${username} OR r.owner = ${username})
    GROUP BY r.id ORDER BY r.created_at DESC`;

  const seen = new Map<string, number>(); // key → index in merged
  const merged: RepoRow[] = [];
  for (const r of [...(owned as any[]), ...(appRepos as any[])]) {
    const key = `${r.owner}/${r.name}`;
    const existing = seen.get(key);
    if (existing === undefined) {
      seen.set(key, merged.length);
      merged.push(r as RepoRow);
    } else if (r.appInstalled && !merged[existing].appInstalled) {
      // Prefer the app-installed version so the one-click button shows
      merged[existing] = { ...merged[existing], appInstalled: true };
    }
  }
  return merged;
}

export default async function ReposPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const username = (session.user as any).username as string ?? session.user?.name ?? "";
  const repos = await getRepos(githubId, username);

  const appSlug = process.env.NEXT_PUBLIC_GITHUB_APP_SLUG ?? "aegisdiff";
  const ingestUrl = `${process.env.NEXTAUTH_URL ?? ""}/api/ingest`;

  return (
    <div>
      <div className="mb-6 flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-50">Connected Repositories</h1>
        <div className="flex gap-2 flex-wrap items-center">
          <SyncButton />
          <a href={`https://github.com/apps/${appSlug}/installations/new`} target="_blank"
            rel="noopener noreferrer"
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
            + Install GitHub App
          </a>
          <a href="/onboarding"
            className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700">
            + Manual Connect
          </a>
        </div>
      </div>

      {repos.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 dark:border-gray-700 p-12 text-center">
          <p className="text-gray-500 dark:text-gray-400 font-medium">No repositories connected yet.</p>
          <p className="mt-2 text-sm text-gray-400 dark:text-gray-500 mb-6">
            Install the GitHub App for zero-config setup, or connect manually with your own API keys.
          </p>
          <div className="flex justify-center gap-3">
            <a href={`https://github.com/apps/${appSlug}/installations/new`} target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
              Install GitHub App (recommended)
            </a>
            <a href="/onboarding"
              className="rounded-lg border border-gray-300 dark:border-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800">
              Manual setup
            </a>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {repos.map((repo) => {
            const total = parseInt(repo.totalScans, 10);
            const tp = parseInt(repo.truePositives, 10);
            const score = securityScore(total, tp);
            return (
              <div key={repo.id} className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-4 shadow-sm hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <a href={`/repos/${repo.owner}/${repo.name}`}
                        className="font-mono font-semibold text-gray-900 dark:text-gray-50 hover:text-blue-600 truncate">
                        {repo.owner}/{repo.name}
                      </a>
                      {repo.appInstalled ? (
                        <span className="rounded-full bg-blue-50 dark:bg-blue-950 px-2 py-0.5 text-xs font-medium text-blue-700 dark:text-blue-300 ring-1 ring-inset ring-blue-700/10">
                          GitHub App
                        </span>
                      ) : (
                        <span className="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-600 dark:text-gray-300 ring-1 ring-inset ring-gray-500/10">
                          Manual
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-gray-400 dark:text-gray-500 flex-wrap">
                      <span>Connected {new Date(repo.createdAt).toLocaleDateString()}</span>
                      {total > 0 && <span>{total} scans (30d)</span>}
                      {tp > 0 && <span className="text-red-500">{tp} issue{tp !== 1 ? "s" : ""}</span>}
                    </div>
                  </div>

                  <div className="flex items-center gap-4 ml-4 shrink-0">
                    {/* Security score */}
                    {score !== null && (
                      <div className="text-center">
                        <div className={`text-xl font-bold ${scoreColor(score)}`}>{score}</div>
                        <div className="text-[10px] text-gray-400 dark:text-gray-500">score</div>
                      </div>
                    )}
                    <div className="flex gap-2 text-xs">
                      <a href={`https://github.com/${repo.owner}/${repo.name}`}
                        target="_blank" rel="noopener noreferrer"
                        className="text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">GitHub ↗</a>
                      <a href={`/repos/${repo.owner}/${repo.name}`}
                        className="text-blue-600 hover:underline">Details →</a>
                    </div>
                  </div>
                </div>
                <RepoSetup owner={repo.owner} name={repo.name} ingestUrl={ingestUrl} appInstalled={repo.appInstalled} />
              </div>
            );
          })}
        </div>
      )}
      {repos.length > 0 && (
        <p className="mt-4 text-xs text-gray-400 dark:text-gray-500">
          Security score = 100 − TP rate over last 30 days. Click any repo for full details.
        </p>
      )}
    </div>
  );
}
