import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import { RepoSetup } from "./RepoSetup";

interface RepoRow {
  id: number;
  owner: string;
  name: string;
  createdAt: string;
  appInstalled: boolean;
}

async function getRepos(githubId: number, username: string): Promise<RepoRow[]> {
  // Manually connected repos
  const owned = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           (r.installation_id IS NOT NULL) AS "appInstalled"
    FROM repos r
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
    ORDER BY r.created_at DESC
  `;

  // GitHub App installed repos (user_id is NULL — matched by account_login)
  const appRepos = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt",
           TRUE AS "appInstalled"
    FROM repos r
    WHERE r.installation_id IS NOT NULL
      AND r.user_id IS NULL
      AND r.owner = ${username}
    ORDER BY r.created_at DESC
  `;

  // Merge, deduplicate
  const seen = new Set<string>();
  const merged: RepoRow[] = [];
  for (const r of [...(owned as any[]), ...(appRepos as any[])]) {
    const key = `${r.owner}/${r.name}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(r as RepoRow);
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
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Connected Repositories</h1>
        <div className="flex gap-2">
          <a
            href={`https://github.com/apps/${appSlug}/installations/new`}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            + Install GitHub App
          </a>
          <a
            href="/repos/connect"
            className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700"
          >
            + Manual Connect
          </a>
        </div>
      </div>

      {repos.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 p-12 text-center">
          <p className="text-gray-500 font-medium">No repositories connected yet.</p>
          <p className="mt-2 text-sm text-gray-400 mb-6">
            Install the GitHub App for zero-config setup, or connect manually with your own API keys.
          </p>
          <div className="flex justify-center gap-3">
            <a
              href={`https://github.com/apps/${appSlug}/installations/new`}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
            >
              Install GitHub App (recommended)
            </a>
            <a
              href="/repos/connect"
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Manual setup
            </a>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {repos.map((repo) => (
            <div
              key={repo.id}
              className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-medium text-gray-900">
                        {repo.owner}/{repo.name}
                      </span>
                      {repo.appInstalled ? (
                        <span className="inline-flex items-center rounded-full bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-700 ring-1 ring-inset ring-blue-700/10">
                          GitHub App
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-gray-50 px-2 py-0.5 text-xs font-medium text-gray-600 ring-1 ring-inset ring-gray-500/10">
                          Manual
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Connected {new Date(repo.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <div className="flex gap-3 items-center">
                  <a
                    href={`https://github.com/${repo.owner}/${repo.name}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-gray-400 hover:text-gray-700"
                  >
                    GitHub ↗
                  </a>
                  <a
                    href={`/dashboard?repo=${repo.owner}/${repo.name}`}
                    className="text-xs text-blue-600 hover:underline"
                  >
                    View scans
                  </a>
                </div>
              </div>
              <RepoSetup
                owner={repo.owner}
                name={repo.name}
                ingestUrl={ingestUrl}
              />
            </div>
          ))}
        </div>
      )}

      {repos.length > 0 && (
        <p className="mt-4 text-xs text-gray-400">
          To add more repositories, click <strong>+ Install GitHub App</strong> and select additional repos.
        </p>
      )}
    </div>
  );
}
