import { getServerSession } from "next-auth/next";
import { redirect } from "next/navigation";
import { authOptions } from "../../lib/auth";
import { sql } from "../../lib/db";
import type { Repo } from "../../lib/types";

async function getRepos(githubId: number): Promise<Repo[]> {
  const rows = await sql`
    SELECT r.id, r.owner, r.name, r.created_at AS "createdAt"
    FROM repos r
    JOIN users u ON r.user_id = u.id
    WHERE u.github_id = ${githubId}
    ORDER BY r.created_at DESC
  `;
  return rows as unknown as Repo[];
}

export default async function ReposPage() {
  const session = await getServerSession(authOptions);
  if (!session) redirect("/api/auth/signin");

  const githubId = (session.user as any).githubId as number;
  const repos = await getRepos(githubId);

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Connected Repositories</h1>
        <a
          href="/repos/connect"
          className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-700"
        >
          + Connect Repo
        </a>
      </div>

      {repos.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 p-12 text-center">
          <p className="text-gray-500">No repositories connected yet.</p>
          <p className="mt-2 text-sm text-gray-400">
            Click <strong>+ Connect Repo</strong> to get started.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {repos.map((repo) => (
            <div
              key={repo.id}
              className="flex items-center justify-between rounded-lg border border-gray-200 bg-white p-4 shadow-sm"
            >
              <div>
                <span className="font-mono font-medium text-gray-900">
                  {repo.owner}/{repo.name}
                </span>
                <p className="text-xs text-gray-400 mt-0.5">
                  Connected {new Date(repo.createdAt).toLocaleDateString()}
                </p>
              </div>
              <div className="flex gap-2">
                <a
                  href={`/dashboard?repo=${repo.owner}/${repo.name}`}
                  className="text-xs text-blue-600 hover:underline"
                >
                  View scans
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
