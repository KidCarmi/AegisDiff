/**
 * RBAC helpers — verify a GitHub OAuth user has access to a given repository.
 *
 * Access is delegated to GitHub: if the user's OAuth token can read the repo
 * via the GitHub API, they can view its scan data in AegisDiff.
 */

/**
 * Throws an Error (HTTP 403 message) if the user does not have at least read
 * access to `owner/repo` on GitHub.
 *
 * Usage in any API route:
 *   await requireRepoAccess(session.accessToken, owner, repo);
 */
export async function requireRepoAccess(
  accessToken: string,
  owner: string,
  repo: string,
  requiredLevel: "read" | "admin" = "read"
): Promise<void> {
  let data: any;
  try {
    const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
      },
      // Re-validate access every 5 minutes (Next.js fetch cache)
      next: { revalidate: 300 },
    });

    if (!resp.ok) {
      throw new Error(`GitHub returned ${resp.status}`);
    }

    data = await resp.json();
  } catch (err) {
    throw new Error(`No access to ${owner}/${repo}: ${(err as Error).message}`);
  }

  if (requiredLevel === "admin" && !data?.permissions?.admin) {
    throw new Error(`Admin access required for ${owner}/${repo}`);
  }
}
