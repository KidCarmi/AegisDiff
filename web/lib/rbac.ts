/**
 * RBAC — Role resolution from GitHub API.
 *
 * Roles are derived from existing GitHub permissions — no separate DB table.
 * Source of truth is always GitHub. Results cache via Next.js fetch (5 min TTL).
 *
 * Role hierarchy (highest → lowest):
 *   platform:admin  Operator access — PLATFORM_ADMIN_GITHUB_IDS env var
 *   org:owner       GitHub org owner
 *   repo:admin      GitHub repo admin permission
 *   repo:developer  GitHub repo write permission
 *   repo:viewer     GitHub repo read permission
 */

export type Role =
  | "platform:admin"
  | "org:owner"
  | "repo:admin"
  | "repo:developer"
  | "repo:viewer";

const ROLE_RANK: Record<Role, number> = {
  "platform:admin": 50,
  "org:owner":      40,
  "repo:admin":     30,
  "repo:developer": 20,
  "repo:viewer":    10,
};

export function roleRank(role: Role): number {
  return ROLE_RANK[role] ?? 0;
}

export function hasMinRole(userRole: Role | null, minRole: Role): boolean {
  if (!userRole) return false;
  return roleRank(userRole) >= roleRank(minRole);
}

// ── Platform admin ────────────────────────────────────────────────────────────

export function isPlatformAdmin(githubId: number): boolean {
  const ids = (process.env.PLATFORM_ADMIN_GITHUB_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map(Number);
  return ids.includes(githubId);
}

export function isPlatformAdminSession(session: any): boolean {
  const githubId = session?.user?.githubId as number | undefined;
  return githubId ? isPlatformAdmin(githubId) : false;
}

// ── GitHub API helper ─────────────────────────────────────────────────────────

async function ghFetch(path: string, accessToken: string): Promise<any | null> {
  try {
    const resp = await fetch(`https://api.github.com${path}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      next: { revalidate: 300 }, // cache 5 min
    });
    if (!resp.ok) return null;
    return resp.json();
  } catch {
    return null;
  }
}

async function getUsername(accessToken: string): Promise<string | null> {
  const data = await ghFetch("/user", accessToken);
  return data?.login ?? null;
}

// ── Role resolution ───────────────────────────────────────────────────────────

/**
 * Resolve the highest role a user holds for a given repo (or org).
 *
 * @param githubId    User's GitHub numeric ID (from session)
 * @param accessToken User's GitHub OAuth access token (from session)
 * @param owner       Repo owner or org name
 * @param repo        Optional — omit for org-level check only
 */
export async function resolveRole(
  githubId: number,
  accessToken: string,
  owner: string,
  repo?: string
): Promise<Role | null> {
  // 1. Platform admin — env var check, no API call needed
  if (isPlatformAdmin(githubId)) return "platform:admin";

  const username = await getUsername(accessToken);
  if (!username) return null;

  // 2. Org owner
  const membership = await ghFetch(
    `/orgs/${owner}/memberships/${username}`,
    accessToken
  );
  if (membership?.role === "admin" && membership?.state === "active") {
    return "org:owner";
  }

  // 3. Repo-level permission
  if (repo) {
    const permData = await ghFetch(
      `/repos/${owner}/${repo}/collaborators/${username}/permission`,
      accessToken
    );
    const perm: string = permData?.permission ?? "";
    if (perm === "admin") return "repo:admin";
    if (perm === "write") return "repo:developer";
    if (perm === "read")  return "repo:viewer";

    // Fallback: check repo visibility via basic fetch
    const repoData = await ghFetch(`/repos/${owner}/${repo}`, accessToken);
    if (repoData?.permissions?.push)  return "repo:developer";
    if (repoData?.permissions?.pull)  return "repo:viewer";
  }

  return null;
}

// ── Route guard helpers ───────────────────────────────────────────────────────

/**
 * Assert the session user has at least `minRole` for a repo.
 * Returns the resolved role on success.
 * Throws a Response (401 or 403) on failure — catch in route handler.
 */
export async function requireRepoRole(
  session: any,
  owner: string,
  repo: string,
  minRole: Role
): Promise<Role> {
  const githubId   = session?.user?.githubId   as number | undefined;
  const accessToken = session?.user?.accessToken as string | undefined;

  if (!githubId || !accessToken) {
    throw new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const role = await resolveRole(githubId, accessToken, owner, repo);
  if (!role || !hasMinRole(role, minRole)) {
    throw new Response(
      JSON.stringify({ error: "Forbidden", required: minRole, resolved: role ?? "none" }),
      { status: 403, headers: { "Content-Type": "application/json" } }
    );
  }
  return role;
}

/**
 * Assert the session user is a platform admin.
 * Returns true on success, throws a 403 Response on failure.
 */
export function requirePlatformAdmin(session: any): true {
  if (!isPlatformAdminSession(session)) {
    throw new Response(JSON.stringify({ error: "Platform admin access required" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }
  return true;
}

// ── Legacy compat — keep existing callers working ────────────────────────────

/**
 * @deprecated Use requireRepoRole() instead.
 * Kept for backwards compat with existing API routes that call requireRepoAccess().
 */
export async function requireRepoAccess(
  accessToken: string,
  owner: string,
  repo: string,
  requiredLevel: "read" | "admin" = "read"
): Promise<void> {
  try {
    const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
      next: { revalidate: 300 },
    });
    if (!resp.ok) throw new Error(`GitHub returned ${resp.status}`);
    const data = await resp.json();
    if (requiredLevel === "admin" && !data?.permissions?.admin) {
      throw new Error(`Admin access required for ${owner}/${repo}`);
    }
  } catch (err) {
    throw new Error(`No access to ${owner}/${repo}: ${(err as Error).message}`);
  }
}
