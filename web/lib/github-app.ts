/**
 * GitHub App authentication helpers.
 * Used by the sync and setup-workflow API routes.
 */
import { SignJWT } from "jose";
import { createPrivateKey } from "crypto";

/** Generate a short-lived GitHub App JWT (valid 8 min). */
export async function generateAppJWT(): Promise<string> {
  const appId = process.env.GITHUB_APP_ID;
  const rawKey = process.env.GITHUB_APP_PRIVATE_KEY;
  if (!appId || !rawKey) {
    throw new Error(
      "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set in Vercel environment variables."
    );
  }
  const pem = rawKey.replace(/\\n/g, "\n");
  const privateKey = createPrivateKey(pem);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: appId })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt(now - 60)
    .setExpirationTime(now + 480)
    .sign(privateKey);
}

/** Get a short-lived installation access token for a given installation ID.
 *
 * Pass `repo` to scope the token to that specific repository — required when
 * the App was installed with "Selected repositories" mode. Without scoping the
 * token may be rejected with "Resource not accessible by integration" even when
 * the App has the right permissions.
 */
export async function getInstallationToken(
  installationId: number,
  repo?: { owner: string; name: string },
): Promise<string> {
  const jwt = await generateAppJWT();
  const body = repo ? JSON.stringify({ repositories: [repo.name] }) : undefined;
  const resp = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body,
      cache: "no-store",
    }
  );
  if (!resp.ok) {
    const body2 = await resp.text().catch(() => "");
    throw new Error(`Failed to get installation token (${resp.status}): ${body2.slice(0, 200)}`);
  }
  const data = await resp.json();
  return data.token as string;
}

/**
 * Look up the GitHub App installation for a specific repo via the App JWT.
 * Returns the installation ID, or null if the App isn't installed on that repo.
 */
export async function getRepoInstallationId(
  owner: string,
  name: string,
): Promise<number | null> {
  try {
    const jwt = await generateAppJWT();
    const resp = await fetch(
      `https://api.github.com/repos/${owner}/${name}/installation`,
      {
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: "application/vnd.github+json",
        },
        cache: "no-store",
      }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    return (data.id as number) ?? null;
  } catch {
    return null;
  }
}

/** Call GitHub API with a token. Throws on non-2xx. */
export async function ghFetch(url: string, token: string, method = "GET", body?: unknown) {
  const resp = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`GitHub API ${resp.status} ${method} ${url}: ${text.slice(0, 300)}`);
  }
  return resp.json();
}
