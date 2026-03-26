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

/** Get a short-lived installation access token for a given installation ID. */
export async function getInstallationToken(installationId: number): Promise<string> {
  const jwt = await generateAppJWT();
  const resp = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
      },
      cache: "no-store",
    }
  );
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`Failed to get installation token (${resp.status}): ${body.slice(0, 200)}`);
  }
  const data = await resp.json();
  return data.token as string;
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
