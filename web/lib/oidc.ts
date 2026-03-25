/**
 * Shared GitHub Actions OIDC verification utility.
 * Used by /api/ingest and /api/llm-token.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS = createRemoteJWKSet(
  new URL(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`)
);

/**
 * Verify a GitHub Actions OIDC JWT (audience: "aegisdiff").
 * Returns the repository claim ("owner/name") on success, null on failure.
 */
export async function verifyOIDC(token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, GITHUB_JWKS, {
      issuer: GITHUB_OIDC_ISSUER,
      audience: "aegisdiff",
    });
    return (payload["repository"] as string) ?? null;
  } catch {
    return null;
  }
}
