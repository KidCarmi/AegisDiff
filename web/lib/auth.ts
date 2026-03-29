/**
 * NextAuth.js configuration with GitHub OAuth provider.
 *
 * RBAC is delegated to GitHub: access is determined by whether the user
 * can read the repo via the GitHub API (using their OAuth access_token).
 */
import type { NextAuthOptions } from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import { sql } from "./db";
import { sendWelcomeEmail } from "./email";

export const authOptions: NextAuthOptions = {
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      authorization: {
        params: {
          // Minimum scopes needed:
          //   read:user   — GitHub ID + login for session
          //   user:email  — email for welcome notification
          //   read:org    — org membership check for RBAC (org:owner role)
          //   repo        — collaborator permission check requires this on private repos
          scope: "read:user user:email read:org repo",
        },
      },
    }),
  ],

  secret: process.env.NEXTAUTH_SECRET,

  callbacks: {
    async signIn({ user, account, profile }) {
      if (!profile || account?.provider !== "github") return false;

      const githubId = Number((profile as any).id);
      const username = (profile as any).login as string;
      const email = user.email ?? null;

      // Upsert user record — detect first-ever sign-in to send welcome email
      const result = await sql`
        INSERT INTO users (github_id, username, email)
        VALUES (${githubId}, ${username}, ${email})
        ON CONFLICT (github_id) DO UPDATE
          SET username = EXCLUDED.username,
              email    = COALESCE(EXCLUDED.email, users.email)
        RETURNING (xmax = 0) AS is_new_user
      `;
      const isNewUser = (result[0] as any)?.is_new_user === true;
      if (isNewUser && email) {
        sendWelcomeEmail(email, username); // fire-and-forget
      }

      return true;
    },

    async session({ session, token }) {
      if (session.user && token.sub) {
        (session.user as any).githubId = token.githubId;
        (session.user as any).accessToken = token.accessToken;
        (session.user as any).username = token.username;
      }
      return session;
    },

    async jwt({ token, account, profile }) {
      if (account && profile) {
        token.githubId = (profile as any).id;
        token.accessToken = account.access_token;
        token.username = (profile as any).login;
      }
      return token;
    },
  },

  pages: {
    signIn: "/login",
  },
};

/**
 * Verify that the authenticated user has access to a given repo
 * by calling the GitHub API with their OAuth token.
 * Returns true if the user can read the repo, false otherwise.
 */
export async function verifyRepoAccess(
  accessToken: string,
  owner: string,
  repo: string
): Promise<boolean> {
  try {
    const resp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
        },
        // Short cache: re-validate access every 5 minutes
        next: { revalidate: 300 },
      }
    );
    return resp.ok;
  } catch {
    return false;
  }
}
