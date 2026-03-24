/**
 * Next.js instrumentation hook — runs once on server startup (every cold start).
 * Used to apply idempotent schema migrations so the DB is always in sync
 * without any manual steps after deploy.
 */
export async function register() {
  // Only run in Node.js runtime (not edge)
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (!process.env.DATABASE_URL) return;

  try {
    const { neon } = await import("@neondatabase/serverless");
    const sql = neon(process.env.DATABASE_URL);

    // Each statement is idempotent — safe to run on every cold start.
    // Order matters: create tables before adding FK columns.
    await sql`
      CREATE TABLE IF NOT EXISTS installations (
        id                     SERIAL PRIMARY KEY,
        installation_id        BIGINT UNIQUE NOT NULL,
        account_login          TEXT NOT NULL,
        account_type           TEXT NOT NULL,
        installed_by_github_id BIGINT,
        created_at             TIMESTAMPTZ DEFAULT NOW(),
        deleted_at             TIMESTAMPTZ
      )
    `;

    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS installation_id BIGINT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS github_repo_id  BIGINT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER DEFAULT 30`;

    await sql`CREATE INDEX IF NOT EXISTS installations_account_idx ON installations(account_login)`;
    await sql`CREATE INDEX IF NOT EXISTS repos_token_hash_idx ON repos(token_hash)`;
  } catch (err) {
    // Don't crash the server — log and continue
    console.warn("[migrate] Schema migration error (non-fatal):", err);
  }
}
