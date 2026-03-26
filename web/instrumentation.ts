/**
 * Next.js instrumentation hook — runs once on server startup (every cold start).
 * Initialises Sentry, then applies all schema migrations idempotently.
 */
export async function register() {
  // Sentry — must init before any other imports so it catches early errors
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }
  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }

  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (!process.env.DATABASE_URL) return;

  try {
    const { neon } = await import("@neondatabase/serverless");
    const sql = neon(process.env.DATABASE_URL);

    // ── Core tables (Phase 0) ─────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS installations (
        id                     SERIAL PRIMARY KEY,
        installation_id        BIGINT UNIQUE NOT NULL,
        account_login          TEXT NOT NULL,
        account_type           TEXT NOT NULL,
        installed_by_github_id BIGINT,
        created_at             TIMESTAMPTZ DEFAULT NOW(),
        deleted_at             TIMESTAMPTZ
      )`;

    // ── repos columns ─────────────────────────────────────────────────────
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS installation_id    BIGINT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS github_repo_id     BIGINT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS slack_webhook_url  TEXT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS deleted_at         TIMESTAMPTZ`;

    // ── Phase 1: Discord + Teams + notification thresholds ────────────────
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS discord_webhook_url    TEXT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS teams_webhook_url      TEXT`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS notify_min_severity    TEXT DEFAULT 'INFO'`;
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS notify_on_needs_review BOOLEAN DEFAULT FALSE`;

    // ── Phase 2: GitHub Issues auto-create ────────────────────────────────
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS auto_github_issue BOOLEAN DEFAULT FALSE`;

    // ── users columns ─────────────────────────────────────────────────────
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER DEFAULT 30`;

    // ── Phase 4: API keys ─────────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS api_keys (
        id          SERIAL PRIMARY KEY,
        github_id   BIGINT NOT NULL,
        key_hash    TEXT UNIQUE NOT NULL,
        key_prefix  TEXT NOT NULL,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        revoked_at  TIMESTAMPTZ
      )`;

    // ── Phase 5: Ignore rules ─────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS ignore_rules (
        id            SERIAL PRIMARY KEY,
        repo_id       INTEGER REFERENCES repos(id) ON DELETE CASCADE,
        cwe_id        TEXT,
        title_keyword TEXT,
        reason        TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      )`;

    // ── Phase 5: Audit log ────────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS audit_log (
        id          SERIAL PRIMARY KEY,
        github_id   BIGINT NOT NULL,
        action      TEXT NOT NULL,
        repo_owner  TEXT,
        repo_name   TEXT,
        details     JSONB,
        ip_hash     TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )`;

    // ── Phase 0: platform key rate-limit override per repo ────────────────
    await sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS custom_daily_limit INTEGER`;

    // ── Phase 5: scan feedback (developer verdict corrections) ────────────
    await sql`
      CREATE TABLE IF NOT EXISTS scan_feedback (
        id              SERIAL PRIMARY KEY,
        scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,
        github_id       BIGINT NOT NULL,
        correct_verdict TEXT NOT NULL,
        reason          TEXT,
        created_at      TIMESTAMPTZ DEFAULT NOW()
      )`;

    // ── Indexes ───────────────────────────────────────────────────────────
    await sql`CREATE INDEX IF NOT EXISTS installations_account_idx ON installations(account_login)`;
    await sql`CREATE INDEX IF NOT EXISTS repos_token_hash_idx      ON repos(token_hash)`;
    await sql`CREATE INDEX IF NOT EXISTS api_keys_github_idx        ON api_keys(github_id)`;
    await sql`CREATE INDEX IF NOT EXISTS audit_log_github_idx       ON audit_log(github_id, created_at DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS ignore_rules_repo_idx      ON ignore_rules(repo_id)`;
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS scan_feedback_scan_user_idx ON scan_feedback(scan_id, github_id)`;

  } catch (err) {
    console.warn("[migrate] Schema migration error (non-fatal):", err);
  }
}
