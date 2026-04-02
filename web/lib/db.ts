/**
 * Neon PostgreSQL client (serverless driver — optimized for edge/serverless).
 * Connection pooling is handled automatically by the Neon serverless driver.
 */
import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

// Lazy singleton — Neon client is created on first query, not at module load.
// This allows `next build` to complete without DATABASE_URL set in the build
// environment (Vercel sets it at runtime). The error surfaces on the first
// actual DB query if the env var is missing.
let _client: NeonQueryFunction<false, false> | null = null;

function getClient(): NeonQueryFunction<false, false> {
  if (!_client) {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL environment variable is not set");
    }
    _client = neon(process.env.DATABASE_URL);
  }
  return _client;
}

// sql is a tagged-template proxy — same API as neon(), but lazily initialized.
export const sql: NeonQueryFunction<false, false> = new Proxy(
  (() => {}) as unknown as NeonQueryFunction<false, false>,
  {
    apply(_t, _this, args) {
      return (getClient() as unknown as Function).apply(_this, args);
    },
  }
);

// ── Schema types ────────────────────────────────────────────────────────────

export interface DbUser {
  id: number;
  github_id: number;
  username: string;
  email: string | null;
  created_at: string;
}

export interface DbInstallation {
  id: number;
  installation_id: number;
  account_login: string;
  account_type: string;
  installed_by_github_id: number | null;
  created_at: string;
  deleted_at: string | null;
}

export interface DbRepo {
  id: number;
  user_id: number;
  owner: string;
  name: string;
  token_hash: string;
  installation_id: number | null;
  github_repo_id: number | null;
  created_at: string;
}

export interface DbScan {
  id: string;
  repo_id: number;
  pr_number: number | null;
  commit_sha: string;
  pr_url: string | null;
  verdict: string;
  severity: string | null;
  cwe_id: string | null;
  confidence: number | null;
  title: string | null;
  provider: string | null;
  scan_ms: number | null;
  created_at: string;
}

// ── DB initialization SQL ────────────────────────────────────────────────────

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id          SERIAL PRIMARY KEY,
  github_id   BIGINT UNIQUE NOT NULL,
  username    TEXT NOT NULL,
  email       TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS installations (
  id                     SERIAL PRIMARY KEY,
  installation_id        BIGINT UNIQUE NOT NULL,
  account_login          TEXT NOT NULL,
  account_type           TEXT NOT NULL,
  installed_by_github_id BIGINT,
  created_at             TIMESTAMPTZ DEFAULT NOW(),
  deleted_at             TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS repos (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
  owner           TEXT NOT NULL,
  name            TEXT NOT NULL,
  token_hash      TEXT UNIQUE NOT NULL,
  installation_id BIGINT REFERENCES installations(installation_id),
  github_repo_id  BIGINT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(owner, name)
);

CREATE TABLE IF NOT EXISTS scans (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id        INTEGER REFERENCES repos(id) ON DELETE CASCADE,
  pr_number      INTEGER,
  commit_sha     TEXT NOT NULL,
  pr_url         TEXT,
  verdict        TEXT NOT NULL,
  severity       TEXT,
  cwe_id         TEXT,
  confidence     FLOAT,
  title          TEXT,
  provider       TEXT,
  scan_ms        INTEGER,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS scans_repo_id_idx ON scans(repo_id);
CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS installations_account_idx ON installations(account_login);
CREATE INDEX IF NOT EXISTS repos_token_hash_idx ON repos(token_hash);

-- Run once to add new columns (safe to re-run — IF NOT EXISTS guards)
ALTER TABLE repos ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER DEFAULT 30;
`;
