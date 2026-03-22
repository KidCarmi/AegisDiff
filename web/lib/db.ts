/**
 * Neon PostgreSQL client (serverless driver — optimized for edge/serverless).
 * Connection pooling is handled automatically by the Neon serverless driver.
 */
import { neon } from "@neondatabase/serverless";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is not set");
}

export const sql = neon(process.env.DATABASE_URL);

// ── Schema types ────────────────────────────────────────────────────────────

export interface DbUser {
  id: number;
  github_id: number;
  username: string;
  email: string | null;
  created_at: string;
}

export interface DbRepo {
  id: number;
  user_id: number;
  owner: string;
  name: string;
  token_hash: string;
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

CREATE TABLE IF NOT EXISTS repos (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
  owner           TEXT NOT NULL,
  name            TEXT NOT NULL,
  token_hash      TEXT UNIQUE NOT NULL,
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
`;
