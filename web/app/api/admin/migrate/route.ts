/**
 * POST /api/admin/migrate
 *
 * Applies any pending schema changes (idempotent — uses IF NOT EXISTS).
 * Protected by the ADMIN_SECRET env var.
 *
 * Usage (run once after deploy):
 *   curl -s -X POST https://your-app.vercel.app/api/admin/migrate \
 *     -H "Authorization: Bearer $ADMIN_SECRET"
 */
import { NextRequest, NextResponse } from "next/server";
import { sql } from "../../../../lib/db";

export async function POST(req: NextRequest) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "ADMIN_SECRET not configured" }, { status: 500 });
  }

  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (token !== secret) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const migrations = [
    {
      name: "repos.slack_webhook_url",
      run: () => sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT`,
    },
    {
      name: "users.scan_retention_days",
      run: () => sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS scan_retention_days INTEGER DEFAULT 30`,
    },
    {
      name: "installations table",
      run: () => sql`
        CREATE TABLE IF NOT EXISTS installations (
          id                     SERIAL PRIMARY KEY,
          installation_id        BIGINT UNIQUE NOT NULL,
          account_login          TEXT NOT NULL,
          account_type           TEXT NOT NULL,
          installed_by_github_id BIGINT,
          created_at             TIMESTAMPTZ DEFAULT NOW(),
          deleted_at             TIMESTAMPTZ
        )
      `,
    },
    {
      name: "repos.installation_id column",
      run: () => sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS installation_id BIGINT`,
    },
    {
      name: "repos.github_repo_id column",
      run: () => sql`ALTER TABLE repos ADD COLUMN IF NOT EXISTS github_repo_id BIGINT`,
    },
    {
      name: "index: installations_account_idx",
      run: () => sql`CREATE INDEX IF NOT EXISTS installations_account_idx ON installations(account_login)`,
    },
    {
      name: "index: repos_token_hash_idx",
      run: () => sql`CREATE INDEX IF NOT EXISTS repos_token_hash_idx ON repos(token_hash)`,
    },
  ];

  const results: { name: string; status: "ok" | "error"; error?: string }[] = [];

  for (const migration of migrations) {
    try {
      await migration.run();
      results.push({ name: migration.name, status: "ok" });
    } catch (err: any) {
      results.push({ name: migration.name, status: "error", error: err.message });
    }
  }

  const anyError = results.some((r) => r.status === "error");
  return NextResponse.json({ ok: !anyError, results });
}
