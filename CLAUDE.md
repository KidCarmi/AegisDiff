# AegisDiff — Project Guide for AI Agents

## What Is This?

AegisDiff is a **managed SaaS AppSec triage platform**. The operator (KidCarmi)
hosts a single Vercel + Neon deployment. Users sign in with GitHub OAuth, connect
their repos, and get PR security scanning with zero configuration. The operator
manages the LLM API keys and rate limits. Users never need their own AI keys.

## $0/Month Constraint

This is a hard requirement. Every architectural decision must preserve this.
- No paid VMs, no persistent servers, no managed databases with charges
- See `README.md` → "The Ghost Stack" for the full service list

## Repository Structure

```
aegisdiff/              Python triage engine
  github/               GitHub API clients (client.py + app_client.py)
  llm/providers/        openrouter.py, groq.py, github_models.py, cerebras.py (unused)
  triage/               engine.py, verdicts.py, prompts.py, sarif.py
  code_context/         extractor.py (AST sink/source), models.py
  cache/                gist_cache.py (optional ephemeral cache)
web/                    Next.js 14 App Router dashboard (Vercel)
  app/api/              32 API route handlers
  lib/                  db.ts, rbac.ts, github-app.ts, auth.ts, types.ts
  middleware.ts          Route protection (session + admin guard)
  instrumentation.ts     Sentry init + DB migrations on cold start
landing/                Static landing page (Cloudflare Pages)
tests/                  13 test files, ~263 tests, 10 security fixtures
scripts/                local_scan.py for manual testing
.github/
  workflows/
    aegisdiff-app.yml    GitHub App path (repository_dispatch from webhook)
    ci.yml               Canary + self-scan + lint/test (this repo's CI)
    security.yml         SAST/SCA pipeline (Semgrep, Bandit, Trivy, Gitleaks)
    cleanup.yml          Daily DB retention cleanup (cron)
```

## Key Design Rules — DO NOT VIOLATE

1. **Never store code in the database.** The Neon DB stores only metadata: verdict,
   severity, CWE ID, confidence, title, provider, timing. No code, no diffs, no
   evidence strings. Evidence lives ONLY in the GitHub PR comment.

2. **LLM provider priority: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-27b-it:free → Groq llama-3.3-70b-versatile → GitHub Models (GITHUB_TOKEN fallback).**
   Cerebras is excluded — GitHub Actions (Azure IPs) are blocked by Cerebras WAF.
   Groq is active and wired in (free tier, no training on requests, no Azure IP block).
   Gemini, SambaNova, llama-4-maverick, deepseek-chat-v3-0324, mistral-7b-instruct have been removed. Do not re-add them.
   Mistral La Plateforme free tier trains on requests — disqualified for a security scanner.
   Gemini free tier trains on requests — disqualified for a security scanner.
   GitHub Models model ID is bare name: `Llama-3.3-70B-Instruct` (NOT `meta/Llama-3.3-70B-Instruct` — namespace prefix causes 400).
   GitHub Models uses the always-present `GITHUB_TOKEN` — zero-config last resort.

3. **Verdict JSON schema is backwards-compatible.** `parse_verdict()` in
   `aegisdiff/triage/verdicts.py` must always handle missing keys gracefully.
   Fields can be added, never removed or renamed.

4. **All secrets via environment variables, never hardcoded.**

5. **Confidence calibration rules in `verdicts.py` are non-negotiable:**
   - `TRUE_POSITIVE` requires `confidence >= 0.7`
   - `confidence < 0.5` forces `NEEDS_REVIEW`

6. **`Verdict.error(reason)` uses reason as the title (truncated to 80 chars).**
   Never hardcode "Analysis engine error" — the actual failure reason must be
   visible in the dashboard.

7. **Auth is OIDC-first.** `_get_oidc_token()` runs first. Falls back to
   `AEGISDIFF_REPO_TOKEN` only for legacy repos.

8. **Platform key distribution is the zero-config path.** The engine must NOT
   hard-exit when no user LLM keys are configured — it must first try
   `/api/llm-token` (OIDC-authenticated), then GitHub Models as last resort.
   Only exit if ALL paths are unavailable. User-provided keys always take priority.

9. **RBAC is derived from GitHub — never store role assignments in the DB.**
   Roles are resolved at request time from the GitHub API (org membership,
   repo permissions) and cached per session. No `memberships` table needed.

## LLM Provider Stack (in priority order)

```
User keys (OPENROUTER_API_KEY 1/2/3, GROQ_API_KEY 1/2/3):
  1. OpenRouter llama-3.3-70b-instruct:free  (key 1)
  2. OpenRouter llama-3.3-70b-instruct:free  (key 2)
  3. OpenRouter llama-3.3-70b-instruct:free  (key 3)
  4. OpenRouter gemma-3-27b-it:free          (key 1)
  5. OpenRouter gemma-3-27b-it:free          (key 2)
  6. OpenRouter gemma-3-27b-it:free          (key 3)
  7. Groq llama-3.3-70b-versatile            (key 1)
  8. Groq llama-3.3-70b-versatile            (key 2)
  9. Groq llama-3.3-70b-versatile            (key 3)

Platform keys (via OIDC → /api/llm-token, 100 scans/day):
  10. OpenRouter llama-3.3-70b-instruct:free  (platform key 1)
  11. OpenRouter llama-3.3-70b-instruct:free  (platform key 2)
  12. OpenRouter llama-3.3-70b-instruct:free  (platform key 3)
  13. OpenRouter gemma-3-27b-it:free          (platform key 1)
  14. OpenRouter gemma-3-27b-it:free          (platform key 2)
  15. OpenRouter gemma-3-27b-it:free          (platform key 3)
  16. Groq llama-3.3-70b-versatile            (platform key 1)
  17. Groq llama-3.3-70b-versatile            (platform key 2)
  18. Groq llama-3.3-70b-versatile            (platform key 3)

Zero-config fallback (always present in Actions):
  19. GitHub Models Llama-3.3-70B-Instruct  (GITHUB_TOKEN)
```

Rate limits: OpenRouter free tier = 8 req/min per key per model (~200 RPD).
Groq free tier = 30 req/min per key (~14,400 RPD). Does NOT train on requests.
GitHub Models: conservative RPM, but always available as absolute last resort.

## RBAC Model

Roles are resolved from the GitHub API on every session, not stored in DB.

| Role | Source | Permissions |
|---|---|---|
| `platform:admin` | `PLATFORM_ADMIN_GITHUB_IDS` env var (comma-separated) | Everything + admin panel |
| `org:owner` | GitHub org owner | All repos in org, org settings |
| `repo:admin` | GitHub repo admin permission | Repo settings, webhooks, ignore rules |
| `repo:developer` | GitHub repo write permission | View scans, feedback, rescan |
| `repo:viewer` | GitHub repo read permission | View scans (read-only) |

**Resolution function** (implemented in `web/lib/rbac.ts`):
```typescript
type Role = "platform:admin" | "org:owner" | "repo:admin" | "repo:developer" | "repo:viewer" | null;

async function resolveRole(
  session: Session,         // NextAuth session (github_id, access_token)
  owner: string,            // repo owner or org name
  repo?: string,            // optional — if omitted, resolves org-level role
): Promise<Role>
```

Resolution order (first match wins):
1. If `session.github_id` is in `PLATFORM_ADMIN_GITHUB_IDS` → `platform:admin`
2. Call `GET /orgs/{owner}/memberships/{username}` → if `role=owner` → `org:owner`
3. If `repo` provided, call `GET /repos/{owner}/{repo}/collaborators/{username}/permission`
   - `admin` → `repo:admin`
   - `write` → `repo:developer`
   - `read` → `repo:viewer`
4. Return `null` (no access)

Cache: store resolved role in the Next.js session JWT (5-minute TTL).
Never trust a role claim from the client — always re-resolve from GitHub API.

**Middleware** (`web/middleware.ts`): protect routes by minimum required role:
```
/dashboard            → repo:viewer or higher
/repos/[o]/[n]        → repo:viewer or higher for that repo
/repos/[o]/[n]/...    → repo:admin for settings routes
/admin                → platform:admin only
/api/admin/*          → platform:admin only
/api/repos/[o]/[n]/*  → repo:admin for mutations, repo:viewer for reads
```

## Dev Commands

```bash
# Python engine
pip install -e .[dev]           # Install with dev dependencies
pytest                          # Run all tests (~231 tests, ~2.5s)
pytest tests/test_orchestrator.py -v
ruff check aegisdiff/           # Lint (CI gate — must pass)
ruff format aegisdiff/          # Format

# Local scan
python scripts/local_scan.py --diff path/to/file.diff

# Dashboard
cd web && npm install
npm run dev                     # http://localhost:3000
npm run build                   # Production build
```

## Test Fixtures

| Fixture | CWE | Expected Verdict |
|---|---|---|
| `sample.diff` | CWE-78 + CWE-22 | TRUE_POSITIVE |
| `ssrf.diff` | CWE-918 | TRUE_POSITIVE |
| `ssti.diff` | CWE-94 | TRUE_POSITIVE |
| `hardcoded_secret.diff` | CWE-798 | TRUE_POSITIVE |
| `jwt_weak.diff` | CWE-327 | TRUE_POSITIVE |
| `deserialization.diff` | CWE-502 | TRUE_POSITIVE |
| `xxe.diff` | CWE-611 | TRUE_POSITIVE |
| `xss.diff` | CWE-79 | TRUE_POSITIVE |
| `open_redirect.diff` | CWE-601 | TRUE_POSITIVE |
| `safe.diff` | — | FALSE_POSITIVE |

## Critical Files

| File | Purpose |
|---|---|
| `aegisdiff/llm/orchestrator.py` | Failover + retry + adaptive 413 trimming |
| `aegisdiff/llm/providers/openrouter.py` | OpenRouter :free models (llama-3.3-70b primary, gemma-3-27b-it secondary) |
| `aegisdiff/llm/providers/groq.py` | Groq llama-3.3-70b-versatile (free tier, no training, 30 RPM / 14k RPD) |
| `aegisdiff/llm/providers/github_models.py` | GitHub Models (GITHUB_TOKEN, zero-config last-resort fallback) |
| `aegisdiff/llm/providers/cerebras.py` | Cerebras (kept on disk, NOT wired in — Azure IP blocked) |
| `aegisdiff/code_context/extractor.py` | AST sink/source detection (Python/JS/TS/Go/Java/Ruby/PHP/C#) |
| `aegisdiff/triage/prompts.py` | Cynical AppSec system prompt |
| `aegisdiff/triage/verdicts.py` | Verdict parsing + calibration rules |
| `aegisdiff/triage/sarif.py` | SARIF 2.1.0 builder for GitHub Code Scanning upload |
| `aegisdiff/entrypoint.py` | OIDC auth + platform key fetch + inline PR comment |
| `aegisdiff/app_entrypoint.py` | GitHub App path entrypoint (mirrors entrypoint.py) |
| `aegisdiff/github/client.py` | GitHub API: PR comments + inline review comments + SARIF upload |
| `aegisdiff/github/app_client.py` | GitHub App installation token + diff fetch + review + SARIF upload |
| `aegisdiff/sentry.py` | Sentry init helper (no-op without SENTRY_DSN) |
| `aegisdiff/config.py` | All env var loading (OPENROUTER_API_KEY 1/2/3, GROQ_API_KEY 1/2/3, GITHUB_TOKEN) |
| `.github/workflows/aegisdiff-app.yml` | GitHub App path workflow (repository_dispatch) |
| `web/app/api/ingest/route.ts` | Receives scan metadata, fires webhooks |
| `web/app/api/llm-token/route.ts` | Platform key distribution — 100 scans/day limit |
| `web/app/api/webhooks/github/route.ts` | GitHub App webhook handler (HMAC verify + event routing) |
| `web/app/api/repos/[o]/[n]/setup-workflow/route.ts` | One-click workflow commit via GitHub App token |
| `web/app/admin/page.tsx` | Platform admin dashboard (Overview/Users/Rate Limits tabs) |
| `web/lib/rbac.ts` | Role resolution from GitHub API (Phase 1) |
| `web/lib/github-app.ts` | GitHub App JWT + installation token helpers |
| `web/middleware.ts` | Route protection — admin routes require platform:admin |
| `web/instrumentation.ts` | Sentry init + auto-applies DB migrations on cold start |
| `web/lib/db.ts` | Neon client + schema SQL |

## Dashboard API Surface

```
# Public (OIDC auth from GitHub Actions)
GET  /api/llm-token                     Platform AI key distribution (100/day)
POST /api/ingest                        Scan metadata ingestion (array or single)

# Webhooks
POST /api/webhooks/github               GitHub App webhook (HMAC-SHA256 verified)

# User-facing (NextAuth session, RBAC enforced)
GET  /api/repos                         List repos (viewer+)
POST /api/repos                         Connect new repo (admin)
POST /api/repos/sync                    Re-sync repos from GitHub App (admin)
GET  /api/scans                         Scan history filtered to user's repos (viewer+)
GET  /api/scans/export                  Export as CSV/JSON (viewer+)
GET  /api/scans/top-vulns               Top vulnerability trends (viewer+)
GET  /api/scans/sla-breaches            CRITICAL/HIGH open > N days (viewer+)
POST /api/scans/[id]/feedback           Verdict correction (developer+)
POST /api/scans/[id]/rescan             Trigger manual rescan (developer+)
GET  /api/repos/[o]/[n]/token           Rotate ingest token (admin)
GET  /api/repos/[o]/[n]/usage           Daily scan count (viewer+)
GET  /api/repos/[o]/[n]/setup-workflow  Generate workflow YAML (admin)
GET|PATCH /api/repos/[o]/[n]/slack      Slack webhook (admin)
GET|PATCH /api/repos/[o]/[n]/discord    Discord webhook (admin)
GET|PATCH /api/repos/[o]/[n]/teams      MS Teams webhook (admin)
GET|PATCH /api/repos/[o]/[n]/notify     Notification severity threshold (admin)
GET|POST|DELETE /api/repos/[o]/[n]/ignore  Ignore rules by CWE/title (admin)
GET  /api/audit                         Audit log (admin+)
GET|PATCH /api/settings                 User settings (scan retention days)
DELETE /api/user/delete                 Account deletion

# Badges
GET  /api/badge/[o]/[n]                 SVG security status badge (public)

# Platform admin (platform:admin only)
GET  /api/admin/stats                   Platform-wide usage stats
POST /api/admin/migrate                 Manual DB migration trigger
POST /api/admin/rate-limit              Override daily scan limit per repo/org
GET  /api/admin/users                   User list + role view
POST /api/admin/cleanup                 Manual 90-day retention cleanup (Bearer token)

# Cron (Vercel, protected by CRON_SECRET)
POST /api/cron/weekly-digest            Monday 09:00 UTC digest to all webhooks

# External (Bearer ak_ key)
GET  /api/v1/scans                      Public scan history
GET|POST|DELETE /api/v1/key             Manage API key
```

## DB Schema

Tables managed by `web/instrumentation.ts` (idempotent `ALTER TABLE IF NOT EXISTS`).
**Never add code/diff/evidence columns to any table.**

- `users` — GitHub OAuth users (github_id, username, email)
- `installations` — GitHub App installs (installation_id, account_login)
- `repos` — connected repos + integration settings (webhooks, thresholds)
- `scans` — scan metadata only (verdict, severity, cwe_id, confidence, title,
  provider, scan_ms, pr_number, commit_sha, pr_url)
- `api_keys` — public REST API keys (key_hash SHA-256)
- `ignore_rules` — per-repo suppression (cwe_id or title_keyword)
- `audit_log` — action history (user, action, detail, created_at)
- `scan_feedback` — developer verdict corrections (Phase 5)

Note: **No `memberships` table.** RBAC is resolved from GitHub API at runtime.

## Phases Roadmap

Work through phases in order. All tests must pass before starting the next phase.

### ✅ Phase 0 — Platform Key Distribution (COMPLETE)

Users need zero secrets. The engine fetches platform LLM keys from `/api/llm-token`
via OIDC. Rate limit: **100 scans/day** per repo. User-provided keys always win.

Vercel env vars required: `PLATFORM_OPENROUTER_API_KEY`, `PLATFORM_OPENROUTER_API_KEY_2`,
`PLATFORM_OPENROUTER_API_KEY_3`, `PLATFORM_GROQ_API_KEY`, `PLATFORM_GROQ_API_KEY_2`,
`PLATFORM_GROQ_API_KEY_3`, `PLATFORM_ADMIN_GITHUB_IDS`.

### ✅ Phase 1 — RBAC (COMPLETE)

GitHub-derived roles, middleware route protection, platform admin panel.
Admin panel has 3 tabs: Overview (stats + top repos + audit log), Users (list),
Rate Limits (override form). Admin link in NavBar shown only to platform:admin.

### ✅ Phase 2 — Inline PR Review Comments (COMPLETE)

TRUE_POSITIVE findings posted as inline review comments on the exact vulnerable
line. Top-level comment is a summary only. Both `entrypoint.py` (manual path)
and `app_entrypoint.py` (GitHub App path) use inline comments. 25 tests added
in `tests/test_pr_comment.py`.

### ✅ Phase 3 — Per-Hunk Analysis (COMPLETE)

Each changed file analyzed independently. Results aggregated (highest severity wins).
`analyze_diff_chunked()` in `engine.py` splits by `diff --git` headers, then further
splits each file's diff into sub-hunks of ≤ 150 lines (`_split_file_diff_into_hunks`).
This ensures vulnerabilities in lines 201+ of large changed files are never missed.
Cap: `_MAX_CHUNKS_PER_PR = 20` sub-chunks per PR to protect daily quota.
`entrypoint.py` uses chunked mode when diff > 100 lines (`CHUNKED_DIFF_THRESHOLD`).
Ingest accepts array payloads — one DB row per finding per PR.

### ✅ Phase 4 — `aegisdiff-ignore` Inline Suppression (COMPLETE)

`# aegisdiff-ignore: CWE-89 reason: test-only` on or above a sink silences it.
`extractor.py` detects `_IGNORE_RE` for Python/Ruby/JS/TS/Go/Java comment styles.
`engine.py` short-circuits with `Verdict.suppressed()` when all sinks are suppressed.
`ingest/route.ts` persists suppressions to `ignore_rules` table.

### ✅ Phase 5 — Feedback Loop (COMPLETE)

"Mark FP / Mark TP" buttons in `ScanCard.tsx` (developer+ role only).
`POST /api/scans/[id]/feedback` upserts `scan_feedback`, writes `audit_log`.
FALSE_POSITIVE feedback on a TRUE_POSITIVE auto-adds to `ignore_rules`.

### ✅ Phase 6 — Re-scan on Demand (COMPLETE)

`@aegisdiff rescan` in any PR comment triggers a fresh scan (case-insensitive).
`webhooks/github/route.ts` handles `issue_comment` event, rate-limits to 3/PR/hour.
`POST /api/scans/[id]/rescan` provides same trigger from the dashboard UI.
`RescanButton.tsx` component with loading/queued state.
Ack comment posted: "🔄 Re-scan queued — results in ~90s."

### ✅ Phase 7 — SARIF / GitHub Code Scanning (COMPLETE)

TRUE_POSITIVE findings uploaded to GitHub Code Scanning API after every scan.
`aegisdiff/triage/sarif.py` builds a valid SARIF 2.1.0 document.
Both `entrypoint.py` and `app_entrypoint.py` call `upload_sarif()` (non-fatal on 403/404).
Requires `security-events: write` permission in the workflow.
Findings appear in the repo's Security tab alongside Dependabot and CodeQL alerts.

### ✅ Phase 8 — Trend Analytics & SLA Tracking (COMPLETE)

Weekly digest cron (Monday 09:00 UTC) fires Slack/Discord/Teams webhooks per repo.
`GET /api/scans/sla-breaches` — CRITICAL/HIGH TRUE_POSITIVEs open > N days.
`SlaBreaches.tsx` dashboard section: green all-clear or red breach list.
MTTF (Mean Time To Fix) stat card on dashboard (avg days TRUE_POSITIVE → feedback).
`vercel.json` cron schedule; protected by `CRON_SECRET`.

## Modifying the System Prompt

`aegisdiff/triage/prompts.py` → `APPSEC_SYSTEM_PROMPT` is the quality driver.
Changes must:
- Preserve the JSON verdict schema exactly
- Preserve the calibration rules section
- Not relax the NEEDS_REVIEW triggers

## Adding a New LLM Provider

1. Create `aegisdiff/llm/providers/your_provider.py` implementing `LLMProvider`
2. Set `name`, `model`, `max_context_tokens` class attributes
3. Implement `complete(request) -> LLMResponse` and `is_retryable_error(exc) -> bool`
4. Ensure `is_retryable_error` returns `False` for 413 (orchestrator handles it)
5. Add to provider list in `aegisdiff/entrypoint.py` and `aegisdiff/app_entrypoint.py` (after OpenRouter/Groq, before GitHub Models)
6. If key needed: add to `aegisdiff/config.py`, update `PLATFORM_*` env vars in Vercel, and add to `/api/llm-token/route.ts` response
7. Update `.github/workflows/aegisdiff-app.yml` and `.github/workflows/ci.yml` env vars
8. GitHub Models needs no extra steps — GITHUB_TOKEN is always available
