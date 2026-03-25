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
aegisdiff/       Python triage engine (runs in user's GitHub Actions)
web/             Next.js 14 App Router dashboard (operator hosts on Vercel)
landing/         Static landing page (Cloudflare Pages)
tests/           Pytest unit tests + 10 security diff fixtures
scripts/         local_scan.py for manual testing
.github/
  workflows/
    aegisdiff.yml      Triage workflow (users copy this to their repos)
    ci.yml             Canary + self-scan + lint/test (this repo's CI)
    security.yml       SAST/SCA pipeline (Semgrep, Bandit, Trivy, Gitleaks)
    cleanup.yml        Daily DB retention cleanup
```

## Key Design Rules — DO NOT VIOLATE

1. **Never store code in the database.** The Neon DB stores only metadata: verdict,
   severity, CWE ID, confidence, title, provider, timing. No code, no diffs, no
   evidence strings. Evidence lives ONLY in the GitHub PR comment.

2. **LLM provider priority is Gemini first, Groq second.** This order is set in
   `aegisdiff/entrypoint.py` and must not be reversed.

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
   `/api/llm-token` (OIDC-authenticated). Only exit if both user keys AND
   platform keys are unavailable. User-provided keys always take priority.

9. **RBAC is derived from GitHub — never store role assignments in the DB.**
   Roles are resolved at request time from the GitHub API (org membership,
   repo permissions) and cached per session. No `memberships` table needed.

## RBAC Model

Roles are resolved from the GitHub API on every session, not stored in DB.

| Role | Source | Permissions |
|---|---|---|
| `platform:admin` | `PLATFORM_ADMIN_GITHUB_IDS` env var (comma-separated) | Everything + admin panel |
| `org:owner` | GitHub org owner | All repos in org, org settings |
| `repo:admin` | GitHub repo admin permission | Repo settings, webhooks, ignore rules |
| `repo:developer` | GitHub repo write permission | View scans, feedback, rescan |
| `repo:viewer` | GitHub repo read permission | View scans (read-only) |

**Resolution function** (implement in `web/lib/rbac.ts`):
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
pytest                          # Run all tests (63 tests, ~0.4s)
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
| `aegisdiff/llm/providers/groq.py` | Groq (max_context_tokens = 5,500) |
| `aegisdiff/llm/providers/gemini.py` | Gemini (max_context_tokens = 900k) |
| `aegisdiff/code_context/extractor.py` | AST sink/source detection |
| `aegisdiff/triage/prompts.py` | Cynical AppSec system prompt |
| `aegisdiff/triage/verdicts.py` | Verdict parsing + calibration rules |
| `aegisdiff/entrypoint.py` | OIDC auth + platform key fetch + PR comment |
| `aegisdiff/config.py` | All env var loading |
| `.github/workflows/aegisdiff.yml` | User-facing triage workflow |
| `web/app/api/ingest/route.ts` | Receives scan metadata, fires webhooks |
| `web/app/api/llm-token/route.ts` | Platform key distribution (Phase 0) |
| `web/lib/rbac.ts` | Role resolution from GitHub API (Phase 1) |
| `web/instrumentation.ts` | Auto-applies DB migrations on cold start |
| `web/lib/db.ts` | Neon client + schema SQL |

## Dashboard API Surface

```
# Public (OIDC auth from GitHub Actions)
GET  /api/llm-token           Platform AI key distribution
POST /api/ingest              Scan metadata ingestion

# User-facing (NextAuth session, RBAC enforced)
GET  /api/repos               List repos (viewer+)
GET  /api/scans               Scan history (viewer+)
GET  /api/scans/export        CSV or SARIF export (viewer+)
POST /api/scans/[id]/feedback Wrong verdict correction (developer+)
GET|PATCH /api/repos/[o]/[n]/slack     Slack webhook (admin)
GET|PATCH /api/repos/[o]/[n]/discord   Discord webhook (admin)
GET|PATCH /api/repos/[o]/[n]/teams     MS Teams webhook (admin)
GET|PATCH /api/repos/[o]/[n]/notify    Notification thresholds (admin)
GET|POST|DELETE /api/repos/[o]/[n]/ignore  Ignore rules (admin)
GET  /api/audit               Audit log (admin+)

# Platform admin (platform:admin only)
GET  /api/admin/stats         Platform-wide usage stats
POST /api/admin/migrate       Manual DB migration
POST /api/admin/rate-limit    Override rate limit for a repo/org
GET  /api/admin/users         User list + role view

# External
GET  /api/v1/scans            Public REST API (Bearer ak_ key)
GET|POST|DELETE /api/v1/key   Manage public API key
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

### Phase 0 — Platform Key Distribution

**Goal:** Users need zero secrets — not even `GEMINI_API_KEY`. The engine
fetches platform LLM keys from `/api/llm-token` via OIDC. LLM calls still
made FROM the user's runner. Code never leaves GitHub.

**New Vercel env vars (operator sets these once):**
- `PLATFORM_GEMINI_API_KEY` — operator's Gemini key
- `PLATFORM_GROQ_API_KEY` — operator's Groq key
- `PLATFORM_ADMIN_GITHUB_IDS` — comma-separated GitHub user IDs with admin access

**`web/app/api/llm-token/route.ts`:**
- `GET` with `Authorization: Bearer <oidc-jwt>`
- Call `verifyOIDC(token)` → get `repo` claim
- Count scans for this repo in last 24h from `scans` table
- If count ≥ 50 → return 429 `{ error: "Rate limit: 50 scans/day on free tier" }`
- Return `{ gemini_key, groq_key, expires_at }` (exp = 5 min from now)
- Write to `audit_log`: action `"llm_key_issued"`, detail = repo

**`aegisdiff/entrypoint.py` changes:**
- Add `_fetch_platform_keys(ingest_url, oidc_token) -> dict`
- In `main()`: before the `sys.exit(1)` on missing keys, try platform keys
- If platform keys are available, build providers with them
- User-provided keys always checked first — skip platform fetch if set
- On 429 from platform: log clearly, exit 1 with actionable message

**`aegisdiff/config.py`:** No change needed.

**`.github/workflows/aegisdiff.yml`:** Remove `GEMINI_API_KEY`/`GROQ_API_KEY`
from required secrets documentation. Keep as optional override.

**Tests (`tests/test_entrypoint.py`):**
- User keys present → `_fetch_platform_keys` never called
- No user keys + ingest URL → `_fetch_platform_keys` called with OIDC token
- Platform returns 429 → `sys.exit(1)` with clear message
- Platform returns keys → providers built, scan proceeds

### Phase 1 — RBAC

**Goal:** Role-based access control derived from GitHub permissions. Platform
admin panel. No manual role assignments — GitHub is the source of truth.

**`web/lib/rbac.ts`:**
- `resolveRole(session, owner, repo?)` — see RBAC Model section above
- `requireRole(minRole)` — Next.js middleware helper, returns 403 if insufficient
- Cache resolved role in JWT claims (re-verify on session refresh)

**`web/middleware.ts`:** Route protection table (see RBAC Model section).

**`web/app/admin/page.tsx`:** Platform admin dashboard:
- Total scans (today / 7d / 30d)
- Top repos by scan count
- Rate-limited repos list
- User list with role + last active
- Override rate limit form

**API changes:** Add `requireRole` checks to all mutation endpoints.

**Tests:** Mock GitHub API responses, verify role resolution and route protection.

### Phase 2 — Inline PR Review Comments

**Goal:** Findings posted as inline comments on the exact vulnerable line.

- `aegisdiff/github/client.py` — add `create_review(pr, commit_sha, comments[])`
- `aegisdiff/triage/verdicts.py` — add `line_number: Optional[int]`
- `aegisdiff/code_context/extractor.py` — ensure sink line number always set
- `aegisdiff/entrypoint.py` — use review when line number known; top-level fallback
- Top-level comment becomes a summary only (verdict + severity + CWE)
- Inline comment contains evidence quote + remediation

### Phase 3 — Per-Hunk Analysis

**Goal:** Analyze each changed file independently. Aggregate results.

- `aegisdiff/triage/engine.py` — `analyze_diff_chunked(diff)`: split by
  `diff --git` headers, analyze each independently, return list of Verdicts
- Aggregate: highest severity wins for overall PR status
- `aegisdiff/entrypoint.py` — chunked mode when diff > 100 lines
- Dashboard ingest accepts array (one row per finding per PR)

### Phase 4 — `aegisdiff-ignore` Inline Suppression

**Goal:** `# aegisdiff-ignore: CWE-89 reason: test-only` silences a finding.

- `aegisdiff/code_context/extractor.py` — detect ignore comments on/above sinks
- `aegisdiff/triage/engine.py` — suppressed sink → FALSE_POSITIVE with reason
- `web/app/api/ingest/route.ts` — write suppression to `ignore_rules` table

### Phase 5 — Feedback Loop

**Goal:** "Wrong verdict" button lets developers correct FPs/FNs.

- `web/app/api/scans/[id]/feedback/route.ts` — POST `{correct_verdict, reason}`
- `web/components/ScanCard.tsx` — thumbs up/down UI (developer+ role only)
- FALSE_POSITIVE feedback on TRUE_POSITIVE → auto-add to `ignore_rules`
- All corrections written to `audit_log` + new `scan_feedback` table

### Phase 6 — Re-scan on Demand

**Goal:** `@aegisdiff rescan` triggers a fresh scan without pushing a commit.

- `web/app/api/webhooks/github/route.ts` — handle `issue_comment` event
- Detect `@aegisdiff rescan` (case-insensitive)
- Trigger `aegisdiff.yml` via `repository_dispatch`
- Rate-limit: max 3 rescans/PR/hour (check `audit_log`)
- Post ack comment: "Re-scan queued — results in ~90s"

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
5. Add to provider list in `aegisdiff/entrypoint.py` (after Groq)
6. Add API key to `aegisdiff/config.py`
7. Add key to `PLATFORM_*` env vars in Vercel
8. Update `.github/workflows/aegisdiff.yml` env vars
