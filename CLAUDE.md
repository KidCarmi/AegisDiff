# AegisDiff — Project Guide for AI Agents

## What Is This?

AegisDiff is a **zero-cost autonomous AppSec triage engine**. It analyzes pull request
diffs for security vulnerabilities using an AI "cynical AppSec engineer" — one that
tries to DISPROVE vulnerabilities rather than confirm them. Verdicts are posted as
GitHub PR comments and scan metadata is sent to a Next.js dashboard.

## $0/Month Constraint

This is a hard requirement. Every architectural decision must preserve this.
- No paid VMs, no persistent servers, no managed databases with charges
- See `README.md` → "The Ghost Stack" for the full service list

## Repository Structure

```
aegisdiff/       Python triage engine (runs in GitHub Actions)
web/             Next.js 14 App Router dashboard (deploy to Vercel)
landing/         Static landing page (deploy to Cloudflare Pages)
tests/           Pytest unit tests + security fixtures
  fixtures/      .diff files covering 9 CWE classes (see below)
scripts/         local_scan.py for manual testing
.github/
  workflows/
    aegisdiff.yml      Main triage workflow (pull_request trigger)
    ci.yml             Canary scan + self-scan + lint/test
    security.yml       SAST/SCA pipeline (Semgrep, Bandit, Trivy, Gitleaks)
    cleanup.yml        Daily DB retention cleanup
```

## Key Design Rules — DO NOT VIOLATE

1. **Never store code in the database.** The Neon DB stores only metadata: verdict,
   severity, CWE ID, confidence, title, provider, timing. No code quotes, no diffs,
   no evidence strings. Evidence lives ONLY in the GitHub PR comment.

2. **LLM provider priority is Gemini first, Groq second.** This order is set in
   `aegisdiff/entrypoint.py` and must not be reversed. Groq's limited context
   makes it unsuitable as primary for large diffs.

3. **Verdict JSON schema is backwards-compatible.** The `parse_verdict()` function in
   `aegisdiff/triage/verdicts.py` must always handle missing keys gracefully. New
   fields can be added but existing fields cannot be removed or renamed.

4. **All secrets via environment variables, never hardcoded.** See `aegisdiff/config.py`
   for the full list. In the dashboard, `NEXTAUTH_SECRET` is used for session signing.

5. **The confidence calibration rules in `verdicts.py` are non-negotiable:**
   - `TRUE_POSITIVE` requires `confidence >= 0.7`
   - `confidence < 0.5` forces `NEEDS_REVIEW`
   These rules protect against hallucinated high-confidence verdicts.

6. **`Verdict.error(reason)` uses reason as the title (truncated to 80 chars).**
   Never hardcode "Analysis engine error" — the actual failure reason must be visible
   in the dashboard so users can debug without reading Actions logs.

7. **Auth is OIDC-first.** The entrypoint calls `_get_oidc_token()` first, falls back
   to `AEGISDIFF_REPO_TOKEN` only for legacy repos. New installs need only
   `AEGISDIFF_INGEST_URL`. Do not add new token-based auth paths.

8. **Platform key distribution is the zero-config path.** After Phase 0 ships,
   the engine must NOT hard-exit when no user LLM keys are configured — it must
   first try `/api/llm-token` (OIDC-authenticated). Only exit if both user keys
   AND platform keys are unavailable. User-provided keys always take priority
   and bypass the 50/day rate limit.

8. **Groq context budget is 5,500 tokens.** The orchestrator halves `context_scale`
   on 413 responses (1.0 → 0.5 → 0.25 → 0.125) and retries the same provider before
   rotating. Do not raise this limit without testing against large real-world diffs.

## Dev Commands

```bash
# Python engine
pip install -e .[dev]           # Install with dev dependencies
pytest                          # Run all tests (63 tests, ~0.4s)
pytest tests/test_orchestrator.py -v  # Run specific test file
ruff check aegisdiff/           # Lint (must pass — CI gate)
ruff format aegisdiff/          # Format

# Local scan (against a local diff file)
python scripts/local_scan.py --diff path/to/file.diff

# Dashboard
cd web
npm install
npm run dev                     # http://localhost:3000
npm run build                   # Production build
```

## Test Fixtures

All fixtures live in `tests/fixtures/`. Each is a `.diff` file representing a real
vulnerability class. Tests in `test_engine.py` are grouped by CWE class and use mock
orchestrators — no real LLM calls are made in unit tests.

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

When adding a new fixture: add the `.diff` file, add a fixture in `conftest.py`,
add a test class in `test_engine.py` following the existing CWE class pattern.

## Critical Files

| File | Purpose |
|---|---|
| `aegisdiff/llm/orchestrator.py` | Failover + retry + adaptive 413 context trimming |
| `aegisdiff/llm/providers/groq.py` | Groq provider (max_context_tokens = 5,500) |
| `aegisdiff/llm/providers/gemini.py` | Gemini provider (max_context_tokens = 900k) |
| `aegisdiff/code_context/extractor.py` | AST parsing, sink/source detection |
| `aegisdiff/triage/prompts.py` | Cynical AppSec system prompt (quality driver) |
| `aegisdiff/triage/verdicts.py` | Verdict parsing + calibration rules |
| `aegisdiff/entrypoint.py` | Entry point: OIDC auth + ingest + PR comment |
| `aegisdiff/config.py` | All env var loading |
| `.github/workflows/aegisdiff.yml` | Workflow trigger + diff generation |
| `.github/workflows/ci.yml` | Canary + self-scan + lint/test |
| `.github/workflows/security.yml` | SAST/SCA security pipeline |
| `web/app/api/ingest/route.ts` | Receives scan metadata, fires webhooks, creates Issues |
| `web/app/api/v1/scans/route.ts` | Public REST API (Bearer ak_ keys) |
| `web/instrumentation.ts` | Auto-applies all DB migrations on cold start |
| `web/lib/db.ts` | Neon DB client + schema SQL |

## Dashboard API Surface

```
POST /api/ingest              Scan metadata from GitHub Actions (OIDC or Bearer)
GET  /api/repos               List repos for the session user
GET  /api/scans               Scan history (filters: repo, verdict, limit)
GET  /api/scans/export        CSV or SARIF 2.1.0 export
GET  /api/v1/scans            Public REST API (Bearer ak_ key required)
GET  /api/v1/key              Manage public API key
GET|PATCH /api/repos/[o]/[n]/slack     Slack webhook
GET|PATCH /api/repos/[o]/[n]/discord   Discord webhook
GET|PATCH /api/repos/[o]/[n]/teams     MS Teams webhook
GET|PATCH /api/repos/[o]/[n]/notify    Notification thresholds
GET|POST|DELETE /api/repos/[o]/[n]/ignore  Ignore rules
GET  /api/audit               Last 200 audit events
POST /api/admin/migrate       One-time manual migration (ADMIN_SECRET required)
```

## DB Schema (Neon PostgreSQL)

Tables managed by `web/instrumentation.ts` (idempotent `ALTER TABLE IF NOT EXISTS`):

- `installations` — GitHub App installs (owner, install_id)
- `repos` — connected repos + integration settings (slack/discord/teams webhooks,
  notify thresholds, auto_github_issue flag)
- `scans` — scan metadata (verdict, severity, cwe_id, confidence, title, provider,
  scan_ms, pr_number, commit_sha, pr_url, repo_owner, repo_name, created_at)
- `api_keys` — public REST API keys (key_hash SHA-256, name, last_used_at)
- `ignore_rules` — per-repo suppression rules (cwe_id or title_keyword)
- `audit_log` — action history (user, action, detail, created_at)

**Never add code/diff/evidence columns to any table.**

## Modifying the System Prompt

The system prompt is in `aegisdiff/triage/prompts.py` → `APPSEC_SYSTEM_PROMPT`.
It is the most important piece of the system. Changes must:
- Preserve the JSON verdict schema exactly (field names and types)
- Preserve the calibration rules section
- Not make the model more permissive (avoid relaxing the NEEDS_REVIEW triggers)

## Phases Roadmap

Work through phases in order. Do not start a phase until the previous is complete
and all tests pass.

### Phase 0 — Platform Key Distribution (TRUE zero-config)

**Goal:** Users add only `AEGISDIFF_INGEST_URL`. No `GEMINI_API_KEY`, no `GROQ_API_KEY`.
AegisDiff distributes its own platform LLM keys to authenticated runners via OIDC.
User-provided keys always win (no rate limit). Platform keys are rate-limited (50/day/repo).

**Privacy preserved:** Keys travel to the GitHub Actions runner. LLM calls are made
FROM the runner. The diff never leaves GitHub — only OIDC tokens reach AegisDiff.

**New Vercel env vars (set by the AegisDiff operator):**
- `PLATFORM_GEMINI_API_KEY` — AegisDiff's own Gemini key
- `PLATFORM_GROQ_API_KEY` — AegisDiff's own Groq key

**New endpoint — `web/app/api/llm-token/route.ts`:**
```
GET /api/llm-token
Authorization: Bearer <github-oidc-jwt>

Response 200:
{ "gemini_key": "...", "groq_key": "...", "expires_at": "<ISO>" }

Response 429:
{ "error": "Rate limit: 50 scans/day per repo on free tier" }
```
- Verify OIDC JWT (same `verifyOIDC()` used by `/api/ingest`)
- Count `scans` rows for this repo in the last 24 hours
- If count >= 50, return 429 with a clear message
- Otherwise return `PLATFORM_GEMINI_API_KEY` + `PLATFORM_GROQ_API_KEY` from env
- Write the key fetch to `audit_log` (action: "llm_key_issued")

**Changes to `aegisdiff/entrypoint.py`:**
```python
def _fetch_platform_keys(ingest_url: str, oidc_token: str) -> dict:
    """Fetch platform LLM keys from AegisDiff when user has none configured."""
    base = ingest_url.removesuffix("/api/ingest").rstrip("/")
    resp = httpx.get(
        f"{base}/api/llm-token",
        headers={"Authorization": f"Bearer {oidc_token}"},
        timeout=10.0,
    )
    if resp.status_code == 429:
        logger.warning("Platform key rate limit reached: %s", resp.json().get("error"))
        return {}
    resp.raise_for_status()
    return resp.json()
```

In `main()`, replace the hard exit when no keys are found:
```python
# Try platform keys before giving up
if not cfg.gemini_api_key and not groq_keys and cfg.aegisdiff_ingest_url:
    oidc = _get_oidc_token()
    if oidc:
        platform = _fetch_platform_keys(cfg.aegisdiff_ingest_url, oidc)
        gemini_key = platform.get("gemini_key", "")
        groq_key = platform.get("groq_key", "")
        if not gemini_key and not groq_key:
            logger.error("No keys available (platform rate limit or no AEGISDIFF_INGEST_URL)")
            sys.exit(1)
        # rebuild providers with platform keys
        ...
```

**Changes to `aegisdiff/config.py`:** No change needed — the platform key fetch
happens in `entrypoint.py` after config load, before provider construction.

**Changes to `.github/workflows/aegisdiff.yml`:**
- Remove `GEMINI_API_KEY` and `GROQ_API_KEY` from the required secrets docs
- Keep them as optional pass-through (if set, they take priority)
- Update the `Run AegisDiff triage` step comment

**Rate limit table (stored in DB `scans`, not a separate table):**
```sql
SELECT COUNT(*) FROM scans
WHERE repo_owner = $1 AND repo_name = $2
  AND created_at > NOW() - INTERVAL '24 hours'
```

**Tests:**
- `tests/test_entrypoint.py` — mock `_fetch_platform_keys`, verify it's called when
  no user keys are set; verify user keys skip the fetch entirely
- Test 429 handling: engine exits 1 with a clear message, not a traceback

### Phase 1 — Inline PR Review Comments
**Goal:** Post findings as inline review comments pinned to the exact vulnerable line,
not just a top-level PR comment.

- `aegisdiff/github/client.py` — add `create_review_with_comments(pr, commit_sha, comments)`
- `aegisdiff/triage/verdicts.py` — add `line_number: Optional[int]` to Verdict
- `aegisdiff/code_context/extractor.py` — ensure sink line number is always populated
- `aegisdiff/entrypoint.py` — call `create_review_with_comments` when line number available;
  fall back to top-level comment when line number is unknown
- `aegisdiff/github/pr_comment.py` — keep top-level comment as summary; inline comment
  contains the evidence quote and remediation
- Tests: add `test_github_client.py` covering review comment creation (mock GitHub API)

### Phase 2 — Per-Hunk Analysis
**Goal:** Analyze each changed file independently for large PRs; aggregate results.

- `aegisdiff/triage/engine.py` — add `analyze_diff_chunked(diff)`: splits by
  `diff --git` headers, analyzes each file diff separately, returns list of Verdicts
- Aggregate: if any chunk is TRUE_POSITIVE, overall is TRUE_POSITIVE (highest severity wins)
- `aegisdiff/entrypoint.py` — use chunked analysis when diff > 100 lines
- Dashboard: ingest accepts array of scan results for one PR (one row per finding)
- Tests: fixture with 3-file diff where one file is safe and one is vulnerable

### Phase 3 — `aegisdiff-ignore` Inline Suppression
**Goal:** Developers suppress known FPs with a comment directly in code.

- Pattern: `# aegisdiff-ignore: CWE-89 reason: test-only code`
  (also `// aegisdiff-ignore:` for JS/TS)
- `aegisdiff/code_context/extractor.py` — scan diff lines for ignore comments;
  annotate affected sinks as suppressed
- `aegisdiff/triage/engine.py` — if sink is suppressed, return FALSE_POSITIVE
  with `false_positive_reason = "Suppressed by aegisdiff-ignore comment"`
- `web/app/api/ingest/route.ts` — write suppression to `ignore_rules` table
- Tests: fixture with ignore comment on the vulnerable line

### Phase 4 — Feedback Loop ("Wrong verdict" button)
**Goal:** Developers can correct verdicts from the dashboard; corrections feed back
into ignore rules and future prompt calibration.

- `web/app/api/scans/[id]/feedback/route.ts` — POST `{correct_verdict, reason}`
- `web/components/ScanCard.tsx` — add thumbs up/down UI
- On FALSE_POSITIVE feedback for a TRUE_POSITIVE: auto-add to `ignore_rules`
- On TRUE_POSITIVE feedback for a FALSE_POSITIVE: flag for manual review
- Write all feedback to `audit_log`
- Future: export feedback corpus for prompt fine-tuning

### Phase 5 — Re-scan on Demand
**Goal:** `@aegisdiff rescan` PR comment triggers a fresh scan without pushing a commit.

- `web/app/api/webhooks/github/route.ts` — handle `issue_comment` webhook event;
  detect `@aegisdiff rescan` (case-insensitive)
- Trigger `aegisdiff.yml` via `repository_dispatch` event
- Rate-limit: max 3 rescans per PR per hour (tracked in `audit_log`)
- Post acknowledgement comment: "Re-scan triggered — results in ~90s"

## Adding a New LLM Provider

1. Create `aegisdiff/llm/providers/your_provider.py` implementing `LLMProvider`
2. Set `name`, `model`, `max_context_tokens` class attributes
3. Implement `complete(request) -> LLMResponse` and `is_retryable_error(exc) -> bool`
4. Ensure `is_retryable_error` returns `False` for 413 (handled by orchestrator)
5. Add the provider to the list in `aegisdiff/entrypoint.py` (after Groq)
6. Add the API key to `aegisdiff/config.py`
7. Update `.github/workflows/aegisdiff.yml` to pass the new key as an env var
