# AegisDiff

**Zero-cost autonomous AppSec triage for pull requests — hosted SaaS.**

AegisDiff is a managed platform. Connect your repo in one click — we run the scans.
No API keys. No infrastructure. No YAML files. No configuration.

**Platform cost to you: $0/month.**

---

## How It Works

```
PR opened in your repo
    │
    ▼
GitHub App webhook → Vercel (verify + dispatch, <1s)
    │
    ▼
repository_dispatch → AegisDiff Engine (GitHub Actions on our repo)
    │
    ├── Fetch diff via GitHub App installation token
    ├── AST parse → sink/source/data-flow extraction
    │   (Python, JS, TS, Go, Java, Ruby, PHP)
    ├── OpenRouter llama-3.3-70b:free (primary)
    │   └── 429 → rotate to next key/model
    ├── OpenRouter gemma-3-9b-it:free (secondary fallback)
    ├── GitHub Models Llama-3.3-70B (zero-config last resort, GITHUB_TOKEN)
    │
    ├── Inline PR review comment on the exact vulnerable line
    ├── Top-level PR summary comment
    ├── SARIF upload → GitHub Code Scanning (Security tab)
    └── Scan metadata sent to dashboard (no code, no diffs — metadata only)
```

**Verdicts:**

```
🚨 TRUE_POSITIVE   — Confirmed vulnerability (confidence ≥ 0.7)
⚠️  NEEDS_REVIEW   — Needs human judgment
✅ FALSE_POSITIVE  — Safe, framework handles it
❌ ERROR           — Engine failed (reason shown in dashboard)
```

---

## Quick Start — 4 clicks

1. Go to [aegis-diff.vercel.app](https://aegis-diff.vercel.app) → **Sign in with GitHub**
2. Click **Install AegisDiff on GitHub** → select repos → click **Install**
3. Open any pull request in a connected repo
4. Security verdict appears in the PR in ~90 seconds

**That's it. Zero configuration. Zero secrets. Zero YAML.**

> **Legacy / Self-Hosted:** You can also manually add `.github/workflows/aegisdiff.yml`
> to your repo. Supply `OPENROUTER_API_KEY` for unlimited scans, or omit it to
> use the platform's 100 scans/day free tier.

---

## Free Tier Limits

| Resource | Free tier |
|---|---|
| Scans | 100 per repo per day (platform AI keys) |
| Repos | Unlimited |
| Scan history | 30 days (configurable) |
| Webhooks | Slack, Discord, MS Teams |
| Dashboard users | Unlimited (RBAC-controlled) |
| Bring your own AI keys | Unlimited scans, bypasses rate limits |

---

## The Ghost Stack — $0/month to operate

| Layer | Service | Cost |
|---|---|---|
| Compute | GitHub Actions (AegisDiff's own repo, public = unlimited minutes) | $0 |
| Primary AI | OpenRouter llama-3.3-70b-instruct:free | Free |
| Secondary AI | OpenRouter gemma-3-9b-it:free (per-key fallback) | Free |
| Last-resort AI | GitHub Models Llama-3.3-70B (GITHUB_TOKEN, always present) | Free |
| Webhook handler | Vercel (Next.js 14) | Free tier: unlimited |
| Database | Neon PostgreSQL (serverless) | Free tier: 0.5 GB |
| Auth | NextAuth.js + GitHub OAuth + GitHub App | Free |
| Landing page | Cloudflare Pages | Free |

---

## Privacy — Your Code Never Leaves GitHub

- The GitHub App fetches your PR diff using a scoped installation token
- LLM calls are made from **AegisDiff's GitHub Actions runner** — your code
  goes directly from GitHub → OpenRouter/GitHub Models with no intermediate storage
- Only scan **metadata** reaches the dashboard: verdict, severity, CWE,
  confidence, title, timing
- **No code, no diffs, no evidence strings** are stored in any database
- Evidence (the vulnerable line) lives only in the GitHub PR comment — on GitHub's servers

---

## RBAC — Access Control

Roles are derived from your existing GitHub permissions. No manual user management.

| Role | Who | Can do |
|---|---|---|
| `platform:admin` | AegisDiff operator (env var) | Platform-wide stats, rate limit overrides, user management |
| `org:owner` | GitHub org owner | All org repos, org settings |
| `repo:admin` | GitHub repo admin | Configure webhooks, ignore rules, notification thresholds |
| `repo:developer` | GitHub repo write access | View scans, submit verdict feedback, trigger rescans |
| `repo:viewer` | GitHub repo read access | View scan results (read-only) |

Roles resolved at request time via GitHub API, cached per session (5 min TTL).
No separate role assignments. If you have write access on GitHub, you have it here.

---

## Analysis Pipeline

### Inline PR Review Comments
TRUE_POSITIVE findings are posted as inline review comments pinned to the exact
vulnerable line, not just a top-level comment. The top-level comment becomes
a summary (verdict + severity + CWE).

### Per-File Chunked Analysis
Diffs over 100 lines are split by file and analyzed independently. Each file gets
its own LLM call. Results are aggregated — highest severity becomes the PR verdict.
Multiple inline comments are posted (one per vulnerable file).

### SARIF / GitHub Code Scanning
Findings are uploaded to GitHub Code Scanning after every scan. They appear in
the repo's Security tab alongside Dependabot and CodeQL alerts.

### `aegisdiff-ignore` Suppression
```python
# aegisdiff-ignore: CWE-89 reason: test-only
result = cursor.execute(raw_sql)  # suppressed
```
Paste on or above a sink line. Suppressed sinks skip the LLM call entirely.

### AI Failover & Context Trimming

```
Provider priority (per scan):

User keys (OPENROUTER_API_KEY 1/2/3):
  1. OpenRouter llama-3.3-70b-instruct:free  (key 1)
  2. OpenRouter llama-3.3-70b-instruct:free  (key 2)
  3. OpenRouter llama-3.3-70b-instruct:free  (key 3)
  4. OpenRouter gemma-3-9b-it:free           (key 1)
  5. OpenRouter gemma-3-9b-it:free           (key 2)
  6. OpenRouter gemma-3-9b-it:free           (key 3)

Platform keys (via OIDC → /api/llm-token, 100 scans/day free):
  7-9.  OpenRouter llama-3.3-70b-instruct:free  (platform keys)
  10-12. OpenRouter gemma-3-9b-it:free          (platform keys)

Zero-config last resort (always present in Actions):
  13. GitHub Models Llama-3.3-70B-Instruct  (GITHUB_TOKEN)

429 → immediate rotation (no sleep)
413 → halve context scale (1.0→0.5→0.25→0.125) + retry same provider
All exhausted → sleep 30s → retry full list once → Verdict.error(reason)
```

---

## The Cynical AppSec Prompt

The AI follows a strict 5-step analysis protocol — **disprove before confirming:**

1. **Study the sink** — is this actually a dangerous operation?
2. **Trace the source** — is input user-controlled or a developer constant?
3. **Find the sanitizer first** — ORM binding, output encoding, allowlist?
4. **Assess reachability** — dead code? admin-only? internal network?
5. **Credit the framework** — Django ORM, React JSX, Rails erb are safe by default

**Hard calibration rules (non-negotiable):**
- `sanitizer_found = true` → verdict cannot be `TRUE_POSITIVE`
- `confidence < 0.5` → forced to `NEEDS_REVIEW`
- `TRUE_POSITIVE` requires `confidence ≥ 0.7`

---

## Security Test Fixtures

| Fixture | CWE | Pattern |
|---|---|---|
| `sample.diff` | CWE-78 + CWE-22 | `subprocess(shell=True)` + path traversal |
| `ssrf.diff` | CWE-918 | `requests.get(user_url)` |
| `ssti.diff` | CWE-94 | `Jinja2.Template(user_input).render()` |
| `hardcoded_secret.diff` | CWE-798 | AWS key + API tokens in source |
| `jwt_weak.diff` | CWE-327 | `jwt.verify` with `algorithms: ['none']` |
| `deserialization.diff` | CWE-502 | `pickle.loads(request.body)` |
| `xxe.diff` | CWE-611 | `lxml XMLParser(resolve_entities=True)` |
| `xss.diff` | CWE-79 | `dangerouslySetInnerHTML` with user content |
| `open_redirect.diff` | CWE-601 | `HttpResponseRedirect(request.GET['next'])` |
| `safe.diff` | — | Django ORM `.filter()` — expected FALSE_POSITIVE |

---

## Local Development

```bash
# Python engine
pip install -e .[dev]
pytest                              # ~231 tests, ~2.5s
ruff check aegisdiff/               # Lint (CI gate)
ruff format aegisdiff/              # Format

# Scan a local diff
python scripts/local_scan.py --diff path/to/your.diff

# Dashboard
cd web && npm install
npm run dev                         # http://localhost:3000
npm run build                       # Production build check
```

---

## Roadmap

### ✅ Phase 0 — Platform Key Distribution
Users need zero secrets. Runners exchange OIDC tokens for platform AI keys
at `/api/llm-token`. Rate-limited at 100 scans/day per repo on the free tier.
User-provided `OPENROUTER_API_KEY` always wins and bypasses limits.

### ✅ Phase 1 — RBAC + Admin Panel
Role-based access derived from GitHub org/repo permissions. Org owners see
all repos. Admins configure. Platform admin panel with Overview / Users /
Rate Limits / Failures tabs. Admin link in navbar (platform:admin only).

### ✅ Phase 2 — Inline PR Review Comments
Findings pinned to the exact vulnerable line, not just a top-level PR comment.
Summary comment shows verdict + severity + CWE. Both entrypoints (manual workflow
and GitHub App) post inline review comments.

### ✅ Phase 3 — Per-File Chunked Analysis
One verdict per changed file. Eliminates the "one verdict for 20 files" problem.
Aggregated by severity: worst finding becomes the PR verdict.

### ✅ Phase 4 — `aegisdiff-ignore` Inline Suppression
`# aegisdiff-ignore: CWE-89 reason: test-only` — standard SAST workflow.
Suppressed sinks skip the LLM call entirely. Suppressions persisted to dashboard.

### ✅ Phase 5 — Feedback Loop
"Mark FP / Mark TP" buttons in dashboard (developer+ role). FALSE_POSITIVE feedback
auto-adds to ignore rules. All corrections logged in audit trail.

### ✅ Phase 6 — Re-scan on Demand
`@aegisdiff rescan` in a PR comment triggers a fresh analysis without a commit.
Rate-limited: max 3 rescans/PR/hour. Dashboard "Re-scan" button also available.

### ✅ Phase 7 — SARIF / GitHub Code Scanning
TRUE_POSITIVE findings uploaded to GitHub Code Scanning API after every scan.
Appear in the repo's Security tab alongside Dependabot and CodeQL alerts.

### ✅ Phase 8 — Trend Analytics & SLA Tracking
Per-repo vulnerability velocity charts. Mean-time-to-fix tracking.
Weekly digest (Monday 09:00 UTC). SLA breach alerts (CRITICAL/HIGH unresolved > N days).

---

## Contributing

1. Fork and create a branch
2. Run `pytest` and `ruff check aegisdiff/` before submitting
3. The system prompt (`aegisdiff/triage/prompts.py`) is the most sensitive piece
4. Open a PR — AegisDiff will scan it automatically

---

## License

MIT
