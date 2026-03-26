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
    ├── Fetch diff via GitHub App token
    ├── AST parse → sink/source/data-flow extraction
    ├── Per-file chunked analysis (one verdict per changed file)
    ├── aegisdiff-ignore comments → suppressed without LLM call
    ├── Gemini 1.5 Pro (primary) ──[fail]──▶ Groq Llama-3 (fallback)
    │
    ├── Inline PR review comment on the exact vulnerable line
    ├── Top-level PR summary comment
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

1. Go to [app.aegisdiff.io](https://app.aegisdiff.io) → **Sign in with GitHub**
2. Click **Install AegisDiff on GitHub** → select repos → click **Install**
3. Open any pull request in a connected repo
4. Security verdict appears in the PR in ~90 seconds

**That's it. Zero configuration. Zero secrets. Zero YAML.**

> **Legacy / Self-Hosted:** You can also manually add `.github/workflows/aegisdiff.yml`
> to your repo and supply your own `GEMINI_API_KEY`. The GitHub App path is recommended.

---

## Free Tier Limits

| Resource | Free tier |
|---|---|
| Scans | 50 per repo per day (platform AI keys) |
| Repos | Unlimited |
| Scan history | 30 days |
| Webhooks | Slack, Discord, MS Teams |
| Dashboard users | Unlimited (RBAC-controlled) |
| Bring your own AI keys | Unlimited scans, bypasses rate limits |

---

## The Ghost Stack — $0/month to operate

| Layer | Service | Cost |
|---|---|---|
| Compute | GitHub Actions (AegisDiff's own repo, public = unlimited) | $0 |
| Primary AI | Google Gemini 1.5 Pro | Free tier: 1,500 req/day |
| Fallback AI | Groq Llama-3.3-70b | Free tier: 14,400 req/day |
| Webhook handler | Vercel (Next.js 14) | Free tier: unlimited |
| Database | Neon PostgreSQL (serverless) | Free tier: 0.5 GB |
| Auth | NextAuth.js + GitHub OAuth + GitHub App | Free |
| Landing page | Cloudflare Pages | Free |

---

## Privacy — Your Code Never Leaves GitHub

- The GitHub App fetches your PR diff using a scoped installation token
- LLM calls are made from **AegisDiff's GitHub Actions runner** — your code
  goes directly from GitHub → Gemini/Groq with no intermediate storage
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

### Per-File Chunked Analysis (Phase 3)
Large diffs are split by `diff --git` header and analyzed independently.
Each file gets its own verdict. The worst finding is selected as the PR verdict.
Accurate per-file line numbers for inline comments.

### Inline PR Review Comments (Phase 2)
TRUE_POSITIVE findings are posted as inline comments pinned to the exact
vulnerable line, not just a top-level comment. The top-level comment becomes
a summary (verdict + severity + CWE).

### `aegisdiff-ignore` Suppression (Phase 4)
```python
# aegisdiff-ignore: CWE-89 reason: test-only fixture
cursor.execute(f"SELECT * FROM {table}")
```
Add a comment on or above any sink. AegisDiff short-circuits to FALSE_POSITIVE
without making an LLM call. Standard SAST workflow.

### Feedback Loop (Phase 5)
Dashboard shows 👍 / 👎 buttons on each scan card (repo:developer+).
- 👍 on a TRUE_POSITIVE → marks as false positive, auto-adds to ignore rules
- 👎 on a FALSE_POSITIVE → marks as missed finding
All corrections written to audit log.

### AI Failover & Context Trimming

```
1. Google Gemini 1.5 Pro  (primary — 1M token context)
   └── 429 / 5xx → exponential backoff (2s, 4s, 8s) then rotate

2. Groq Llama-3.3-70b  (fallback — 5,500 token effective budget)
   └── 413 Payload Too Large → halve context scale (1.0→0.5→0.25→0.125) + retry

Both exhausted → Verdict.error(reason) — reason visible in dashboard title
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
pytest                              # 63 tests, ~0.4s
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
at `/api/llm-token`. Rate-limited at 50 scans/day per repo on the free tier.
User-provided keys always win and bypass limits.

### ✅ Phase 1 — RBAC
Role-based access derived from GitHub org/repo permissions. Org owners see
all repos. Admins configure. Developers view and give feedback. Platform admin
panel for the operator.

### ✅ Phase 2 — Inline PR Review Comments
Findings pinned to the exact vulnerable line, not just a top-level PR comment.

### ✅ Phase 3 — Per-File Chunked Analysis
One verdict per changed file. Eliminates the "one verdict for 20 files" problem.
Aggregated by severity: worst finding becomes the PR verdict.

### ✅ Phase 4 — `aegisdiff-ignore` Inline Suppression
`# aegisdiff-ignore: CWE-89 reason: test-only` — standard SAST workflow.
Suppressed sinks skip the LLM call entirely.

### ✅ Phase 5 — Feedback Loop
👍 / 👎 buttons in dashboard. FALSE_POSITIVE feedback auto-adds to ignore rules.
All corrections in audit log.

### Phase 6 — Re-scan on Demand
`@aegisdiff rescan` in a PR comment triggers a fresh analysis without a commit.
Rate-limited: max 3 rescans/PR/hour.

### Phase 7 — SARIF Export + GitHub Code Scanning Integration
Export findings as SARIF. Integrate with GitHub's native Security tab so
findings appear alongside Dependabot and CodeQL alerts.

### Phase 8 — Trend Analytics & SLA Tracking
Per-repo vulnerability velocity charts. Mean-time-to-fix tracking.
Weekly digest emails. SLA breach alerts (e.g. HIGH unresolved > 7 days).

---

## Contributing

1. Fork and create a branch
2. Run `pytest` and `ruff check aegisdiff/` before submitting
3. The system prompt (`aegisdiff/triage/prompts.py`) is the most sensitive piece
4. Open a PR — AegisDiff will scan it automatically

---

## License

MIT
