# AegisDiff

**Zero-cost autonomous AppSec triage for pull requests — hosted SaaS.**

AegisDiff is a managed platform. You connect your repos, we run the scans.
No API keys. No infrastructure. No configuration beyond adding one workflow file.

**Platform cost to you: $0/month.**

---

## How It Works

```
PR opened in your repo
    │
    ▼
GitHub Actions (runs in YOUR environment — your code never leaves GitHub)
    │
    ├── git diff → changed files
    ├── AST parse → sink/source/data-flow extraction
    ├── GET /api/llm-token  ← OIDC-authenticated, gets platform AI keys
    ├── Gemini 1.5 Pro (primary) ──[fail]──▶ Groq Llama-3 (fallback)
    │
    ├── Verdict posted as inline PR review comment + commit status
    └── Scan metadata sent to dashboard (no code, no diffs — metadata only)
```

**Verdicts:**

```
✅ FALSE_POSITIVE  — Safe, framework handles it
🚨 TRUE_POSITIVE   — Confirmed vulnerability (confidence ≥ 0.7)
⚠️  NEEDS_REVIEW   — Needs human judgment
❌ ERROR           — Engine failed (reason shown in dashboard)
```

---

## Quick Start — 2 steps

### Step 1 — Sign up

Go to [app.aegisdiff.io](https://app.aegisdiff.io) and sign in with GitHub.
Connect your repository. Done — no API keys, no configuration.

### Step 2 — Add the workflow

Copy `.github/workflows/aegisdiff.yml` into your repo. The workflow will
automatically authenticate via GitHub OIDC — no secrets needed.

> **Want unlimited scans?** Add your own `GEMINI_API_KEY` and/or `GROQ_API_KEY`
> as repo secrets. Your keys take priority and bypass platform rate limits.

---

## Free Tier Limits

| Resource | Free tier |
|---|---|
| Scans | 50 per repo per day (platform AI keys) |
| Repos | Unlimited |
| Scan history | 30 days |
| Webhooks | Slack, Discord, MS Teams |
| Dashboard users | Unlimited (RBAC-controlled) |
| Bring your own AI keys | Unlimited scans |

---

## The Ghost Stack — $0/month to operate

| Layer | Service | Cost |
|---|---|---|
| Compute | GitHub Actions (runs in user's environment) | $0 — user's quota |
| Primary AI | Google Gemini 1.5 Pro | Free tier: 1,500 req/day |
| Fallback AI | Groq Llama-3.3-70b | Free tier: 14,400 req/day |
| Dashboard | Vercel (Next.js 14) | Free tier: unlimited deploys |
| Database | Neon PostgreSQL (serverless) | Free tier: 0.5 GB |
| Auth | NextAuth.js + GitHub OAuth | Free |

---

## Privacy — Your Code Never Leaves GitHub

- Analysis runs **inside your GitHub Actions runner** — not on AegisDiff servers
- AegisDiff distributes temporary AI keys to your runner via OIDC token exchange
- LLM calls are made **from your runner** directly to Gemini/Groq — AegisDiff never sees your code
- Only scan **metadata** reaches the dashboard: verdict, severity, CWE, confidence, title, timing
- **No code, no diffs, no evidence strings** are stored in any database
- Evidence (the vulnerable line) lives only in the GitHub PR comment — on GitHub's servers

---

## RBAC — Access Control

AegisDiff derives roles from your existing GitHub permissions. No manual user management.

| Role | Who | Can do |
|---|---|---|
| `org:owner` | GitHub org owner | See all org repos, manage org settings, invite members |
| `repo:admin` | GitHub repo admin | Configure webhooks, ignore rules, notification thresholds |
| `repo:developer` | GitHub repo write access | View scans, submit feedback, trigger rescans |
| `repo:viewer` | GitHub repo read access | View scan results (read-only) |
| `platform:admin` | AegisDiff operator | Platform-wide stats, rate limit overrides, user management |

Roles are resolved at request time via the GitHub API and cached per session.
No separate role assignments needed — if you have write access on GitHub, you have it here.

---

## AI Failover & Context Trimming

```
1. Google Gemini 1.5 Pro  (primary — 1M token context)
   └── 429 / 5xx → exponential backoff (2s, 4s, 8s) then rotate

2. Groq Llama-3.3-70b  (fallback — 5,500 token effective budget)
   └── 413 Payload Too Large → halve context scale (1.0→0.5→0.25→0.125) + retry
   └── Context trimmed at <<<CODE>>> block boundary

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
pytest                              # 63 tests
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

### Phase 0 — Platform Key Distribution ← in progress
Users need zero secrets. Runners exchange OIDC tokens for platform AI keys
at `/api/llm-token`. Rate-limited at 50 scans/day per repo on the free tier.
User-provided keys always win and bypass limits.

### Phase 1 — RBAC
Role-based access derived from GitHub org/repo permissions. Org owners see
all repos. Admins configure. Developers view and give feedback. Platform admin
panel for the operator.

### Phase 2 — Inline PR Review Comments
Findings pinned to the exact vulnerable line, not just a top-level PR comment.

### Phase 3 — Per-Hunk Analysis
One verdict per changed file. Eliminates the "one verdict for 20 files" problem.

### Phase 4 — `aegisdiff-ignore` Inline Suppression
`// aegisdiff-ignore: CWE-89 reason: test-only code` — standard SAST workflow.

### Phase 5 — Feedback Loop
"Wrong verdict" button → auto-adds to ignore rules, feeds prompt calibration.

### Phase 6 — Re-scan on Demand
`@aegisdiff rescan` in a PR comment triggers a fresh analysis.

---

## Contributing

1. Fork and create a branch
2. Run `pytest` and `ruff check aegisdiff/` before submitting
3. The system prompt (`aegisdiff/triage/prompts.py`) is the most sensitive piece
4. Open a PR — AegisDiff will scan it automatically

---

## License

MIT
