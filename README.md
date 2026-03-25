# AegisDiff

**Zero-cost autonomous AppSec triage for pull requests.**

AegisDiff is an AI-powered security engine that analyzes every PR diff for real vulnerabilities — and aggressively eliminates false positives. It acts as a cynical AppSec engineer who tries to *disprove* the vulnerability before confirming it.

**Total infrastructure cost: $0/month.**

---

## How It Works

```
PR opened
    │
    ▼
GitHub Actions Runner (your environment — code never leaves GitHub)
    │
    ├── git diff → changed source files
    ├── AST parse → sink/source/data-flow extraction
    ├── Gemini 1.5 Pro (primary) ─── [fail/413] ──▶ Groq Llama-3 (fallback)
    │       └── adaptive context trimming on 413 Payload Too Large
    │
    ├── Verdict posted as PR comment + commit status
    └── Scan metadata sent to dashboard (no code, no diffs)
```

**Verdicts:**

```
✅ FALSE_POSITIVE  — Safe, framework/ORM handles it
🚨 TRUE_POSITIVE   — Confirmed vulnerability (confidence ≥ 0.7)
⚠️  NEEDS_REVIEW   — Concerning pattern, needs human judgment
❌ ERROR           — Engine failed (reason shown in dashboard)
```

---

## Quick Start (60 seconds)

### Step 1 — Add one secret to your repo

**Settings → Secrets → Actions:**

| Secret | Value |
|---|---|
| `AEGISDIFF_INGEST_URL` | Your Vercel deployment URL + `/api/ingest` |

That's it. No Gemini key. No Groq key. AegisDiff provides the AI backbone.

> **Bring your own keys for unlimited scans.**
> Add `GEMINI_API_KEY` and/or `GROQ_API_KEY` to use your own free-tier quota
> instead of the platform quota. Your keys always take priority.

### Step 2 — Add the workflow

Copy `.github/workflows/aegisdiff.yml` into your repository's `.github/workflows/`.

### Step 3 — Open a test PR

Push any change to a `.py`, `.js`, `.ts`, `.tsx`, `.go`, `.java`, `.rb`, or `.php` file.
AegisDiff will analyze it and post a comment within ~90 seconds.

---

## The Ghost Stack — $0/month

| Layer | Service | Free Tier |
|---|---|---|
| Compute | GitHub Actions | Unlimited (public), 2k min/month (private) |
| Primary AI | Google Gemini 1.5 Pro | 1,500 req/day · 1M token context |
| Fallback AI | Groq Llama-3.3-70b | 14,400 req/day · fast LPU inference |
| Dashboard | Vercel (Next.js 14) | Unlimited deploys, 100 GB bandwidth |
| Database | Neon PostgreSQL (serverless) | 0.5 GB, auto-suspend |
| Auth | NextAuth.js + GitHub OAuth | Free |
| Landing Page | Cloudflare Pages | Unlimited static hosting |

> Public repos get **unlimited** Actions minutes. Private repos use ~90–120 min/month
> on a small team — well within the 2k free tier.

---

## Privacy — Your Code Never Leaves GitHub

- Analysis runs **inside your GitHub Actions runner** — not on AegisDiff servers
- Your LLM API keys live in **your GitHub Secrets** — never transmitted to us
- LLM calls are made **from your runner** using your keys
- Only scan **metadata** reaches the dashboard: verdict, severity, CWE, confidence, title, timing
- **No code, no diffs, no evidence strings** are stored in the database
- Evidence (the vulnerable line) lives only in the GitHub PR comment — on GitHub's servers

---

## Features

### Engine
- AST-based sink/source/data-flow extraction (Python; heuristic for JS/TS/Go/Java)
- Cynical AppSec system prompt — tries to disprove before confirming
- Hard calibration rules: `TRUE_POSITIVE` requires `confidence ≥ 0.7`; `confidence < 0.5` forces `NEEDS_REVIEW`
- Adaptive context trimming: automatic halving on Groq 413 responses
- Provider failover with exponential backoff (Gemini → Groq, 3 retries each)
- Error reason surfaced in dashboard title (not just "Analysis engine error")

### Dashboard (web/)
- Scan history with filter pills (All / Issues / Review / Clean) and full-text search
- Per-repo detail page: 30-day stats, top CWEs, recent scan history
- Security score per repo (100 − TP rate over 30 days), color-coded
- Weekly trend chart
- Guided onboarding wizard (4-step)

### Integrations
- Slack, Discord, MS Teams webhooks with per-repo notification thresholds
- GitHub Issues auto-creation on TRUE_POSITIVE (via GitHub App JWT)
- SARIF 2.1.0 export for GitHub Security tab
- CSV export
- Public REST API (`ak_` bearer keys, filters by repo/verdict/severity)
- Ignore rules by CWE or title keyword
- Audit log

### CI (this repo)
- Canary scan: always scans `tests/fixtures/sample.diff` (known cmd injection + path traversal)
- Self-scan (dogfood): scans every PR's own diff
- Security pipeline: Gitleaks · Semgrep · Bandit · Trivy · pip-audit · npm-audit

---

## AI Failover & Context Trimming

```
1. Google Gemini 1.5 Pro  (primary — 1M token context)
   └── 429 / 5xx → exponential backoff (2s, 4s, 8s)
   └── Still failing → rotate to Groq

2. Groq Llama-3.3-70b  (fallback — 5,500 token effective budget)
   └── 413 Payload Too Large → halve context (1.0 → 0.5 → 0.25 → 0.125) + retry
   └── Context trimmed at <<<CODE>>> block boundary
   └── 429 / 5xx → same backoff logic

Both exhausted → Verdict.error(reason) — reason visible in dashboard
```

---

## The Cynical AppSec Prompt

The AI follows a strict analysis protocol:

1. **Study the sink** — is this actually a dangerous operation?
2. **Trace the source** — is the input user-controlled or a developer constant?
3. **Find the sanitizer first** — ORM binding, output encoding, allowlist?
4. **Assess reachability** — dead code, admin-only, internal network?
5. **Credit the framework** — Django ORM, React JSX, Rails erb are safe by default

**Hard calibration rules:**
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

## Dashboard Setup

1. Deploy `web/` to Vercel
2. Set environment variables:
   - `DATABASE_URL` — Neon PostgreSQL connection string
   - `NEXTAUTH_SECRET` — `openssl rand -base64 32`
   - `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` — GitHub OAuth App
3. Schema migrations run automatically on first cold start (`web/instrumentation.ts`)

---

## Local Development

```bash
# Python engine
pip install -e .[dev]
pytest                              # 63 tests
ruff check aegisdiff/               # Lint
ruff format aegisdiff/              # Format

# Scan a local diff file
python scripts/local_scan.py --diff path/to/your.diff

# Dashboard
cd web && npm install
npm run dev                         # http://localhost:3000
npm run build                       # Production build check
```

---

## How Platform Keys Work

When you don't provide your own `GEMINI_API_KEY`/`GROQ_API_KEY`, the engine
fetches short-lived platform keys from AegisDiff before each scan:

```
GitHub Actions runner
    │
    ├── 1. Get OIDC token (audience: aegisdiff) — auto, no config
    ├── 2. POST /api/llm-token  ← exchanges OIDC for platform LLM keys
    │         └── rate limited: 50 scans/day per repo (free tier)
    ├── 3. Call Gemini/Groq directly FROM the runner using those keys
    └── 4. Your diff never leaves GitHub — only tokens travel to AegisDiff
```

**Bring your own keys = unlimited.** Set `GEMINI_API_KEY` in your repo secrets
and the platform key step is skipped entirely.

---

## Roadmap

### Phase 0 — Platform Key Distribution ← next
`/api/llm-token` endpoint: OIDC-authenticated runners exchange their GitHub
token for AegisDiff's own Gemini/Groq keys. **Users need zero API keys.**
Rate-limited at 50 scans/day per repo on the free tier. User-provided keys
always take priority and bypass the limit entirely.

### Phase 1 — Inline PR Review Comments
Post findings as inline review comments pinned to the exact vulnerable line,
not just a top-level PR comment. What developers actually expect from a SAST tool.

### Phase 2 — Per-Hunk Analysis
Split large PRs by file/hunk, analyze each independently, aggregate results.
Eliminates the "one verdict for 20 files" problem.

### Phase 3 — `aegisdiff-ignore` Inline Suppression
`// aegisdiff-ignore: CWE-89 reason: test-only code` — standard SAST workflow,
lets teams silence known false positives without touching the dashboard.

### Phase 4 — Feedback Loop
"Wrong verdict" button in the dashboard. Stores developer corrections,
auto-adds to ignore rules, feeds into prompt calibration over time.

### Phase 5 — Re-scan on Demand
`@aegisdiff rescan` PR comment command triggers a fresh analysis.
Closes the loop after a developer fixes the flagged issue.

---

## Contributing

1. Fork and create a branch
2. Run `pytest` and `ruff check aegisdiff/` before submitting
3. The system prompt (`aegisdiff/triage/prompts.py`) is the most sensitive piece — changes need careful justification
4. Open a PR — AegisDiff will scan it automatically

---

## License

MIT
