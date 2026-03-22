# 🛡️ AegisDiff

**Zero-cost autonomous AppSec triage for pull requests.**

AegisDiff is an AI-powered security engine that analyzes every pull request diff for real vulnerabilities — and aggressively eliminates false positives. It acts as a cynical AppSec engineer who tries to *disprove* the vulnerability before confirming it.

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
    ├── Gemini 1.5 Pro (primary) ─── [fail] ──▶ Groq Llama-3 (fallback)
    │
    └── Verdict posted as PR comment + metadata sent to dashboard
```

**The verdict:**

```
✅ FALSE_POSITIVE  — Safe, ORM handles it
🚨 TRUE_POSITIVE   — SQL injection, user input → cursor.execute()
⚠️  NEEDS_REVIEW   — Concerning pattern, needs human review
```

---

## Quick Start (60 seconds)

### Step 1 — Add GitHub Secrets to your repo

Go to your repo → **Settings → Secrets → Actions** and add:

| Secret | Value |
|---|---|
| `GEMINI_API_KEY` | Get free at [aistudio.google.com](https://aistudio.google.com) |
| `GROQ_API_KEY` | Get free at [console.groq.com](https://console.groq.com) |
| `AEGISDIFF_REPO_TOKEN` | Generated when you connect the repo in the dashboard |
| `AEGISDIFF_INGEST_URL` | Your Vercel dashboard URL + `/api/ingest` |

### Step 2 — Add the workflow file

Copy `.github/workflows/aegisdiff.yml` from this repo into your repository.

### Step 3 — Open a test PR

Push any change to a Python, JavaScript, TypeScript, Go, Java, Ruby, or PHP file.
AegisDiff will analyze it and post a comment within ~90 seconds.

---

## The Ghost Stack — $0/month

| Layer | Service | Free Tier |
|---|---|---|
| Compute/Trigger | GitHub Actions | Unlimited (public repos), 2k min/month (private) |
| Primary AI | Google Gemini 1.5 Pro | 1,500 req/day · 1M token context |
| Fallback AI | Groq Llama-3-70b | 14,400 req/day · fast LPU inference |
| Secret Management | GitHub Actions Secrets | Unlimited |
| Dashboard | Vercel (Next.js) | Unlimited deploys, 100GB bandwidth |
| Database | Neon PostgreSQL | 0.5 GB (~1.6M scans with 90-day retention) |
| Landing Page | Cloudflare Pages | Unlimited static hosting |
| Auth | NextAuth.js + GitHub OAuth | Free |

> **GitHub Actions on public repos = unlimited minutes.** For private repos, the PR-only
> trigger (default) uses ~90–120 min/month for a small team — well within the 2k limit.

---

## AI Failover

AegisDiff uses **two AI providers** in priority order:

```
1. Google Gemini 1.5 Pro  (primary)
   └── Rate limited / down? → exponential backoff (2s, 4s, 8s)
   └── Still failing? → rotate to fallback

2. Groq Llama-3-70b  (fallback)
   └── Context trimmed automatically from 1M → 7k tokens
   └── Same retry logic applied
```

If both providers fail after 3 retries each, the verdict is `ERROR` and the scan
is marked as failed (does not block the PR).

---

## Privacy — Your Code Never Leaves GitHub

AegisDiff uses **Model A: Zero code egress**.

- The analysis engine runs **inside your GitHub Actions runner** — not on our servers
- Your API keys (Gemini, Groq) are stored in your GitHub Secrets — we never see them
- LLM calls are made **from your runner**, using your keys
- Only scan **metadata** is sent to the dashboard: verdict, severity, CWE, confidence, title
- **No code, no diffs, no evidence quotes** are stored in our database
- Evidence (code quotes) appears only in the GitHub PR comment — on GitHub's servers

---

## The Cynical AppSec Prompt

The AI is instructed to act as a skeptical AppSec engineer who:

1. Studies the sink — is this actually dangerous?
2. Traces the source — is input actually user-controlled?
3. **Finds the sanitizer first** — ORM? Escape function? Allowlist?
4. Assesses reachability — dead code, admin-only?
5. Credits the framework — Django ORM, React JSX, Rails erb are safe by default

**Calibration rules (hard-coded):**
- `sanitizer_found = true` → verdict cannot be `TRUE_POSITIVE`
- `confidence < 0.5` → forced to `NEEDS_REVIEW`
- `TRUE_POSITIVE` requires `confidence ≥ 0.7`

---

## Dashboard Setup

1. Deploy `web/` to Vercel (one-click from the Vercel dashboard)
2. Set environment variables in Vercel:
   - `DATABASE_URL` (Neon connection string)
   - `NEXTAUTH_SECRET` (`openssl rand -base64 32`)
   - `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` (GitHub OAuth App)
3. Run the DB schema: copy `web/lib/db.ts` → `SCHEMA_SQL` into the Neon SQL editor

---

## Local Development

```bash
# Python engine
pip install -e .[dev]
pytest

# Run against a local diff
python scripts/local_scan.py --diff path/to/your.diff

# Dashboard
cd web
npm install
npm run dev   # http://localhost:3000
```

---

## Contributing

1. Fork the repo and create a branch
2. Run `pytest` and `ruff check aegisdiff/` before submitting
3. The system prompt in `aegisdiff/triage/prompts.py` is the most sensitive piece — changes need careful justification
4. Open a PR — AegisDiff will analyze it automatically 🙂

---

## License

MIT
