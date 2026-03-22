# AegisDiff — Project Guide for AI Agents

## What Is This?

AegisDiff is a **zero-cost autonomous AppSec triage engine**. It analyzes pull request
diffs for security vulnerabilities using an AI "cynical AppSec engineer" — one that
tries to DISPROVE vulnerabilities rather than confirm them. Verdicts are posted as
GitHub PR comments.

## $0/Month Constraint

This is a hard requirement. Every architectural decision must preserve this.
- No paid VMs, no persistent servers, no managed databases with charges
- See `README.md` → "The Ghost Stack" for the full service list

## Repository Structure

```
aegisdiff/       Python triage engine (runs in GitHub Actions)
web/             Next.js dashboard (deploy to Vercel)
landing/         Static landing page (deploy to Cloudflare Pages)
tests/           Pytest unit tests for the Python engine
.github/
  workflows/
    aegisdiff.yml  Main triage workflow (triggered on pull_request)
    cleanup.yml    Daily DB retention cleanup
```

## Key Design Rules — DO NOT VIOLATE

1. **Never store code in the database.** The Neon DB stores only metadata: verdict,
   severity, CWE ID, confidence, title, provider, timing. No code quotes, no diffs,
   no evidence strings. Evidence lives ONLY in the GitHub PR comment.

2. **LLM provider priority is Gemini first, Groq second.** This order is set in
   `aegisdiff/entrypoint.py` and must not be reversed. Groq's 8k context window
   makes it unsuitable as the primary for large diffs.

3. **Verdict JSON schema is backwards-compatible.** The `parse_verdict()` function in
   `aegisdiff/triage/verdicts.py` must always handle missing keys gracefully. New
   fields can be added but existing fields cannot be removed or renamed.

4. **All secrets via environment variables, never hardcoded.** See `aegisdiff/config.py`
   for the full list. In the dashboard, `NEXTAUTH_SECRET` is used for session signing.

5. **The confidence calibration rules in `verdicts.py` are non-negotiable:**
   - `TRUE_POSITIVE` requires `confidence >= 0.7`
   - `confidence < 0.5` forces `NEEDS_REVIEW`
   These rules protect against hallucinated high-confidence verdicts.

## Dev Commands

```bash
# Python engine
pip install -e .[dev]           # Install with dev dependencies
pytest                          # Run all tests (with coverage)
pytest tests/test_orchestrator.py -v  # Run specific test file
ruff check aegisdiff/           # Lint
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

`tests/fixtures/sample.diff` — Contains a deliberate SQLi + cmd injection.
Expected: `TRUE_POSITIVE` verdict.

`tests/fixtures/safe.diff` — Django ORM `.filter()` call (safe by design).
Expected: `FALSE_POSITIVE` verdict.

## Critical Files

| File | Purpose |
|---|---|
| `aegisdiff/llm/orchestrator.py` | Failover + retry + context trimming |
| `aegisdiff/code_context/extractor.py` | AST parsing, sink/source detection |
| `aegisdiff/triage/prompts.py` | Cynical AppSec system prompt (quality driver) |
| `aegisdiff/triage/verdicts.py` | Verdict parsing + calibration rules |
| `.github/workflows/aegisdiff.yml` | Workflow trigger + diff generation |
| `aegisdiff/entrypoint.py` | Entry point called by GitHub Actions |
| `web/app/api/ingest/route.ts` | Receives scan metadata from Actions |
| `web/lib/db.ts` | Neon DB client + schema SQL |

## Modifying the System Prompt

The system prompt is in `aegisdiff/triage/prompts.py` → `APPSEC_SYSTEM_PROMPT`.
It is the most important piece of the system. Changes must:
- Preserve the JSON verdict schema exactly (field names and types)
- Preserve the calibration rules section
- Not make the model more permissive (avoid relaxing the NEEDS_REVIEW triggers)

## Adding a New LLM Provider

1. Create `aegisdiff/llm/providers/your_provider.py` implementing `LLMProvider`
2. Set `name`, `model`, `max_context_tokens` class attributes
3. Implement `complete(request) -> LLMResponse` and `is_retryable_error(exc) -> bool`
4. Add the provider to the list in `aegisdiff/entrypoint.py` (after Groq)
5. Add the API key to `aegisdiff/config.py`
6. Update `.github/workflows/aegisdiff.yml` to pass the new key as an env var
