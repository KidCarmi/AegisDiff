"""
AegisDiff GitHub App entry point.

Called by the `aegisdiff-app.yml` workflow which is triggered by a
`repository_dispatch` event (type: analyze_pr) from our Vercel webhook
handler.  Authenticates as the GitHub App, fetches the PR diff, runs
the triage engine, posts the comment, and sends metadata to the dashboard.

Environment variables (all passed by the workflow):
  GITHUB_APP_ID             — numeric GitHub App ID
  GITHUB_APP_PRIVATE_KEY    — RSA private key PEM (newlines can be \\n escaped)
  INSTALLATION_ID           — GitHub App installation ID for the target repo
  TARGET_REPO               — "owner/name"
  PR_NUMBER                 — pull request number
  COMMIT_SHA                — head commit SHA
  OPENROUTER_API_KEY        — LLM key 1 (from our repo secrets)
  OPENROUTER_API_KEY_2      — LLM key 2
  OPENROUTER_API_KEY_3      — LLM key 3
  GITHUB_TOKEN              — auto-injected by Actions; used as GitHub Models fallback
  AEGISDIFF_INGEST_URL      — dashboard ingest endpoint (passed via dispatch)
  AEGISDIFF_INGEST_TOKEN    — per-repo ingest token (passed via dispatch)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("aegisdiff.app_entrypoint")

from .sentry import init_sentry  # noqa: E402

init_sentry(release="aegisdiff@app-entrypoint")


def _get_env(key: str, required: bool = True) -> str:
    val = os.environ.get(key, "")
    if required and not val:
        logger.error("Missing required environment variable: %s", key)
        sys.exit(1)
    return val


def _build_item(verdict, pr_number: int, commit_sha: str, repo: str, scan_ms: int) -> dict:
    return {
        "verdict": verdict.verdict.value,
        "severity": verdict.severity.value,
        "cwe_id": verdict.cwe_id,
        "confidence": verdict.confidence,
        "title": verdict.title,
        "provider": verdict.provider,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "pr_url": f"https://github.com/{repo}/pull/{pr_number}",
        "scan_ms": scan_ms,
    }


def _send_to_ingest(
    ingest_url: str,
    ingest_token: str,
    verdicts,
    pr_number: int,
    commit_sha: str,
    repo: str,
    scan_ms: int,
) -> None:
    from .triage.verdicts import Verdict as _Verdict

    if isinstance(verdicts, _Verdict):
        payload = _build_item(verdicts, pr_number, commit_sha, repo, scan_ms)
    else:
        payload = [_build_item(v, pr_number, commit_sha, repo, scan_ms) for v in verdicts]

    headers = {"Authorization": f"Bearer {ingest_token}", "Content-Type": "application/json"}
    try:
        resp = httpx.post(ingest_url, json=payload, headers=headers, timeout=10.0)
        resp.raise_for_status()
        count = len(payload) if isinstance(payload, list) else 1
        logger.info(
            "Scan metadata sent to ingest (%d finding(s), HTTP %d)", count, resp.status_code
        )
    except Exception as exc:
        logger.warning("Failed to send to ingest endpoint (non-fatal): %s", exc)


def main() -> None:
    import time

    from .github.app_client import GitHubAppClient
    from .github.pr_comment import (
        COMMENT_MARKER,
        format_inline_comment,
        format_large_pr_summary,
        format_summary_comment,
    )
    from .llm.orchestrator import LLMOrchestrator
    from .llm.platform_keys import fetch_platform_keys, get_oidc_token
    from .llm.providers.github_models import GitHubModelsProvider
    from .llm.providers.groq import GroqProvider
    from .llm.providers.openrouter import OpenRouterProvider
    from .triage.budget import select_inline_findings
    from .triage.engine import TriageEngine
    from .triage.large_pr import detect_large_pr
    from .triage.verdicts import VerdictType

    CHUNKED_DIFF_THRESHOLD = 100  # lines

    # ── Config ────────────────────────────────────────────────────────────────
    app_id = _get_env("GITHUB_APP_ID")
    # Allow \\n-escaped newlines (common when storing PEM in env vars)
    private_key = _get_env("GITHUB_APP_PRIVATE_KEY").replace("\\n", "\n")
    try:
        installation_id = int(_get_env("INSTALLATION_ID"))
        pr_number = int(_get_env("PR_NUMBER"))
    except ValueError as e:
        logger.error("Invalid integer environment variable: %s", e)
        sys.exit(1)
    target_repo = _get_env("TARGET_REPO")  # "owner/name"
    commit_sha = _get_env("COMMIT_SHA")

    openrouter_keys = [
        k
        for k in [
            os.environ.get("OPENROUTER_API_KEY", ""),
            os.environ.get("OPENROUTER_API_KEY_2", ""),
            os.environ.get("OPENROUTER_API_KEY_3", ""),
        ]
        if k
    ]
    groq_keys = [
        k
        for k in [
            os.environ.get("GROQ_API_KEY", ""),
            os.environ.get("GROQ_API_KEY_2", ""),
            os.environ.get("GROQ_API_KEY_3", ""),
        ]
        if k
    ]
    ingest_url = os.environ.get("AEGISDIFF_INGEST_URL", "")
    ingest_token = os.environ.get("AEGISDIFF_INGEST_TOKEN", "")

    owner, repo_name = target_repo.split("/", 1)

    # ── Fetch diff via GitHub App ─────────────────────────────────────────────
    app_client = GitHubAppClient(app_id=app_id, private_key_pem=private_key)

    logger.info(
        "Fetching diff for %s#%d (installation %d)", target_repo, pr_number, installation_id
    )
    installation_token = app_client.get_installation_token(installation_id)
    raw_diff = app_client.get_pr_diff(
        installation_id, owner, repo_name, pr_number, token=installation_token
    )

    if not raw_diff.strip():
        logger.info("Empty diff — nothing to analyze")
        sys.exit(0)

    # ── Fetch full file content for changed files ─────────────────────────────
    # The GitHub App path has no checked-out repo, so the extractor can't read
    # files from disk. We fetch each changed file's content via the Contents API
    # and pass it as a cache so the extractor has full file context.
    #
    # Phase-1 classification gate: SKIP files (docs / generated / static /
    # minified) and DEPENDENCY_ONLY files (lockfiles) are NEVER analyzed by
    # the LLM, so eagerly fetching their contents is wasted GitHub API
    # traffic. We classify upfront on path metadata only (no diff content
    # required) and skip the prefetch for those buckets. The lazy
    # ``_fetch_file`` fallback below still covers any cross-file extractor
    # lookup that would normally be served from the cache.
    import re as _re

    from .triage.engine import TriageEngine as _TriageEngine
    from .triage.file_classifier import Decision, classify_files

    # Use the existing diff splitter so the path list matches what the
    # engine itself sees later — no risk of drift between the prefetch
    # path list and the analysis path list.
    _file_chunks = _TriageEngine._split_diff_by_file(raw_diff)
    changed_file_paths = [path for path, _diff in _file_chunks]
    if not changed_file_paths:
        # Defensive fallback for diff shapes the splitter doesn't recognise
        # (e.g. binary-only diffs). Keep the legacy regex behaviour so we
        # don't silently drop content for unusual diffs.
        changed_file_paths = _re.findall(r"^\+\+\+ b/(.+)$", raw_diff, _re.MULTILINE)

    _classifications = classify_files(changed_file_paths)
    _worth_fetching = {
        c.path for c in _classifications if c.decision in (Decision.ANALYZE, Decision.DEPRIORITIZE)
    }
    _skipped_prefetch = len(changed_file_paths) - len(_worth_fetching)
    if _skipped_prefetch > 0:
        logger.info(
            "Skipping content prefetch for %d non-analyzable file(s) "
            "(skip / dependency_only) — saves Contents API calls",
            _skipped_prefetch,
        )

    file_cache: dict = {}
    for fp in changed_file_paths:
        if fp not in _worth_fetching:
            logger.debug("Prefetch skipped (Phase-1 classifier): %s", fp)
            continue
        content = app_client.get_file_content(
            token=installation_token,
            owner=owner,
            repo=repo_name,
            path=fp,
            ref=commit_sha,
        )
        if content is not None:
            file_cache[fp] = content
            logger.info("Fetched full file context: %s (%d chars)", fp, len(content))
        else:
            logger.debug("Could not fetch content for %s — diff-only analysis", fp)

    # ── Build providers ───────────────────────────────────────────────────────
    # Cerebras excluded: GitHub Actions (Azure IPs) are blocked by Cerebras WAF.
    # Priority: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-27b:free
    providers = []
    n_or = len(openrouter_keys)
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key))
        logger.info("Provider: OpenRouter llama-3.3-70b:free (key %d/%d)", i, n_or)
    # Secondary model per key — less congested free-tier fallback
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key, model="google/gemma-3-27b-it:free"))
        logger.info("Provider: OpenRouter gemma-3-27b:free (key %d/%d)", i, n_or)

    # ── Groq — fast free-tier LLM, no training on requests ───────────────────
    for i, key in enumerate(groq_keys, start=1):
        providers.append(GroqProvider(key))
        logger.info("Provider: Groq llama-3.3-70b-versatile (key %d/%d)", i, len(groq_keys))

    # ── Platform keys via OIDC (Vercel → /api/llm-token) ─────────────────────
    # Appended AFTER direct secrets so operator keys always take priority.
    # This adds the platform OpenRouter + Groq pool as an extra buffer before
    # falling to GitHub Models — critical when all direct keys are 429'd.
    oidc = get_oidc_token()
    if oidc and ingest_url:
        logger.info("Appending platform keys as fallback providers via OIDC")
        platform = fetch_platform_keys(ingest_url, oidc)
        platform_openrouter = [k for k in platform.get("openrouter_keys", []) if k]
        n_por = len(platform_openrouter)
        for i, key in enumerate(platform_openrouter, start=1):
            providers.append(OpenRouterProvider(key))
            logger.info("Provider: OpenRouter llama-3.3-70b:free (platform %d/%d)", i, n_por)
        for i, key in enumerate(platform_openrouter, start=1):
            providers.append(OpenRouterProvider(key, model="google/gemma-3-27b-it:free"))
            logger.info("Provider: OpenRouter gemma-3-27b:free (platform %d/%d)", i, n_por)
        platform_groq = [k for k in platform.get("groq_keys", []) if k]
        n_pg = len(platform_groq)
        for i, key in enumerate(platform_groq, start=1):
            providers.append(GroqProvider(key))
            logger.info("Provider: Groq llama-3.3-70b-versatile (platform %d/%d)", i, n_pg)

    # ── GitHub Models — zero-config last-resort fallback ─────────────────────
    # GITHUB_APP_PRIVATE_KEY signs JWTs — but the Actions GITHUB_TOKEN also works
    # for GitHub Models API. No extra secret needed.
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if github_token:
        providers.append(GitHubModelsProvider(github_token))
        logger.info("Provider: GitHub Models Llama-3.3-70B (zero-config fallback)")

    if not providers:
        logger.error("No LLM keys configured. Set OPENROUTER_API_KEY in this repo's secrets.")
        sys.exit(1)

    orchestrator = LLMOrchestrator(providers, max_retries_per_provider=3)

    def _fetch_file(path: str) -> Optional[str]:
        """Fetch an imported file from GitHub for cross-file context resolution."""
        return app_client.get_file_content(
            token=installation_token,
            owner=owner,
            repo=repo_name,
            path=path,
            ref=commit_sha,
        )

    engine = TriageEngine(
        orchestrator,
        repo_root=Path("."),
        file_cache=file_cache,
        file_fetcher=_fetch_file,
    )

    # ── Analyze ───────────────────────────────────────────────────────────────
    t0 = time.monotonic()
    diff_lines = raw_diff.count("\n")
    added_lines = sum(
        1 for line in raw_diff.splitlines() if line.startswith("+") and not line.startswith("+++")
    )
    file_chunks = TriageEngine._split_diff_by_file(raw_diff)
    total_diff_bytes = len(raw_diff.encode("utf-8"))
    detection = detect_large_pr(
        changed_files=len(file_chunks),
        added_lines=added_lines,
        total_diff_bytes=total_diff_bytes,
    )

    large_pr_summary_block: Optional[str] = None
    large_pr_run = None

    if detection.is_large_pr:
        logger.info(
            "Large PR Risk Triage Mode — files=%d added=%d bytes=%d reasons=%s",
            len(file_chunks),
            added_lines,
            total_diff_bytes,
            detection.reasons,
        )
        large_pr_run = engine.analyze_diff_large_pr_mode(raw_diff, detection)
        all_verdicts = large_pr_run.verdicts
        verdict = TriageEngine.aggregate_verdicts(all_verdicts)
        logger.info(
            "Large PR Mode: %d/%d LLM call(s) used, exhausted=%s, primary=%s [%s]",
            large_pr_run.llm_calls_budget_used,
            large_pr_run.llm_calls_budget_total,
            large_pr_run.budget_exhausted,
            verdict.verdict.value,
            verdict.severity.value,
        )
    elif diff_lines > CHUNKED_DIFF_THRESHOLD:
        logger.info("Large diff (%d lines) — using chunked analysis", diff_lines)
        all_verdicts = engine.analyze_diff_chunked(raw_diff)
        verdict = TriageEngine.aggregate_verdicts(all_verdicts)
        logger.info(
            "Aggregated %d chunk(s) → primary: %s [%s]",
            len(all_verdicts),
            verdict.verdict.value,
            verdict.severity.value,
        )
    else:
        verdict = engine.analyze_diff(raw_diff)
        all_verdicts = [verdict]

    scan_ms = int((time.monotonic() - t0) * 1000)
    logger.info(
        "Verdict: %s (confidence=%.2f, provider=%s, ms=%d)",
        verdict.verdict.value,
        verdict.confidence,
        verdict.provider,
        scan_ms,
    )

    # ── Post inline review comments + top-level summary ───────────────────────
    sha_short = commit_sha[:7]

    # In Large PR Mode the inline-comment count is capped at
    # max_inline_comments and CRITICAL/HIGH findings are posted first;
    # select_inline_findings() is the single source of truth for both the
    # cap and the exact overflow count.
    if large_pr_run is not None:
        inline_candidates, inline_overflow = select_inline_findings(
            all_verdicts, detection.budgets.max_inline_comments
        )
    else:
        inline_candidates = [v for v in all_verdicts if v.line_number and v.file_path]
        inline_overflow = 0

    # ``inline_posted_count`` counts only the inline reviews GitHub
    # actually accepted (create_review() returns False on 422
    # line-not-in-diff, rate-limit, etc.). The Large PR summary reports
    # this number, not ``len(inline_candidates)``. ``inline_overflow``
    # stays based on eligibility-vs-cap, not posting success.
    any_inline_posted = False
    inline_posted_count = 0
    for v in inline_candidates:
        inline_body = format_inline_comment(v)
        posted = app_client.create_review(
            installation_id,
            owner,
            repo_name,
            pr_number,
            commit_sha,
            v.file_path,
            v.line_number,
            inline_body,
        )
        if posted:
            inline_posted_count += 1
            if v is verdict:
                any_inline_posted = True

    tp_count = len([v for v in all_verdicts if v.verdict == VerdictType.TRUE_POSITIVE])
    if large_pr_run is not None:
        large_pr_summary_block = format_large_pr_summary(
            large_pr_run.coverage,
            llm_calls_used=large_pr_run.llm_calls_budget_used,
            llm_calls_total=large_pr_run.llm_calls_budget_total,
            inline_findings_shown=inline_posted_count,
            inline_findings_overflow=inline_overflow,
            chunks_errored=large_pr_run.chunks_errored,
        )
    comment_body = format_summary_comment(
        verdict,
        pr_number=pr_number,
        sha=sha_short,
        inline_posted=any_inline_posted,
        total_findings=tp_count if tp_count > 1 else None,
        large_pr_summary=large_pr_summary_block,
    )
    app_client.upsert_pr_comment(
        installation_id, owner, repo_name, pr_number, comment_body, COMMENT_MARKER
    )
    logger.info("PR comment posted to %s#%d", target_repo, pr_number)

    # ── Commit status (enables "Require AegisDiff to pass" branch protection) ─
    from .entrypoint import _verdict_to_status

    status_state, status_desc = _verdict_to_status(verdict)
    app_client.post_commit_status(
        installation_id, owner, repo_name, commit_sha, status_state, status_desc
    )

    # ── GitHub Code Scanning (SARIF upload) ──────────────────────────────────
    # Upload findings so they appear in the Security tab. Non-fatal.
    # Requires the GitHub App to have the `security_events` permission.
    from .triage.sarif import build_sarif, encode_sarif

    sarif_doc = build_sarif(all_verdicts, target_repo, commit_sha)
    sarif_b64 = encode_sarif(sarif_doc)
    app_client.upload_sarif(
        installation_id,
        owner,
        repo_name,
        commit_sha,
        f"refs/pull/{pr_number}/head",
        sarif_b64,
    )

    # ── Send metadata to dashboard ────────────────────────────────────────────
    if ingest_url and ingest_token:
        ingest_payload = all_verdicts if len(all_verdicts) > 1 else verdict
        _send_to_ingest(
            ingest_url,
            ingest_token,
            ingest_payload,
            pr_number,
            commit_sha,
            target_repo,
            scan_ms,
        )

    # ── Exit code ─────────────────────────────────────────────────────────────
    if verdict.verdict == VerdictType.TRUE_POSITIVE and verdict.confidence >= 0.8:
        logger.warning(
            "HIGH-CONFIDENCE TRUE POSITIVE (confidence=%.2f) — exiting 1",
            verdict.confidence,
        )
        sys.exit(1)

    logger.info("Analysis complete — exit 0")


if __name__ == "__main__":
    main()
