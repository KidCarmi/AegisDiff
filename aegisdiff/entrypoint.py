"""
AegisDiff entry point — called by GitHub Actions.

Reads environment variables, orchestrates the scan, posts the result
as a PR comment, and optionally sends scan metadata to the dashboard
ingest endpoint (no code content, metadata only).
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
logger = logging.getLogger("aegisdiff.entrypoint")

from .sentry import init_sentry  # noqa: E402

init_sentry(release="aegisdiff@entrypoint")


def _verdict_to_status(verdict) -> tuple[str, str]:
    """Map a Verdict to a GitHub commit status state + description."""
    from .triage.verdicts import VerdictType

    v = verdict.verdict
    conf = verdict.confidence
    if v == VerdictType.TRUE_POSITIVE:
        if conf >= 0.8:
            return "failure", f"Security issue detected: {verdict.title[:100]}"
        return "pending", f"Possible security issue (low confidence): {verdict.title[:80]}"
    if v == VerdictType.FALSE_POSITIVE:
        return "success", "No security issues detected"
    if v == VerdictType.NEEDS_REVIEW:
        return "pending", f"Needs manual security review: {verdict.title[:90]}"
    return "error", "Security analysis failed — check workflow logs"


def _fetch_platform_keys(ingest_url: str, oidc_token: str) -> dict:
    from .llm.platform_keys import fetch_platform_keys

    return fetch_platform_keys(ingest_url, oidc_token)


def build_manual_file_cache(
    raw_diff: str,
    repo_root: Path,
    github_client,
    commit_sha: str,
) -> dict:
    """Pre-populate a ``file_cache`` for the manual entrypoint's TriageEngine.

    Mirrors the gated prefetch added to the GitHub App path in F3, with
    one critical difference: the manual path runs in a checked-out repo,
    so disk reads remain the primary source of truth and Contents API
    fetches are made only for files that are *not* already on disk under
    ``repo_root``.

    Filtering rules:
      * SKIP files (docs / generated / static / minified) — never fetched.
      * DEPENDENCY_ONLY files (lockfiles) — never fetched.
      * ANALYZE / DEPRIORITIZE files already present on disk — never
        fetched (the extractor reads disk first; cache would never win).
      * ANALYZE / DEPRIORITIZE files NOT on disk — fetched once and
        cached so the extractor's primary-sink line resolution and
        surrounding-context windows have content to work with.

    Returns an empty dict when:
      * ``github_client`` is ``None`` (no token / repo configured).
      * ``raw_diff`` is empty or has no recognisable file paths.

    The caller passes the result as ``TriageEngine(..., file_cache=...)``.
    The lazy ``file_fetcher`` fallback for cross-file imports is
    unchanged and still wired through to the engine.
    """
    if github_client is None:
        return {}
    if not raw_diff or not raw_diff.strip():
        return {}

    import re as _re

    from .triage.engine import TriageEngine
    from .triage.file_classifier import Decision, classify_files

    # Use the existing splitter so the path list matches what the engine
    # itself sees later. Defensive fallback for binary-only or otherwise
    # unrecognised diff shapes.
    file_chunks = TriageEngine._split_diff_by_file(raw_diff)
    changed_file_paths = [path for path, _diff in file_chunks]
    if not changed_file_paths:
        changed_file_paths = _re.findall(r"^\+\+\+ b/(.+)$", raw_diff, _re.MULTILINE)
    if not changed_file_paths:
        return {}

    classifications = classify_files(changed_file_paths)
    worth_fetching = {
        c.path for c in classifications if c.decision in (Decision.ANALYZE, Decision.DEPRIORITIZE)
    }

    file_cache: dict = {}
    skipped_disk = 0
    fetched = 0
    for fp in changed_file_paths:
        if fp not in worth_fetching:
            continue
        # Disk-first: if the workflow checked out the file we already
        # have it. Don't burn a Contents API call on a file the
        # extractor will read from disk anyway.
        if (repo_root / fp).exists():
            skipped_disk += 1
            continue
        content = github_client.get_file_content(fp, commit_sha)
        if content is not None:
            file_cache[fp] = content
            fetched += 1

    if fetched or skipped_disk:
        logger.info(
            "Manual prefetch gate: fetched=%d, on-disk=%d, non-analyzable=%d, total=%d",
            fetched,
            skipped_disk,
            len(changed_file_paths) - len(worth_fetching),
            len(changed_file_paths),
        )
    return file_cache


def _get_oidc_token() -> str | None:
    from .llm.platform_keys import get_oidc_token

    return get_oidc_token()


def _build_ingest_item(verdict, pr_number, commit_sha, repo, scan_ms: int) -> dict:
    """Build a single ingest metadata dict for one Verdict."""
    item: dict = {
        "verdict": verdict.verdict.value,
        "severity": verdict.severity.value,
        "cwe_id": verdict.cwe_id,
        "confidence": verdict.confidence,
        "title": verdict.title,
        "provider": verdict.provider,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "pr_url": f"https://github.com/{repo}/pull/{pr_number}" if pr_number else None,
        "scan_ms": scan_ms,
    }
    # Include suppression metadata so the dashboard can persist ignore_rules
    if verdict.false_positive_reason and "aegisdiff-ignore" in verdict.title.lower():
        item["suppressed"] = True
        item["ignore_reason"] = verdict.false_positive_reason
    return item


def _send_to_ingest(
    ingest_url: str,
    auth_token: str,
    verdicts,
    pr_number,
    commit_sha,
    repo,
    scan_ms: int,
) -> None:
    """
    POST scan metadata (no code) to the AegisDiff dashboard ingest endpoint.

    Accepts either a single Verdict or a list. When a list is supplied, sends
    an array payload so the dashboard can store one row per finding per PR.
    """
    from .triage.verdicts import Verdict as _Verdict

    if isinstance(verdicts, _Verdict):
        payload = _build_ingest_item(verdicts, pr_number, commit_sha, repo, scan_ms)
    else:
        payload = [_build_ingest_item(v, pr_number, commit_sha, repo, scan_ms) for v in verdicts]

    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
    try:
        resp = httpx.post(ingest_url, json=payload, headers=headers, timeout=10.0)
        resp.raise_for_status()
        count = len(payload) if isinstance(payload, list) else 1
        logger.info(
            "Scan metadata sent to ingest endpoint (%d finding(s), HTTP %d)",
            count,
            resp.status_code,
        )
    except Exception as e:
        logger.warning("Failed to send to ingest endpoint (non-fatal): %s", e)


def main() -> None:
    import time

    from .config import load_config
    from .github.client import GitHubClient
    from .github.pr_comment import (
        COMMENT_MARKER,
        format_inline_comment,
        format_large_pr_summary,
        format_summary_comment,
        format_verdict_comment,
    )
    from .llm.orchestrator import LLMOrchestrator
    from .llm.providers.github_models import GitHubModelsProvider
    from .llm.providers.groq import GroqProvider
    from .llm.providers.openrouter import OpenRouterProvider
    from .triage.budget import select_inline_findings
    from .triage.engine import TriageEngine
    from .triage.large_pr import detect_large_pr
    from .triage.verdicts import VerdictType

    CHUNKED_DIFF_THRESHOLD = 100  # lines

    cfg = load_config()

    openrouter_keys = [
        k for k in [cfg.openrouter_api_key, cfg.openrouter_api_key_2, cfg.openrouter_api_key_3] if k
    ]
    groq_keys = [k for k in [cfg.groq_api_key, cfg.groq_api_key_2, cfg.groq_api_key_3] if k]

    # ── Build provider list ────────────────────────────────────────────────
    # Priority: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-27b:free
    # Cerebras is excluded: GitHub Actions (Azure IPs) are blocked by Cerebras WAF.
    # Platform keys via OIDC appended as fallback after user keys.
    providers = []
    n_or = len(openrouter_keys)
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key))
        logger.info("Provider: OpenRouter llama-3.3-70b:free (user key %d/%d)", i, n_or)
    # Secondary OpenRouter model per key — less congested free-tier fallback
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key, model="google/gemma-3-27b-it:free"))
        logger.info("Provider: OpenRouter gemma-3-27b:free (user key %d/%d)", i, n_or)

    oidc = _get_oidc_token()
    if oidc and cfg.aegisdiff_ingest_url:
        if not providers:
            logger.info("No user LLM keys — fetching platform keys via OIDC")
        else:
            logger.info("Appending platform keys as fallback providers via OIDC")
        platform = _fetch_platform_keys(cfg.aegisdiff_ingest_url, oidc)
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

    # ── Groq — fast free-tier LLM, no training on requests ───────────────
    for i, key in enumerate(groq_keys, start=1):
        providers.append(GroqProvider(key))
        logger.info("Provider: Groq llama-3.3-70b-versatile (key %d/%d)", i, len(groq_keys))

    # ── GitHub Models — zero-config last-resort fallback ──────────────────
    # GITHUB_TOKEN is always injected into every Actions run — no extra secrets.
    if cfg.github_token:
        providers.append(GitHubModelsProvider(cfg.github_token))
        logger.info("Provider: GitHub Models Llama-3.3-70B (zero-config fallback)")

    if not providers:
        logger.error(
            "No LLM keys available. Either:\n"
            "  1. Add OPENROUTER_API_KEY or GROQ_API_KEY to your repo secrets, or\n"
            "  2. Ensure AEGISDIFF_INGEST_URL is set (platform keys, 100 scans/day free)."
        )
        sys.exit(1)

    orchestrator = LLMOrchestrator(providers, max_retries_per_provider=3)

    # For the manual path the repo is checked out, so the extractor reads files
    # from disk first. Pass a file_fetcher as a lazy fallback for any imported
    # file that isn't in the checkout (e.g. a path the diff parser resolved
    # differently or a cross-file import outside a sparse checkout).
    _gh_client_for_fetch = (
        GitHubClient(cfg.github_token, cfg.repo) if cfg.github_token and cfg.repo else None
    )

    def _fetch_file(path: str):
        if _gh_client_for_fetch is None:
            return None
        return _gh_client_for_fetch.get_file_content(path, cfg.commit_sha)

    # Read diff
    diff_path = Path(cfg.diff_path)
    if not diff_path.exists():
        logger.error("Diff file not found: %s", diff_path)
        sys.exit(1)
    raw_diff = diff_path.read_text(errors="replace")

    if not raw_diff.strip():
        logger.info("Empty diff — nothing to analyze")
        print("## AegisDiff\n\nNo security-relevant code changes detected.")
        sys.exit(0)

    # ── F7: Phase-1 gated prefetch ────────────────────────────────────────
    # Pre-populate ``file_cache`` for ANALYZE / DEPRIORITIZE files that are
    # *not* already on disk under the checked-out repo. Closes the manual-
    # vs-App divergence where sparse-checkout / fetch-only setups silently
    # lost primary-sink line resolution because the extractor saw only the
    # diff text. Disk-first stays the source of truth — files in the
    # checkout aren't fetched again.
    _file_cache = build_manual_file_cache(
        raw_diff,
        repo_root=Path("."),
        github_client=_gh_client_for_fetch,
        commit_sha=cfg.commit_sha,
    )

    engine = TriageEngine(
        orchestrator,
        repo_root=Path("."),
        file_cache=_file_cache,
        file_fetcher=_fetch_file,
    )

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
        logger.info("Large diff (%d lines) — using per-file chunked analysis", diff_lines)
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
    sha_short = cfg.commit_sha[:7]

    # Post to PR + commit status (if we have the needed context)
    if cfg.pr_number and cfg.github_token and cfg.repo:
        client = GitHubClient(cfg.github_token, cfg.repo)

        # ── Inline review comments ───────────────────────────────────────
        # Post an inline comment for every finding with a known sink line.
        # In Large PR Mode the count is capped at max_inline_comments and
        # CRITICAL/HIGH findings are posted first; the rest are reported in
        # the top-level summary's coverage block. select_inline_findings()
        # is the single source of truth for both the cap and the exact
        # overflow count, so the two can never disagree.
        if large_pr_run is not None:
            inline_candidates, inline_overflow = select_inline_findings(
                all_verdicts, detection.budgets.max_inline_comments
            )
        else:
            inline_candidates = [v for v in all_verdicts if v.line_number and v.file_path]
            inline_overflow = 0

        # ``inline_posted_count`` only counts inline reviews GitHub actually
        # accepted (create_review() returns False on 422 line-not-in-diff,
        # rate-limit, etc.). The Large PR summary reports this number, not
        # ``len(inline_candidates)``, so the coverage block reflects what
        # was truly surfaced inline. ``inline_overflow`` is intentionally
        # *not* derived from this counter — overflow is about eligibility-
        # vs-cap, not posting success.
        any_inline_posted = False
        inline_posted_count = 0
        for v in inline_candidates:
            inline_body = format_inline_comment(v)
            posted = client.create_review(
                cfg.pr_number,
                cfg.commit_sha,
                v.file_path,
                v.line_number,
                inline_body,
            )
            if posted:
                inline_posted_count += 1
                if v is verdict:
                    any_inline_posted = True

        # ── Top-level summary comment ────────────────────────────────────
        # Always posted. Based on the primary (most severe) verdict.
        # When inline succeeded for the primary finding, omits evidence.
        extra_count = len([v for v in all_verdicts if v.verdict == VerdictType.TRUE_POSITIVE])
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
            pr_number=cfg.pr_number,
            sha=sha_short,
            inline_posted=any_inline_posted,
            total_findings=extra_count if extra_count > 1 else None,
            large_pr_summary=large_pr_summary_block,
        )
        client.upsert_pr_comment(cfg.pr_number, comment_body, COMMENT_MARKER)

        # Post commit status so result appears in the PR merge checklist
        status_state, status_desc = _verdict_to_status(verdict)
        client.post_commit_status(cfg.commit_sha, status_state, status_desc)

        # ── GitHub Code Scanning (SARIF upload) ──────────────────────────
        # Upload findings so they appear in the repo's Security tab.
        # Non-fatal — skipped silently if token lacks security-events:write.
        from .triage.sarif import build_sarif, encode_sarif

        sarif_doc = build_sarif(all_verdicts, cfg.repo, cfg.commit_sha)
        sarif_b64 = encode_sarif(sarif_doc)
        ref = f"refs/pull/{cfg.pr_number}/head"
        client.upload_sarif(cfg.commit_sha, ref, sarif_b64)
    else:
        # No PR context — print full comment to stdout (local / workflow_dispatch)
        comment_body = format_verdict_comment(
            verdict,
            pr_number=cfg.pr_number or 0,
            sha=sha_short,
        )
        print(comment_body)

    # Send metadata to dashboard (no code content)
    # Auth: try OIDC first (zero-config), fall back to legacy repo token
    if not cfg.aegisdiff_ingest_url:
        logger.warning(
            "Dashboard ingest skipped — AEGISDIFF_INGEST_URL not set. "
            "Scan results will NOT appear in the dashboard."
        )
    else:
        auth_token = oidc or cfg.aegisdiff_repo_token
        if auth_token:
            # Send all findings as an array (one DB row per finding per PR)
            ingest_payload = all_verdicts if len(all_verdicts) > 1 else verdict
            _send_to_ingest(
                cfg.aegisdiff_ingest_url,
                auth_token,
                ingest_payload,
                cfg.pr_number,
                cfg.commit_sha,
                cfg.repo,
                scan_ms,
            )
        else:
            logger.warning(
                "Dashboard ingest skipped — no auth token available. "
                "Set AEGISDIFF_INGEST_URL and ensure id-token: write permission "
                "or set AEGISDIFF_REPO_TOKEN in GitHub Secrets."
            )

    # Print to GitHub Actions step summary (write directly to $GITHUB_STEP_SUMMARY)
    try:
        step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
        if not step_summary_path:
            return
        step_summary = Path(step_summary_path)
        tp_count = sum(1 for v in all_verdicts if v.verdict == VerdictType.TRUE_POSITIVE)
        summary_lines = [
            f"## AegisDiff — {verdict.verdict.value}",
            "",
            f"**{verdict.title}** (confidence: {verdict.confidence:.0%}, "
            f"provider: {verdict.provider})",
        ]
        if len(all_verdicts) > 1:
            summary_lines.append(
                f"\n_{len(all_verdicts)} file(s) analyzed, {tp_count} true positive(s)_"
            )
        with step_summary.open("a") as f:
            f.write("\n".join(summary_lines) + "\n")
        logger.info("Step summary written")
    except OSError:
        pass

    # Exit non-zero on high-confidence true positives to optionally block merges
    if verdict.verdict == VerdictType.TRUE_POSITIVE and verdict.confidence >= 0.8:
        logger.warning(
            "HIGH-CONFIDENCE TRUE POSITIVE detected (confidence=%.2f) — exiting 1",
            verdict.confidence,
        )
        sys.exit(1)

    logger.info("Analysis complete — exit 0")


if __name__ == "__main__":
    main()
