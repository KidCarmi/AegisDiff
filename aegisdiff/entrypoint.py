"""
AegisDiff entry point — called by GitHub Actions.

Reads environment variables, orchestrates the scan, posts the result
as a PR comment, and optionally sends scan metadata to the dashboard
ingest endpoint (no code content, metadata only).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

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
    """
    Exchange an OIDC token for AegisDiff platform LLM keys.

    Returns a dict with 'cerebras_keys' and/or 'openrouter_keys' on success.
    Returns {} on rate-limit (429) or any error — caller falls back to exit.
    """
    base = ingest_url.rstrip("/").removesuffix("/api/ingest")
    try:
        resp = httpx.get(
            f"{base}/api/llm-token",
            headers={"Authorization": f"Bearer {oidc_token}"},
            timeout=10.0,
        )
        if resp.status_code == 429:
            data = resp.json()
            logger.error(
                "Platform key rate limit: %s (%d/%d scans today). "
                "Add OPENROUTER_API_KEY to your repo secrets for unlimited scans.",
                data.get("error", "limit reached"),
                data.get("scans_today", "?"),
                data.get("limit", 100),
            )
            return {}
        if resp.status_code == 503:
            logger.error(
                "AegisDiff platform keys not configured. "
                "Add OPENROUTER_API_KEY to your repo secrets."
            )
            return {}
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("Could not fetch platform keys (non-fatal): %s", e)
        return {}


def _get_oidc_token() -> str | None:
    """Fetch a GitHub Actions OIDC JWT for audience 'aegisdiff'."""
    import os

    token_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not token_url or not request_token:
        return None
    try:
        resp = httpx.get(
            f"{token_url}&audience=aegisdiff",
            headers={"Authorization": f"Bearer {request_token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json().get("value")
    except Exception as e:
        logger.debug("OIDC token request failed (will fall back to repo token): %s", e)
        return None


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
        format_summary_comment,
        format_verdict_comment,
    )
    from .llm.orchestrator import LLMOrchestrator
    from .llm.providers.github_models import GitHubModelsProvider
    from .llm.providers.openrouter import OpenRouterProvider
    from .triage.engine import TriageEngine
    from .triage.verdicts import VerdictType

    CHUNKED_DIFF_THRESHOLD = 100  # lines

    cfg = load_config()

    openrouter_keys = [
        k for k in [cfg.openrouter_api_key, cfg.openrouter_api_key_2, cfg.openrouter_api_key_3] if k
    ]

    # ── Build provider list ────────────────────────────────────────────────
    # Priority: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-9b:free
    # Cerebras is excluded: GitHub Actions (Azure IPs) are blocked by Cerebras WAF.
    # Platform keys via OIDC appended as fallback after user keys.
    providers = []
    n_or = len(openrouter_keys)
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key))
        logger.info("Provider: OpenRouter llama-3.3-70b:free (user key %d/%d)", i, n_or)
    # Secondary OpenRouter model per key — less congested free-tier fallback
    for i, key in enumerate(openrouter_keys, start=1):
        providers.append(OpenRouterProvider(key, model="google/gemma-3-9b-it:free"))
        logger.info("Provider: OpenRouter gemma-3-9b:free (user key %d/%d)", i, n_or)

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
            providers.append(OpenRouterProvider(key, model="google/gemma-3-9b-it:free"))
            logger.info("Provider: OpenRouter gemma-3-9b:free (platform %d/%d)", i, n_por)

    # ── GitHub Models — zero-config last-resort fallback ──────────────────
    # GITHUB_TOKEN is always injected into every Actions run — no extra secrets.
    if cfg.github_token:
        providers.append(GitHubModelsProvider(cfg.github_token))
        logger.info("Provider: GitHub Models Llama-3.3-70B (zero-config fallback)")

    if not providers:
        logger.error(
            "No LLM keys available. Either:\n"
            "  1. Add OPENROUTER_API_KEY to your repo secrets, or\n"
            "  2. Ensure AEGISDIFF_INGEST_URL is set (platform keys, 100 scans/day free)."
        )
        sys.exit(1)

    orchestrator = LLMOrchestrator(providers, max_retries_per_provider=3)

    # For the manual path the repo is checked out, so the extractor reads files
    # from disk. Pass a file_fetcher as fallback for any imported file that
    # isn't in the checkout (e.g. a path the diff parser resolved differently).
    _gh_client_for_fetch = (
        GitHubClient(cfg.github_token, cfg.repo) if cfg.github_token and cfg.repo else None
    )

    def _fetch_file(path: str):
        if _gh_client_for_fetch is None:
            return None
        return _gh_client_for_fetch.get_file_content(path, cfg.commit_sha)

    engine = TriageEngine(
        orchestrator,
        repo_root=Path("."),
        file_fetcher=_fetch_file,
    )

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

    t0 = time.monotonic()
    diff_lines = raw_diff.count("\n")

    if diff_lines > CHUNKED_DIFF_THRESHOLD:
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
        # In chunked mode this can produce multiple inline comments (one per
        # vulnerable file). In single-verdict mode at most one is posted.
        any_inline_posted = False
        for v in all_verdicts:
            if v.line_number and v.file_path:
                inline_body = format_inline_comment(v)
                posted = client.create_review(
                    cfg.pr_number,
                    cfg.commit_sha,
                    v.file_path,
                    v.line_number,
                    inline_body,
                )
                if posted and v is verdict:
                    any_inline_posted = True

        # ── Top-level summary comment ────────────────────────────────────
        # Always posted. Based on the primary (most severe) verdict.
        # When inline succeeded for the primary finding, omits evidence.
        extra_count = len([v for v in all_verdicts if v.verdict == VerdictType.TRUE_POSITIVE])
        comment_body = format_summary_comment(
            verdict,
            pr_number=cfg.pr_number,
            sha=sha_short,
            inline_posted=any_inline_posted,
            total_findings=extra_count if extra_count > 1 else None,
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
        auth_token = _get_oidc_token() or cfg.aegisdiff_repo_token
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

    # Print to GitHub Actions step summary
    try:
        step_summary = Path("/tmp/step_summary.md")
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
        step_summary.write_text("\n".join(summary_lines) + "\n")
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
