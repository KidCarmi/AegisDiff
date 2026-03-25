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

    Returns a dict with 'gemini_key' and/or 'groq_key' on success.
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
                "Add GEMINI_API_KEY or GROQ_API_KEY to your repo secrets for unlimited scans.",
                data.get("error", "limit reached"),
                data.get("scans_today", "?"),
                data.get("limit", 50),
            )
            return {}
        if resp.status_code == 503:
            logger.error(
                "AegisDiff platform keys not configured. "
                "Add GEMINI_API_KEY or GROQ_API_KEY to your repo secrets."
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


def _send_to_ingest(
    ingest_url: str, auth_token: str, verdict, pr_number, commit_sha, repo, scan_ms: int
) -> None:
    """POST scan metadata (no code) to the AegisDiff dashboard ingest endpoint."""
    payload = {
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
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
    try:
        resp = httpx.post(ingest_url, json=payload, headers=headers, timeout=10.0)
        resp.raise_for_status()
        logger.info("Scan metadata sent to ingest endpoint (HTTP %d)", resp.status_code)
    except Exception as e:
        logger.warning("Failed to send to ingest endpoint (non-fatal): %s", e)


def main() -> None:
    import time

    from .config import load_config
    from .github.client import GitHubClient
    from .github.pr_comment import COMMENT_MARKER, format_verdict_comment
    from .llm.orchestrator import LLMOrchestrator
    from .llm.providers.gemini import GeminiProvider
    from .llm.providers.groq import GroqProvider
    from .triage.engine import TriageEngine
    from .triage.verdicts import VerdictType

    cfg = load_config()

    groq_keys = [k for k in [cfg.groq_api_key, cfg.groq_api_key_2, cfg.groq_api_key_3] if k]
    gemini_key = cfg.gemini_api_key

    # ── Platform key fallback — fetch if user hasn't provided their own ───
    if not gemini_key and not groq_keys:
        oidc = _get_oidc_token()
        if oidc and cfg.aegisdiff_ingest_url:
            logger.info("No user LLM keys found — fetching platform keys via OIDC")
            platform = _fetch_platform_keys(cfg.aegisdiff_ingest_url, oidc)
            gemini_key = platform.get("gemini_key", "") or ""
            groq_key = platform.get("groq_key", "") or ""
            if groq_key:
                groq_keys = [groq_key]
        if not gemini_key and not groq_keys:
            logger.error(
                "No LLM keys available. Either:\n"
                "  1. Add GEMINI_API_KEY or GROQ_API_KEY to your repo secrets (unlimited), or\n"
                "  2. Ensure AEGISDIFF_INGEST_URL is set (platform keys, 50 scans/day free)."
            )
            sys.exit(1)
    else:
        logger.info("Using user-provided LLM keys (unlimited scans)")

    # Build provider list — only include providers with keys configured.
    # Multiple Groq keys rotate automatically on rate-limit (429).
    providers = []
    if gemini_key:
        providers.append(GeminiProvider(gemini_key))
        logger.info("Provider: Gemini 1.5 Pro")
    for i, key in enumerate(groq_keys, start=1):
        providers.append(GroqProvider(key))
        logger.info("Provider: Groq Llama-3-70b (key %d/%d)", i, len(groq_keys))

    orchestrator = LLMOrchestrator(providers, max_retries_per_provider=3)
    engine = TriageEngine(orchestrator, repo_root=Path("."))

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
    verdict = engine.analyze_diff(raw_diff)
    scan_ms = int((time.monotonic() - t0) * 1000)

    # Format comment
    sha_short = cfg.commit_sha[:7]
    comment_body = format_verdict_comment(
        verdict,
        pr_number=cfg.pr_number or 0,
        sha=sha_short,
    )

    # Post to PR + commit status (if we have the needed context)
    if cfg.pr_number and cfg.github_token and cfg.repo:
        client = GitHubClient(cfg.github_token, cfg.repo)
        client.upsert_pr_comment(cfg.pr_number, comment_body, COMMENT_MARKER)
        # Post commit status so result appears in the PR merge checklist
        status_state, status_desc = _verdict_to_status(verdict)
        client.post_commit_status(cfg.commit_sha, status_state, status_desc)
    else:
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
            _send_to_ingest(
                cfg.aegisdiff_ingest_url,
                auth_token,
                verdict,
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
        step_summary.write_text(
            f"## AegisDiff — {verdict.verdict.value}\n\n"
            f"**{verdict.title}** (confidence: {verdict.confidence:.0%}, "
            f"provider: {verdict.provider})\n"
        )
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
