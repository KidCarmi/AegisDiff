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


def _send_to_ingest(
    ingest_url: str, repo_token: str, verdict, pr_number, commit_sha, repo, scan_ms: int
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
    headers = {"Authorization": f"Bearer {repo_token}", "Content-Type": "application/json"}
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

    if not cfg.gemini_api_key and not groq_keys:
        logger.error(
            "No LLM API keys configured. "
            "Set GEMINI_API_KEY and/or GROQ_API_KEY / GROQ_API_KEY_2 / GROQ_API_KEY_3 "
            "in GitHub Secrets."
        )
        sys.exit(1)

    # Build provider list — only include providers with keys configured.
    # Multiple Groq keys rotate automatically on rate-limit (429).
    providers = []
    if cfg.gemini_api_key:
        providers.append(GeminiProvider(cfg.gemini_api_key))
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
    if not cfg.aegisdiff_ingest_url:
        logger.warning(
            "Dashboard ingest skipped — AEGISDIFF_INGEST_URL not set. "
            "Scan results will NOT appear in the dashboard."
        )
    if cfg.aegisdiff_ingest_url and cfg.aegisdiff_repo_token:
        _send_to_ingest(
            cfg.aegisdiff_ingest_url,
            cfg.aegisdiff_repo_token,
            verdict,
            cfg.pr_number,
            cfg.commit_sha,
            cfg.repo,
            scan_ms,
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
