"""Shared helpers for OIDC-authenticated platform LLM key distribution."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


def get_oidc_token() -> str | None:
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
    except Exception:
        logger.debug("OIDC token request failed — will skip platform keys")
        return None


def fetch_platform_keys(ingest_url: str, oidc_token: str) -> dict:
    """
    Exchange an OIDC token for AegisDiff platform LLM keys.

    Returns a dict with 'openrouter_keys' and/or 'groq_keys' on success.
    Returns {} on rate-limit (429) or any error — caller falls back gracefully.
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
                "Add OPENROUTER_API_KEY or GROQ_API_KEY to your repo secrets "
                "for unlimited scans.",
                data.get("error", "limit reached"),
                data.get("scans_today", "?"),
                data.get("limit", 100),
            )
            return {}
        if resp.status_code == 503:
            logger.error(
                "AegisDiff platform keys not configured. "
                "Add OPENROUTER_API_KEY or GROQ_API_KEY to your repo secrets."
            )
            return {}
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("Could not fetch platform keys (non-fatal): %s", e)
        return {}
