"""
GitHub Gist as a zero-cost ephemeral key-value cache.

Key: sha256(file_path + diff_content)[:16]
Value: serialized Verdict JSON (metadata only — no code)
TTL: configurable, default 7 days

This is an optional optimization that prevents redundant LLM calls
when the same file/diff combination is re-analyzed (e.g., force-push
with identical content).  If the Gist ID is not configured, all
cache operations are silently no-ops.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from ..triage.verdicts import Verdict, parse_verdict

logger = logging.getLogger(__name__)
CACHE_TTL_DAYS = 7
GITHUB_API_BASE = "https://api.github.com"


class GistCache:
    """
    Args:
        token: GitHub token with gist write scope.
        gist_id: ID of a pre-created secret Gist used as the cache store.
                 If None, all operations are no-ops.
    """

    def __init__(self, token: str, gist_id: Optional[str] = None) -> None:
        self._gist_id = gist_id
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }

    def make_key(self, file_path: str, diff_content: str) -> str:
        raw = f"{file_path}:{diff_content}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, cache_key: str) -> Optional[Verdict]:
        if not self._gist_id:
            return None
        try:
            url = f"{GITHUB_API_BASE}/gists/{self._gist_id}"
            resp = httpx.get(url, headers=self._headers, timeout=10.0)
            resp.raise_for_status()
            gist = resp.json()
            filename = f"cache_{cache_key}.json"
            if filename not in gist.get("files", {}):
                return None
            payload = json.loads(gist["files"][filename]["content"])
            cached_at = datetime.fromisoformat(payload["cached_at"])
            if datetime.now(timezone.utc) - cached_at > timedelta(days=CACHE_TTL_DAYS):
                logger.info("Cache entry %s expired", cache_key)
                return None
            return parse_verdict(json.dumps(payload["verdict"]))
        except Exception as e:
            logger.warning("Cache GET failed (non-fatal): %s", e)
            return None

    def set(self, cache_key: str, verdict: Verdict) -> None:
        if not self._gist_id:
            return
        try:
            filename = f"cache_{cache_key}.json"
            payload = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "verdict": {
                    "verdict": verdict.verdict.value,
                    "severity": verdict.severity.value,
                    "cwe_id": verdict.cwe_id,
                    "confidence": verdict.confidence,
                    "title": verdict.title,
                    "summary": verdict.summary,
                    "evidence": "",  # Never cache code content
                    "sanitizer_found": verdict.sanitizer_found,
                    "sanitizer_description": verdict.sanitizer_description,
                    "attack_vector": None,  # Never cache code-referencing fields
                    "remediation": verdict.remediation,
                    "false_positive_reason": verdict.false_positive_reason,
                },
            }
            url = f"{GITHUB_API_BASE}/gists/{self._gist_id}"
            resp = httpx.patch(
                url,
                headers=self._headers,
                json={"files": {filename: {"content": json.dumps(payload, indent=2)}}},
                timeout=10.0,
            )
            resp.raise_for_status()
            logger.debug("Cached verdict for key %s", cache_key)
        except Exception as e:
            logger.warning("Cache SET failed (non-fatal): %s", e)
