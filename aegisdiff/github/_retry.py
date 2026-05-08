"""HTTP retry helper for transient GitHub API failures.

Retries on 500 / 502 / 503 / 504, ``httpx`` timeouts, and network
errors. Never retries on 401 / 403 / 404 / 422 / 429 — those have
specific business semantics in callers (auth, permission, validation,
or a rate-limit cooldown story that lives elsewhere).

Used only at *idempotent / replace-like* call sites:

  * GET requests (list comments, get file content, get PR diff).
  * ``POST /app/installations/{id}/access_tokens`` — token mint.
  * ``POST /code-scanning/sarifs`` — GitHub treats repeated uploads
    for the same tool / ref / sha as replace-style.

Non-idempotent POST/PATCH operations (``create_review``, create / update
PR comments, ``post_commit_status``) are intentionally NOT routed
through this helper. A duplicate visible side-effect on a 5xx-after-
server-success would be worse for reviewers than a missing comment.

Module-level ``_sleep`` is a test seam — production code uses
``time.sleep`` as expected; the test suite monkeypatches it to a no-op
recorder so the suite stays sub-second.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# HTTP status codes that warrant a retry. 429 is intentionally excluded:
# rate-limit handling needs Retry-After parsing and is out of scope for
# this PR.
_RETRY_STATUSES = frozenset({500, 502, 503, 504})

_DEFAULT_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 0.5  # seconds for attempt 1
_BACKOFF_CAP = 8.0
_BACKOFF_JITTER = 0.2  # ±20%

# Test seam — replace at module level to silence sleeps.
_sleep = time.sleep


def _backoff_seconds(attempt: int) -> float:
    """Backoff schedule for a 1-based attempt index.

    attempt 1 → ~0.5s, attempt 2 → ~2.0s, attempt 3 → ~8.0s (capped).
    Jitter adds ±20% so concurrent clients don't synchronise retries.
    """
    base = min(_BACKOFF_BASE * (4 ** (attempt - 1)), _BACKOFF_CAP)
    jitter = base * random.uniform(-_BACKOFF_JITTER, _BACKOFF_JITTER)
    return max(0.0, base + jitter)


def request_with_retry(
    method: str,
    url: str,
    *,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    **httpx_kwargs,
) -> httpx.Response:
    """Make an ``httpx`` request with retry on transient 5xx / network
    failures.

    Returns the final ``httpx.Response`` — which *may* carry a 5xx after
    retries are exhausted, so the caller's existing
    ``raise_for_status()`` / ``status_code`` classification logic runs
    unchanged. Re-raises the final timeout / network exception when no
    response is ever received, so existing ``except httpx.HTTPError``
    blocks catch it as today.

    Non-retryable status codes (any 4xx including 401 / 403 / 404 / 422
    / 429) are returned to the caller after the first response.
    """
    last_exc: Optional[BaseException] = None

    for attempt in range(1, max_attempts + 1):
        try:
            resp = httpx.request(method, url, **httpx_kwargs)
        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RemoteProtocolError,
        ) as exc:
            last_exc = exc
            if attempt >= max_attempts:
                raise
            wait = _backoff_seconds(attempt)
            logger.warning(
                "GitHub API %s %s: %s — retry %d/%d in %.1fs",
                method,
                url,
                exc,
                attempt,
                max_attempts,
                wait,
            )
            _sleep(wait)
            continue

        if resp.status_code in _RETRY_STATUSES and attempt < max_attempts:
            wait = _backoff_seconds(attempt)
            logger.warning(
                "GitHub API %s %s returned %d — retry %d/%d in %.1fs",
                method,
                url,
                resp.status_code,
                attempt,
                max_attempts,
                wait,
            )
            _sleep(wait)
            continue

        return resp

    # Defensive: the loop above always returns or raises. This branch is
    # only reachable if max_attempts < 1, which we treat as a programmer
    # error rather than a runtime failure mode.
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("request_with_retry: exhausted attempts without response")
