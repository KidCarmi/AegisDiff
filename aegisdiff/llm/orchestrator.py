"""
LLM Orchestrator — provider failover with rate-limit-aware pacing and backoff.

Priority order: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-27b-it:free
               → Groq llama-3.3-70b-versatile → GitHub Models (GITHUB_TOKEN fallback).
- Consecutive requests to the same provider are paced (min_request_interval)
  so chunked scans don't trip per-minute free-tier limits in the first place.
- On 429: cooldown honors the Retry-After header when present; a 429 caused by
  daily quota exhaustion benches the key for the rest of the run.
- On other retryable errors (timeout, 5xx): exponential backoff + jitter.
- When every provider is cooling down: waits for the soonest recovery within a
  bounded budget (instead of giving up after a single fixed sleep).
If all providers are exhausted: raises RuntimeError.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import replace
from typing import List, Optional

import httpx

from .providers.base import LLMProvider, LLMRequest, LLMResponse

logger = logging.getLogger(__name__)

BACKOFF_BASE = 2.0
BACKOFF_MAX = 60.0
BACKOFF_JITTER = 0.3


_RATE_LIMIT_COOLDOWN = 65.0  # default 429 cooldown when no Retry-After header
_RATE_LIMIT_COOLDOWN_MAX = 900.0  # cap on honored Retry-After values
_DAILY_QUOTA_COOLDOWN = 6 * 3600.0  # bench a key whose daily quota is exhausted
_TIMEOUT_COOLDOWN = 30.0  # seconds to skip a provider after a read timeout

# When every provider is cooling down, wait for the soonest recovery — bounded
# by both a wall-clock budget and a cycle count per complete() call.
_EXHAUSTED_WAIT_BUDGET = 300.0
_MAX_WAIT_CYCLES = 5

# Substrings identifying a 429 caused by a *daily* quota rather than a
# per-minute one. Groq: "... on requests per day (RPD): Limit ...".
# OpenRouter: "Rate limit exceeded: free-models-per-day".
_DAILY_QUOTA_PHRASES = ("per day", "(rpd)", "(tpd)", "daily", "free-models-per-day")


def _cooldown_from_429(exc: httpx.HTTPStatusError) -> float:
    """
    Pick a cooldown for a 429 response.

    Daily-quota exhaustion benches the key for the rest of the run — retrying
    it every minute can never succeed. Otherwise honor Retry-After (capped),
    falling back to the default cooldown.
    """
    try:
        body = exc.response.text[:1000].lower()
        if any(phrase in body for phrase in _DAILY_QUOTA_PHRASES):
            return _DAILY_QUOTA_COOLDOWN
    except Exception:  # noqa: BLE001 — malformed body must never mask the 429
        pass

    try:
        retry_after = exc.response.headers.get("retry-after")
        if retry_after is not None:
            return max(min(float(retry_after) + 1.0, _RATE_LIMIT_COOLDOWN_MAX), 1.0)
    except (TypeError, ValueError, AttributeError):
        pass

    return _RATE_LIMIT_COOLDOWN


class LLMOrchestrator:
    """
    Manages a priority-ordered list of LLM providers with automatic failover.

    Usage::

        orchestrator = LLMOrchestrator([OpenRouterProvider(key), GroqProvider(key)])
        response = orchestrator.complete(request)

    Cooldown and pacing state is persistent across complete() calls so that a
    provider which 429'd on chunk N is skipped on chunk N+1 without re-probing,
    and chunk N+1 doesn't burst-fire into a per-minute rate limit.
    """

    def __init__(
        self,
        providers: List[LLMProvider],
        max_retries_per_provider: int = 3,
    ) -> None:
        if not providers:
            raise ValueError("At least one LLM provider must be supplied.")
        self._providers = providers
        self._max_retries = max_retries_per_provider
        # Maps provider id() → monotonic timestamp when cooldown expires.
        # Survives across complete() calls (chunked analysis).
        self._cooldown_until: dict[int, float] = {}
        # Maps provider id() → monotonic timestamp of the last request sent.
        self._last_request_at: dict[int, float] = {}

    def _in_cooldown(self, provider: LLMProvider) -> bool:
        return time.monotonic() < self._cooldown_until.get(id(provider), 0.0)

    def _set_cooldown(self, provider: LLMProvider, seconds: float) -> None:
        self._cooldown_until[id(provider)] = time.monotonic() + seconds
        logger.debug("Provider %s cooling down for %.0fs", provider.name, seconds)

    def _pace(self, provider: LLMProvider) -> None:
        """Sleep so consecutive requests to one provider respect its rate limit."""
        interval = getattr(provider, "min_request_interval", 0.0)
        if not isinstance(interval, (int, float)) or interval <= 0:
            return
        last = self._last_request_at.get(id(provider))
        if last is None:
            return
        wait = interval - (time.monotonic() - last)
        if wait > 0:
            logger.debug("Pacing %s — sleeping %.1fs between requests", provider.name, wait)
            time.sleep(wait)

    def complete(self, request: LLMRequest) -> LLMResponse:
        last_exc: Optional[Exception] = None
        deadline = time.monotonic() + _EXHAUSTED_WAIT_BUDGET

        for wait_cycle in range(_MAX_WAIT_CYCLES + 1):
            if wait_cycle > 0:
                # Every provider failed or is cooling down. Wait for the
                # soonest cooldown that expires within the remaining budget;
                # if nothing will recover in time (e.g. all keys benched on
                # daily quota), give up now instead of sleeping pointlessly.
                now = time.monotonic()
                upcoming = [exp for exp in self._cooldown_until.values() if now < exp <= deadline]
                if not upcoming:
                    break
                wait = min(upcoming) - now + 0.5
                logger.warning(
                    "All providers cooling down — sleeping %.0fs before retrying",
                    wait,
                )
                time.sleep(wait)

            for provider in self._providers:
                if self._in_cooldown(provider):
                    remaining = self._cooldown_until[id(provider)] - time.monotonic()
                    logger.debug(
                        "Skipping %s — cooling down for %.0fs more",
                        provider.name,
                        remaining,
                    )
                    continue

                # context_scale tracks adaptive trimming: halved on every 413 response
                context_scale = 1.0

                for attempt in range(1, self._max_retries + 1):
                    adapted = self._adapt_request(request, provider, context_scale)
                    self._pace(provider)
                    self._last_request_at[id(provider)] = time.monotonic()
                    try:
                        logger.info(
                            "LLM attempt %d/%d via %s (context scale %.0f%%)",
                            attempt,
                            self._max_retries,
                            provider.name,
                            context_scale * 100,
                        )
                        response = provider.complete(adapted)
                        logger.info(
                            "LLM success via %s in %.0fms (%d in / %d out tokens)",
                            provider.name,
                            response.latency_ms,
                            response.input_tokens,
                            response.output_tokens,
                        )
                        return response

                    except Exception as exc:
                        last_exc = exc

                        # 413 = HTTP payload too large: shrink context and retry
                        if (
                            isinstance(exc, httpx.HTTPStatusError)
                            and exc.response.status_code == 413
                            and context_scale > 0.12  # stop shrinking below ~12%
                        ):
                            context_scale *= 0.5
                            logger.warning(
                                "413 Payload Too Large from %s — shrinking context to %.0f%%",
                                provider.name,
                                context_scale * 100,
                            )
                            time.sleep(2.0)  # brief pause before retry
                            continue  # retry same provider with smaller context

                        # 429 = rate limited: mark cooldown and rotate immediately.
                        # Don't waste time sleeping on a key that won't recover soon.
                        if (
                            isinstance(exc, httpx.HTTPStatusError)
                            and exc.response.status_code == 429
                        ):
                            cooldown = _cooldown_from_429(exc)
                            if cooldown >= _DAILY_QUOTA_COOLDOWN:
                                logger.warning(
                                    "Daily quota exhausted on %s — benching key for this run",
                                    provider.name,
                                )
                            else:
                                logger.warning(
                                    "Rate limit (429) from %s — cooling down %.0fs, rotating",
                                    provider.name,
                                    cooldown,
                                )
                            self._set_cooldown(provider, cooldown)
                            break  # skip remaining retries for this provider

                        # Timeout: the provider accepted the connection but never
                        # responded. Cool down briefly so subsequent chunks don't
                        # repeat the 30s wait on the same hung endpoint.
                        if isinstance(exc, httpx.TimeoutException):
                            logger.warning(
                                "Timeout from %s — cooling down %.0fs, rotating to next provider",
                                provider.name,
                                _TIMEOUT_COOLDOWN,
                            )
                            self._set_cooldown(provider, _TIMEOUT_COOLDOWN)
                            break

                        if not provider.is_retryable_error(exc):
                            logger.warning(
                                "Non-retryable error from %s: %s — rotating provider",
                                provider.name,
                                exc,
                            )
                            break  # Skip remaining retries, try next provider

                        delay = self._backoff_delay(attempt)
                        logger.warning(
                            "Retryable error from %s (attempt %d/%d): %s — sleeping %.1fs",
                            provider.name,
                            attempt,
                            self._max_retries,
                            exc,
                            delay,
                        )
                        time.sleep(delay)

                logger.error("Provider %s exhausted — trying next", provider.name)

        raise RuntimeError(f"All LLM providers exhausted. Last error: {last_exc}") from last_exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at BACKOFF_MAX seconds."""
        base = min(BACKOFF_BASE**attempt, BACKOFF_MAX)
        return base * (1 + random.uniform(-BACKOFF_JITTER, BACKOFF_JITTER))

    def _adapt_request(
        self,
        request: LLMRequest,
        provider: LLMProvider,
        context_scale: float = 1.0,
    ) -> LLMRequest:
        """
        Trim the <<<CODE>>> ... <<<END_CODE>>> block so the request fits within
        the provider's context window.

        context_scale: multiplier applied to max_context_tokens (1.0 = full,
        0.5 = half, etc.). Decreased automatically on 413 responses.
        """
        effective_max = int(provider.max_context_tokens * context_scale)
        # Rough approximation: 1 token ≈ 4 characters
        estimated_tokens = (len(request.system_prompt) + len(request.user_message)) // 4

        if estimated_tokens <= effective_max:
            return request

        budget_chars = effective_max * 4
        system_chars = len(request.system_prompt)
        available = budget_chars - system_chars - 500  # 500-char overhead buffer

        user_msg = request.user_message
        code_start = user_msg.find("<<<CODE>>>")
        code_end = user_msg.find("<<<END_CODE>>>")

        if code_start != -1 and code_end != -1:
            prefix = user_msg[: code_start + len("<<<CODE>>>")]
            suffix = user_msg[code_end:]
            code_block = user_msg[code_start + len("<<<CODE>>>") : code_end]
            max_block = max(available, 200)  # always keep at least 200 chars
            truncated = code_block[:max_block] + "\n\n[...TRUNCATED — context limit reached...]"
            user_msg = prefix + truncated + suffix
            _trim_msg = (
                f"Context trimmed from ~{int(estimated_tokens)} → ~{int(effective_max)}"
                f" effective tokens (scale={context_scale:.0%}) [{provider.name}]"
            )
            logger.warning(_trim_msg)

        return replace(request, user_message=user_msg)
