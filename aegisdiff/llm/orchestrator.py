"""
LLM Orchestrator — provider failover with exponential backoff.

Priority order: OpenRouter llama-3.3-70b:free → OpenRouter gemma-3-9b-it:free
               → GitHub Models Llama-3.3-70B-Instruct (GITHUB_TOKEN fallback).
On retryable errors (429, timeout, 5xx): exponential backoff + jitter, up to max_retries.
On non-retryable errors: immediately rotate to the next provider.
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


class LLMOrchestrator:
    """
    Manages a priority-ordered list of LLM providers with automatic failover.

    Usage::

        orchestrator = LLMOrchestrator([GeminiProvider(key), GroqProvider(key)])
        response = orchestrator.complete(request)
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

    def complete(self, request: LLMRequest) -> LLMResponse:
        last_exc: Optional[Exception] = None

        # Two outer passes: first try all providers, then (if all rate-limited)
        # sleep once and try the whole list again before giving up.
        for full_pass in range(2):
            if full_pass == 1:
                logger.warning(
                    "All providers rate-limited — sleeping 30s before retrying full list"
                )
                time.sleep(30.0)

            for provider in self._providers:
                # context_scale tracks adaptive trimming: halved on every 413 response
                context_scale = 1.0

                for attempt in range(1, self._max_retries + 1):
                    adapted = self._adapt_request(request, provider, context_scale)
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
                            continue  # retry same provider with smaller context

                        # 429 = rate limited: rotate immediately, don't waste time
                        # sleeping on a key that won't recover for ~60s.
                        if (
                            isinstance(exc, httpx.HTTPStatusError)
                            and exc.response.status_code == 429
                        ):
                            logger.warning(
                                "Rate limit (429) from %s — rotating to next provider",
                                provider.name,
                            )
                            break  # skip remaining retries for this provider

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
            logger.warning(
                "Context trimmed from ~%d → ~%d effective tokens for provider %s (scale=%.0f%%)",
                estimated_tokens,
                effective_max,
                provider.name,
                context_scale * 100,
            )

        return replace(request, user_message=user_msg)
