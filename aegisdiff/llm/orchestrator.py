"""
LLM Orchestrator — provider failover with exponential backoff.

Priority order: Gemini 1.5 Pro → Groq Llama-3.
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

        for provider in self._providers:
            adapted = self._adapt_request(request, provider)

            for attempt in range(1, self._max_retries + 1):
                try:
                    logger.info(
                        "LLM attempt %d/%d via %s",
                        attempt,
                        self._max_retries,
                        provider.name,
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

        raise RuntimeError(
            f"All LLM providers exhausted. Last error: {last_exc}"
        ) from last_exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at BACKOFF_MAX seconds."""
        base = min(BACKOFF_BASE**attempt, BACKOFF_MAX)
        return base * (1 + random.uniform(-BACKOFF_JITTER, BACKOFF_JITTER))

    def _adapt_request(self, request: LLMRequest, provider: LLMProvider) -> LLMRequest:
        """
        Trim the <<<CODE>>> ... <<<END_CODE>>> block if the request would exceed
        the provider's context window.  This is critical when falling back from
        Gemini (900k tokens) to Groq (7k tokens).
        """
        # Rough approximation: 1 token ≈ 4 characters
        estimated_tokens = (len(request.system_prompt) + len(request.user_message)) // 4

        if estimated_tokens <= provider.max_context_tokens:
            return request

        budget_chars = provider.max_context_tokens * 4
        system_chars = len(request.system_prompt)
        available = budget_chars - system_chars - 500  # 500-char overhead buffer

        user_msg = request.user_message
        code_start = user_msg.find("<<<CODE>>>")
        code_end = user_msg.find("<<<END_CODE>>>")

        if code_start != -1 and code_end != -1:
            prefix = user_msg[: code_start + len("<<<CODE>>>")]
            suffix = user_msg[code_end:]
            code_block = user_msg[code_start + len("<<<CODE>>>") : code_end]
            truncated = (
                code_block[:available] + "\n\n[...TRUNCATED — context limit reached...]"
            )
            user_msg = prefix + truncated + suffix
            logger.warning(
                "Context trimmed from ~%d → ~%d tokens for provider %s",
                estimated_tokens,
                provider.max_context_tokens,
                provider.name,
            )

        return replace(request, user_message=user_msg)
