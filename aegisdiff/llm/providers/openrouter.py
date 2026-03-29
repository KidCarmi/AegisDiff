"""OpenRouter provider — free-tier LLM engine via aggregated model pool.

Uses the ':free' model variants which are genuinely free with no credit
card required. Primary model: meta-llama/llama-3.3-70b-instruct:free.
"""

from __future__ import annotations

import logging
import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

logger = logging.getLogger(__name__)

_TOO_LARGE_PHRASES = (
    "too large",
    "too long",
    "reduce",
    "context_length_exceeded",
    "maximum context",
    "tokens per",
    "token limit",
    "exceeds",
)


class OpenRouterProvider(LLMProvider):
    name = "openrouter"
    # ':free' suffix = always free, no credits consumed
    model = "meta-llama/llama-3.3-70b-instruct:free"  # default primary model
    max_context_tokens = 6_000  # Conservative below free-tier burst limit

    def __init__(self, api_key: str, model: str | None = None) -> None:
        self._api_key = api_key
        if model is not None:
            self.model = model

    def complete(self, request: LLMRequest) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_message},
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            # OpenRouter strongly recommends these headers for free-tier routing
            "HTTP-Referer": "https://aegisdiff.orelsec.com",
            "X-Title": "AegisDiff",
        }
        t0 = time.monotonic()
        resp = httpx.post(
            OPENROUTER_API_URL,
            json=payload,
            headers=headers,
            timeout=30.0,
        )
        if not resp.is_success:
            try:
                err_body = resp.json()
                err_msg = err_body.get("error", {}).get("message", "")
            except Exception:
                err_msg = resp.text[:300]
            logger.warning("OpenRouter HTTP %d: %s", resp.status_code, err_msg)

            if resp.status_code == 400:
                is_size_error = any(phrase in err_msg.lower() for phrase in _TOO_LARGE_PHRASES)
                if is_size_error or not err_msg:
                    synthetic = httpx.Response(
                        status_code=413,
                        headers=resp.headers,
                        content=resp.content,
                        request=resp.request,
                    )
                    raise httpx.HTTPStatusError(
                        f"OpenRouter 400 rewritten to 413 (context too large): {err_msg}",
                        request=resp.request,
                        response=synthetic,
                    )
                logger.error("OpenRouter 400 (non-size): %s", err_msg)
                raise ValueError(f"OpenRouter API 400: {err_msg}")

        resp.raise_for_status()
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise ValueError(f"OpenRouter response missing content: {data}") from e
        usage = data.get("usage", {})

        return LLMResponse(
            content=content,
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
        )

    def is_retryable_error(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {429, 500, 502, 503, 504}
        return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError))
