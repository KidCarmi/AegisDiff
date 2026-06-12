"""Groq provider — fast inference via Groq Cloud free tier.

Groq uses custom LPU silicon for inference. Key properties:
- Free tier does NOT train on requests (inference-only company).
- OpenAI-compatible API — minimal integration effort.
- No known Azure IP blocks (works from GitHub Actions).
- Free tier rate limit: 30 RPM, ~14,400 RPD for Llama 3.3 70B Versatile.
- Context window: 128k tokens (generous; we use 8k conservatively).

Model: llama-3.3-70b-versatile (best free-tier option; same family as OpenRouter primary).

Docs: https://console.groq.com/docs/openai
"""

from __future__ import annotations

import logging
import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

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
    "request too large",
)


class GroqProvider(LLMProvider):
    name = "groq"
    model = "llama-3.3-70b-versatile"
    # 128k context window; keep conservative to stay well under free-tier TPM limits
    max_context_tokens = 6_000
    # Free tier allows 30 req/min per key (2s spacing)
    min_request_interval = 2.0

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
            "Content-Type": "application/json",
        }
        t0 = time.monotonic()
        resp = httpx.post(
            GROQ_API_URL,
            json=payload,
            headers=headers,
            timeout=60.0,
        )
        if not resp.is_success:
            try:
                err_body = resp.json()
                err_msg = err_body.get("error", {}).get("message", "")
            except Exception:
                err_msg = resp.text[:300]
            logger.warning("Groq HTTP %d: %s", resp.status_code, err_msg)

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
                        f"Groq 400 rewritten to 413: {err_msg}",
                        request=resp.request,
                        response=synthetic,
                    )
                raise ValueError(f"Groq API 400: {err_msg}")

        resp.raise_for_status()
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise ValueError(f"Groq response missing content: {data}") from e
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
