"""Groq (Llama-3-70b) provider — fallback LLM engine."""
from __future__ import annotations

import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqProvider(LLMProvider):
    name = "groq"
    model = "llama3-70b-8192"
    max_context_tokens = 7_000  # 8192 limit; reserve ~1192 for output

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

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
        headers = {"Authorization": f"Bearer {self._api_key}"}
        t0 = time.monotonic()
        resp = httpx.post(
            GROQ_API_URL,
            json=payload,
            headers=headers,
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        content = data["choices"][0]["message"]["content"]
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
