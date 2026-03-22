"""Google Gemini 1.5 Pro provider — primary LLM engine."""
from __future__ import annotations

import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-pro-latest:generateContent"
)


class GeminiProvider(LLMProvider):
    name = "gemini"
    model = "gemini-1.5-pro-latest"
    max_context_tokens = 900_000  # Leave 100k headroom below the 1M limit

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def complete(self, request: LLMRequest) -> LLMResponse:
        payload = {
            "system_instruction": {"parts": [{"text": request.system_prompt}]},
            "contents": [{"parts": [{"text": request.user_message}]}],
            "generationConfig": {
                "maxOutputTokens": request.max_tokens,
                "temperature": request.temperature,
            },
        }
        t0 = time.monotonic()
        resp = httpx.post(
            GEMINI_API_URL,
            params={"key": self._api_key},
            json=payload,
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        content = data["candidates"][0]["content"]["parts"][0]["text"]
        usage = data.get("usageMetadata", {})

        return LLMResponse(
            content=content,
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            latency_ms=latency,
        )

    def is_retryable_error(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {429, 500, 502, 503, 504}
        return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError))
