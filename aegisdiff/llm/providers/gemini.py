"""Google Gemini 2.0 Flash provider — primary LLM engine."""

from __future__ import annotations

import logging
import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

# gemini-1.5-pro-latest was deprecated; gemini-2.0-flash is the current
# recommended model — faster, same 1M context window, free tier available.
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
)

logger = logging.getLogger(__name__)


class GeminiProvider(LLMProvider):
    name = "gemini"
    model = "gemini-2.0-flash"
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
        if not resp.is_success:
            try:
                err_body = resp.json()
                err_msg = str(err_body.get("error", {}).get("message", resp.text[:300]))
            except Exception:
                err_msg = resp.text[:300]
            logger.warning("Gemini HTTP %d: %s", resp.status_code, err_msg)
            # Raise with the actual API error body so it surfaces in the dashboard title.
            # Use httpx.HTTPStatusError for retryable codes so the orchestrator backs off;
            # use ValueError for non-retryable codes so the full message is visible.
            if resp.status_code in {429, 500, 502, 503, 504}:
                resp.raise_for_status()
            raise ValueError(f"Gemini {resp.status_code}: {err_msg}")
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        try:
            content = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            # Safety filter or unexpected response shape (e.g. finishReason=SAFETY)
            candidates = data.get("candidates")
            finish = candidates[0].get("finishReason", "UNKNOWN") if candidates else "NO_CANDIDATES"
            raise ValueError(f"Gemini response missing content (finishReason={finish})") from e
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
