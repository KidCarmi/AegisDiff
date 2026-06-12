"""GitHub Models provider — zero-config fallback using GITHUB_TOKEN.

GitHub Models exposes an OpenAI-compatible API at
https://models.inference.ai.azure.com. Authentication uses the
standard GITHUB_TOKEN that is always injected into every GitHub
Actions run — no extra secrets required.

Free tier: limited RPM/TPD, but always available as last-resort fallback.
Model identifier format: just the model name WITHOUT publisher namespace
  (e.g. "Llama-3.3-70B-Instruct" not "meta/Llama-3.3-70B-Instruct")

Docs: https://docs.github.com/en/github-models
"""

from __future__ import annotations

import logging
import time

import httpx

from .base import LLMProvider, LLMRequest, LLMResponse

GITHUB_MODELS_URL = "https://models.inference.ai.azure.com/chat/completions"

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


class GitHubModelsProvider(LLMProvider):
    name = "github_models"
    model = "Llama-3.3-70B-Instruct"  # No namespace prefix — inference API uses bare model name
    max_context_tokens = 3_500  # ~3500 input + 1024 output ≈ 4500 total, safely under 8000
    # Free tier RPM is undocumented and conservative — space requests out
    min_request_interval = 5.0

    def __init__(self, github_token: str, model: str | None = None) -> None:
        self._token = github_token
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
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        t0 = time.monotonic()
        resp = httpx.post(
            GITHUB_MODELS_URL,
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
            logger.warning("GitHub Models HTTP %d: %s", resp.status_code, err_msg)

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
                        f"GitHub Models 400 rewritten to 413: {err_msg}",
                        request=resp.request,
                        response=synthetic,
                    )
                raise ValueError(f"GitHub Models API 400: {err_msg}")

        resp.raise_for_status()
        data = resp.json()
        latency = (time.monotonic() - t0) * 1000

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise ValueError(f"GitHub Models response missing content: {data}") from e
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
