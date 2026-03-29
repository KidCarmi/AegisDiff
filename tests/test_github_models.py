"""Tests for the GitHub Models LLM provider (zero-config GITHUB_TOKEN fallback)."""
from __future__ import annotations

import httpx
import pytest
import respx

from aegisdiff.llm.providers.base import LLMRequest
from aegisdiff.llm.providers.github_models import GITHUB_MODELS_URL, GitHubModelsProvider

GITHUB_TOKEN = "ghs_test_token_abc123"

SAMPLE_REQUEST = LLMRequest(
    system_prompt="You are a security expert.",
    user_message="Analyze this diff.",
)

VALID_RESPONSE_BODY = {
    "id": "chatcmpl-xyz",
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": '{"verdict": "TRUE_POSITIVE", "confidence": 0.85}',
            },
            "finish_reason": "stop",
            "index": 0,
        }
    ],
    "usage": {
        "prompt_tokens": 90,
        "completion_tokens": 55,
        "total_tokens": 145,
    },
    "model": "Llama-3.3-70B-Instruct",
}


def make_provider(model: str | None = None) -> GitHubModelsProvider:
    return GitHubModelsProvider(github_token=GITHUB_TOKEN, model=model)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestGitHubModelsSuccess:
    @respx.mock
    def test_successful_completion_returns_response(self):
        respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.content == '{"verdict": "TRUE_POSITIVE", "confidence": 0.85}'
        assert resp.provider == "github_models"
        assert resp.model == "Llama-3.3-70B-Instruct"
        assert resp.input_tokens == 90
        assert resp.output_tokens == 55
        assert resp.latency_ms >= 0

    @respx.mock
    def test_missing_usage_defaults_to_zero(self):
        body = {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(200, json=body))

        resp = make_provider().complete(SAMPLE_REQUEST)

        assert resp.input_tokens == 0
        assert resp.output_tokens == 0


# ---------------------------------------------------------------------------
# Model name — no namespace prefix (bare name required)
# ---------------------------------------------------------------------------


class TestModelName:
    def test_default_model_has_no_namespace_prefix(self):
        """GitHub Models rejects "meta/Llama-3.3-70B-Instruct" — must be bare name."""
        provider = make_provider()
        assert "/" not in provider.model
        assert provider.model == "Llama-3.3-70B-Instruct"

    def test_custom_model_override(self):
        provider = GitHubModelsProvider(github_token=GITHUB_TOKEN, model="Phi-3.5-mini-instruct")
        assert provider.model == "Phi-3.5-mini-instruct"

    def test_no_custom_model_keeps_default(self):
        provider = GitHubModelsProvider(github_token=GITHUB_TOKEN)
        assert provider.model == "Llama-3.3-70B-Instruct"

    @respx.mock
    def test_bare_model_name_sent_in_payload(self):
        import json

        route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )
        make_provider().complete(SAMPLE_REQUEST)

        payload = json.loads(route.calls.last.request.content)
        assert payload["model"] == "Llama-3.3-70B-Instruct"
        assert "/" not in payload["model"]


# ---------------------------------------------------------------------------
# Authorization header
# ---------------------------------------------------------------------------


class TestAuthorizationHeader:
    @respx.mock
    def test_bearer_token_sent_in_authorization_header(self):
        route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )
        make_provider().complete(SAMPLE_REQUEST)

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {GITHUB_TOKEN}"


# ---------------------------------------------------------------------------
# is_retryable_error
# ---------------------------------------------------------------------------


class TestIsRetryableError:
    def _make_http_error(self, status_code: int) -> httpx.HTTPStatusError:
        req = httpx.Request("POST", GITHUB_MODELS_URL)
        response = httpx.Response(status_code, request=req)
        return httpx.HTTPStatusError(f"HTTP {status_code}", request=req, response=response)

    def test_429_is_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(429)) is True

    def test_500_is_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(500)) is True

    def test_502_is_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(502)) is True

    def test_503_is_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(503)) is True

    def test_504_is_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(504)) is True

    def test_401_is_not_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(401)) is False

    def test_403_is_not_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(403)) is False

    def test_timeout_is_retryable(self):
        assert make_provider().is_retryable_error(httpx.TimeoutException("timeout")) is True

    def test_network_error_is_retryable(self):
        assert make_provider().is_retryable_error(httpx.NetworkError("reset")) is True

    def test_generic_exception_is_not_retryable(self):
        assert make_provider().is_retryable_error(ValueError("bad")) is False


# ---------------------------------------------------------------------------
# 400 → 413 rewrite
# ---------------------------------------------------------------------------


class TestBadRequestHandling:
    @respx.mock
    def test_400_context_too_large_rewrites_to_413(self):
        body = {"error": {"message": "Request too large for this model"}}
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_context_length_exceeded_rewrites_to_413(self):
        body = {"error": {"message": "context_length_exceeded"}}
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_empty_message_rewrites_to_413(self):
        body = {"error": {"message": ""}}
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_non_size_error_raises_value_error(self):
        body = {"error": {"message": "Model not found"}}
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(ValueError, match="GitHub Models API 400: Model not found"):
            make_provider().complete(SAMPLE_REQUEST)


# ---------------------------------------------------------------------------
# Malformed response
# ---------------------------------------------------------------------------


class TestMalformedResponse:
    @respx.mock
    def test_missing_choices_raises_value_error(self):
        respx.post(GITHUB_MODELS_URL).mock(return_value=httpx.Response(200, json={"usage": {}}))

        with pytest.raises(ValueError, match="GitHub Models response missing content"):
            make_provider().complete(SAMPLE_REQUEST)

    @respx.mock
    def test_empty_choices_raises_value_error(self):
        respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json={"choices": [], "usage": {}})
        )

        with pytest.raises(ValueError, match="GitHub Models response missing content"):
            make_provider().complete(SAMPLE_REQUEST)


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


class TestProviderMetadata:
    def test_provider_name_is_github_models(self):
        assert GitHubModelsProvider.name == "github_models"

    def test_max_context_tokens_is_conservative(self):
        # Must be ≤ 3500 to leave room for output tokens under 8k total
        assert GitHubModelsProvider.max_context_tokens <= 3_500

    def test_model_is_llama_33_70b(self):
        assert "Llama" in GitHubModelsProvider.model or "llama" in GitHubModelsProvider.model
