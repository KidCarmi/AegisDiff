"""Tests for the Groq LLM provider."""
from __future__ import annotations

import httpx
import pytest
import respx

from aegisdiff.llm.providers.base import LLMRequest
from aegisdiff.llm.providers.groq import GROQ_API_URL, GroqProvider

API_KEY = "test_groq_api_key_abc123"

SAMPLE_REQUEST = LLMRequest(
    system_prompt="You are a security expert.",
    user_message="Analyze this diff for vulnerabilities.",
)

VALID_RESPONSE_BODY = {
    "id": "chatcmpl-abc123",
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": '{"verdict": "FALSE_POSITIVE", "confidence": 0.9}',
            },
            "finish_reason": "stop",
            "index": 0,
        }
    ],
    "usage": {
        "prompt_tokens": 110,
        "completion_tokens": 40,
        "total_tokens": 150,
    },
    "model": "llama-3.3-70b-versatile",
}


def make_provider(model: str | None = None) -> GroqProvider:
    return GroqProvider(api_key=API_KEY, model=model)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestGroqSuccess:
    @respx.mock
    def test_successful_completion_returns_response(self):
        respx.post(GROQ_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.content == '{"verdict": "FALSE_POSITIVE", "confidence": 0.9}'
        assert resp.provider == "groq"
        assert resp.model == "llama-3.3-70b-versatile"
        assert resp.input_tokens == 110
        assert resp.output_tokens == 40
        assert resp.latency_ms >= 0

    @respx.mock
    def test_missing_usage_defaults_to_zero(self):
        body = {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.input_tokens == 0
        assert resp.output_tokens == 0


# ---------------------------------------------------------------------------
# is_retryable_error
# ---------------------------------------------------------------------------


class TestIsRetryableError:
    def _make_http_error(self, status_code: int) -> httpx.HTTPStatusError:
        req = httpx.Request("POST", GROQ_API_URL)
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

    def test_404_is_not_retryable(self):
        assert make_provider().is_retryable_error(self._make_http_error(404)) is False

    def test_timeout_is_retryable(self):
        assert make_provider().is_retryable_error(httpx.TimeoutException("timeout")) is True

    def test_read_timeout_is_retryable(self):
        req = httpx.Request("POST", GROQ_API_URL)
        exc = httpx.ReadTimeout("read timeout", request=req)
        assert make_provider().is_retryable_error(exc) is True

    def test_network_error_is_retryable(self):
        assert make_provider().is_retryable_error(httpx.NetworkError("reset")) is True

    def test_generic_exception_is_not_retryable(self):
        assert make_provider().is_retryable_error(ValueError("bad")) is False


# ---------------------------------------------------------------------------
# 400 → 413 rewrite for context-too-large errors
# ---------------------------------------------------------------------------


class TestBadRequestHandling:
    @respx.mock
    def test_400_request_too_large_rewrites_to_413(self):
        body = {"error": {"message": "Request too large for this model"}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_context_length_exceeded_rewrites_to_413(self):
        body = {"error": {"message": "context_length_exceeded"}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_token_limit_phrase_rewrites_to_413(self):
        body = {"error": {"message": "token limit exceeded for this request"}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_empty_error_message_rewrites_to_413(self):
        body = {"error": {"message": ""}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            make_provider().complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_non_size_error_raises_value_error(self):
        body = {"error": {"message": "Invalid API key"}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(400, json=body))

        with pytest.raises(ValueError, match="Groq API 400: Invalid API key"):
            make_provider().complete(SAMPLE_REQUEST)

    @respx.mock
    def test_429_raises_http_status_error(self):
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(429))

        with pytest.raises(httpx.HTTPStatusError):
            make_provider().complete(SAMPLE_REQUEST)


# ---------------------------------------------------------------------------
# Malformed response
# ---------------------------------------------------------------------------


class TestMalformedResponse:
    @respx.mock
    def test_missing_choices_raises_value_error(self):
        body = {"usage": {}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(200, json=body))

        with pytest.raises(ValueError, match="Groq response missing content"):
            make_provider().complete(SAMPLE_REQUEST)

    @respx.mock
    def test_empty_choices_raises_value_error(self):
        body = {"choices": [], "usage": {}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(200, json=body))

        with pytest.raises(ValueError, match="Groq response missing content"):
            make_provider().complete(SAMPLE_REQUEST)

    @respx.mock
    def test_missing_content_in_message_raises_value_error(self):
        body = {"choices": [{"message": {"role": "assistant"}}], "usage": {}}
        respx.post(GROQ_API_URL).mock(return_value=httpx.Response(200, json=body))

        with pytest.raises(ValueError, match="Groq response missing content"):
            make_provider().complete(SAMPLE_REQUEST)


# ---------------------------------------------------------------------------
# Request payload
# ---------------------------------------------------------------------------


class TestRequestPayload:
    @respx.mock
    def test_authorization_header_uses_bearer_token(self):
        route = respx.post(GROQ_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        make_provider().complete(SAMPLE_REQUEST)

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {API_KEY}"

    @respx.mock
    def test_system_and_user_messages_in_payload(self):
        import json

        route = respx.post(GROQ_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        make_provider().complete(SAMPLE_REQUEST)

        payload = json.loads(route.calls.last.request.content)
        assert payload["messages"][0] == {
            "role": "system",
            "content": SAMPLE_REQUEST.system_prompt,
        }
        assert payload["messages"][1] == {
            "role": "user",
            "content": SAMPLE_REQUEST.user_message,
        }

    @respx.mock
    def test_correct_model_sent_in_payload(self):
        import json

        route = respx.post(GROQ_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        make_provider().complete(SAMPLE_REQUEST)

        payload = json.loads(route.calls.last.request.content)
        assert payload["model"] == "llama-3.3-70b-versatile"


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


class TestProviderMetadata:
    def test_provider_name_is_groq(self):
        assert GroqProvider.name == "groq"

    def test_default_model(self):
        assert GroqProvider.model == "llama-3.3-70b-versatile"

    def test_max_context_tokens(self):
        assert GroqProvider.max_context_tokens == 6_000

    def test_custom_model_overrides_default(self):
        provider = GroqProvider(api_key=API_KEY, model="custom-model")
        assert provider.model == "custom-model"

    def test_no_custom_model_keeps_default(self):
        provider = GroqProvider(api_key=API_KEY)
        assert provider.model == "llama-3.3-70b-versatile"
