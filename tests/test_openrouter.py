"""Tests for the OpenRouter LLM provider."""
from __future__ import annotations

import httpx
import pytest
import respx

from aegisdiff.llm.providers.base import LLMRequest
from aegisdiff.llm.providers.openrouter import OPENROUTER_API_URL, OpenRouterProvider

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

API_KEY = "sk-or-test-key-abc123"

SAMPLE_REQUEST = LLMRequest(
    system_prompt="You are a security expert.",
    user_message="Analyze this diff for vulnerabilities.",
)

VALID_RESPONSE_BODY = {
    "id": "gen-abc123",
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
        "prompt_tokens": 120,
        "completion_tokens": 45,
        "total_tokens": 165,
    },
    "model": "meta-llama/llama-3.3-70b-instruct:free",
}


def make_provider(model: str | None = None) -> OpenRouterProvider:
    return OpenRouterProvider(api_key=API_KEY, model=model)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestOpenRouterSuccess:
    @respx.mock
    def test_successful_completion_returns_response(self):
        respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.content == '{"verdict": "FALSE_POSITIVE", "confidence": 0.9}'
        assert resp.provider == "openrouter"
        assert resp.model == "meta-llama/llama-3.3-70b-instruct:free"
        assert resp.input_tokens == 120
        assert resp.output_tokens == 45
        assert resp.latency_ms >= 0

    @respx.mock
    def test_successful_completion_missing_usage_defaults_to_zero(self):
        body = {
            "choices": [
                {"message": {"role": "assistant", "content": "some content"}}
            ]
            # no "usage" key
        }
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.input_tokens == 0
        assert resp.output_tokens == 0


# ---------------------------------------------------------------------------
# is_retryable_error — status codes
# ---------------------------------------------------------------------------


class TestIsRetryableError:
    def _make_http_error(self, status_code: int) -> httpx.HTTPStatusError:
        req = httpx.Request("POST", OPENROUTER_API_URL)
        response = httpx.Response(status_code, request=req)
        return httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=req,
            response=response,
        )

    def test_429_too_many_requests_is_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(429)) is True

    def test_500_internal_server_error_is_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(500)) is True

    def test_502_bad_gateway_is_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(502)) is True

    def test_503_service_unavailable_is_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(503)) is True

    def test_504_gateway_timeout_is_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(504)) is True

    def test_404_not_found_is_not_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(404)) is False

    def test_401_unauthorized_is_not_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(401)) is False

    def test_403_forbidden_is_not_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(self._make_http_error(403)) is False

    def test_timeout_exception_is_retryable(self):
        provider = make_provider()
        exc = httpx.TimeoutException("Request timed out")
        assert provider.is_retryable_error(exc) is True

    def test_read_timeout_is_retryable(self):
        provider = make_provider()
        req = httpx.Request("POST", OPENROUTER_API_URL)
        exc = httpx.ReadTimeout("Read timed out", request=req)
        assert provider.is_retryable_error(exc) is True

    def test_network_error_is_retryable(self):
        provider = make_provider()
        exc = httpx.NetworkError("Connection reset by peer")
        assert provider.is_retryable_error(exc) is True

    def test_connect_error_is_retryable(self):
        provider = make_provider()
        exc = httpx.ConnectError("Connection refused")
        assert provider.is_retryable_error(exc) is True

    def test_generic_exception_is_not_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(ValueError("bad")) is False

    def test_runtime_error_is_not_retryable(self):
        provider = make_provider()
        assert provider.is_retryable_error(RuntimeError("unexpected")) is False


# ---------------------------------------------------------------------------
# 400 handling — size error → rewrite to 413
# ---------------------------------------------------------------------------


class TestBadRequestHandling:
    @respx.mock
    def test_400_with_too_large_phrase_raises_413_http_status_error(self):
        body = {"error": {"message": "Request too large for this model"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            provider.complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_with_context_length_exceeded_raises_413(self):
        body = {"error": {"message": "context_length_exceeded, please reduce your input"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            provider.complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_with_maximum_context_phrase_raises_413(self):
        body = {"error": {"message": "Exceeds maximum context length of 6000 tokens"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            provider.complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_with_token_limit_phrase_raises_413(self):
        body = {"error": {"message": "You have exceeded the token limit for this request"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            provider.complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_with_empty_error_message_raises_413(self):
        # Empty err_msg triggers the same size-error branch
        body = {"error": {"message": ""}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            provider.complete(SAMPLE_REQUEST)

        assert exc_info.value.response.status_code == 413

    @respx.mock
    def test_400_with_non_size_error_raises_value_error(self):
        body = {"error": {"message": "Invalid model specified"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(ValueError, match="OpenRouter API 400: Invalid model specified"):
            provider.complete(SAMPLE_REQUEST)

    @respx.mock
    def test_400_non_size_error_does_not_raise_http_status_error(self):
        body = {"error": {"message": "Model is currently unavailable"}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(400, json=body))

        provider = make_provider()
        with pytest.raises(ValueError):
            provider.complete(SAMPLE_REQUEST)
        # Must NOT be an HTTPStatusError (which would trigger orchestrator 413 path)


# ---------------------------------------------------------------------------
# Malformed response content
# ---------------------------------------------------------------------------


class TestMalformedResponse:
    @respx.mock
    def test_missing_choices_key_raises_value_error(self):
        body = {"usage": {"prompt_tokens": 10, "completion_tokens": 5}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        with pytest.raises(ValueError, match="OpenRouter response missing content"):
            provider.complete(SAMPLE_REQUEST)

    @respx.mock
    def test_empty_choices_array_raises_value_error(self):
        body = {"choices": [], "usage": {}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        with pytest.raises(ValueError, match="OpenRouter response missing content"):
            provider.complete(SAMPLE_REQUEST)

    @respx.mock
    def test_missing_message_key_in_choice_raises_value_error(self):
        body = {"choices": [{"finish_reason": "stop"}], "usage": {}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        with pytest.raises(ValueError, match="OpenRouter response missing content"):
            provider.complete(SAMPLE_REQUEST)

    @respx.mock
    def test_missing_content_key_in_message_raises_value_error(self):
        body = {"choices": [{"message": {"role": "assistant"}}], "usage": {}}
        respx.post(OPENROUTER_API_URL).mock(return_value=httpx.Response(200, json=body))

        provider = make_provider()
        with pytest.raises(ValueError, match="OpenRouter response missing content"):
            provider.complete(SAMPLE_REQUEST)


# ---------------------------------------------------------------------------
# Required headers
# ---------------------------------------------------------------------------


class TestRequiredHeaders:
    @respx.mock
    def test_authorization_header_sent_with_bearer_token(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        provider.complete(SAMPLE_REQUEST)

        sent_request = route.calls.last.request
        assert sent_request.headers["Authorization"] == f"Bearer {API_KEY}"

    @respx.mock
    def test_http_referer_header_sent(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        provider.complete(SAMPLE_REQUEST)

        sent_request = route.calls.last.request
        assert sent_request.headers["HTTP-Referer"] == "https://aegisdiff.orelsec.com"

    @respx.mock
    def test_x_title_header_sent(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        provider.complete(SAMPLE_REQUEST)

        sent_request = route.calls.last.request
        assert sent_request.headers["X-Title"] == "AegisDiff"

    @respx.mock
    def test_all_three_required_headers_present_simultaneously(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        provider.complete(SAMPLE_REQUEST)

        headers = route.calls.last.request.headers
        assert "Authorization" in headers
        assert "HTTP-Referer" in headers
        assert "X-Title" in headers


# ---------------------------------------------------------------------------
# Custom model parameter
# ---------------------------------------------------------------------------


class TestCustomModel:
    @respx.mock
    def test_default_model_used_when_none_provided(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider(model=None)
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.model == "meta-llama/llama-3.3-70b-instruct:free"
        import json
        payload = json.loads(route.calls.last.request.content)
        assert payload["model"] == "meta-llama/llama-3.3-70b-instruct:free"

    @respx.mock
    def test_custom_model_overrides_default(self):
        custom_model = "mistralai/mistral-7b-instruct:free"
        custom_body = dict(VALID_RESPONSE_BODY)
        custom_body["model"] = custom_model
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=custom_body)
        )

        provider = make_provider(model=custom_model)
        resp = provider.complete(SAMPLE_REQUEST)

        assert resp.model == custom_model
        import json
        payload = json.loads(route.calls.last.request.content)
        assert payload["model"] == custom_model

    def test_custom_model_set_as_instance_attribute(self):
        custom_model = "google/gemma-7b-it:free"
        provider = OpenRouterProvider(api_key=API_KEY, model=custom_model)
        assert provider.model == custom_model

    def test_no_custom_model_leaves_class_default(self):
        provider = OpenRouterProvider(api_key=API_KEY)
        assert provider.model == "meta-llama/llama-3.3-70b-instruct:free"


# ---------------------------------------------------------------------------
# Payload structure
# ---------------------------------------------------------------------------


class TestRequestPayload:
    @respx.mock
    def test_system_and_user_messages_sent_in_payload(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        provider = make_provider()
        provider.complete(SAMPLE_REQUEST)

        import json
        payload = json.loads(route.calls.last.request.content)
        messages = payload["messages"]
        assert messages[0] == {"role": "system", "content": SAMPLE_REQUEST.system_prompt}
        assert messages[1] == {"role": "user", "content": SAMPLE_REQUEST.user_message}

    @respx.mock
    def test_max_tokens_and_temperature_sent_in_payload(self):
        route = respx.post(OPENROUTER_API_URL).mock(
            return_value=httpx.Response(200, json=VALID_RESPONSE_BODY)
        )

        request = LLMRequest(
            system_prompt="Sys.",
            user_message="User.",
            max_tokens=1024,
            temperature=0.2,
        )
        provider = make_provider()
        provider.complete(request)

        import json
        payload = json.loads(route.calls.last.request.content)
        assert payload["max_tokens"] == 1024
        assert payload["temperature"] == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


class TestProviderMetadata:
    def test_provider_name_is_openrouter(self):
        assert OpenRouterProvider.name == "openrouter"

    def test_max_context_tokens_is_6000(self):
        assert OpenRouterProvider.max_context_tokens == 6_000

    def test_default_model_contains_free_suffix(self):
        assert ":free" in OpenRouterProvider.model
