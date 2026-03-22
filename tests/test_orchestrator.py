"""Tests for the LLM orchestrator failover logic."""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import httpx
import pytest

from aegisdiff.llm.orchestrator import LLMOrchestrator
from aegisdiff.llm.providers.base import LLMProvider, LLMRequest, LLMResponse


def make_mock_provider(name: str, max_tokens: int = 900_000) -> MagicMock:
    provider = MagicMock(spec=LLMProvider)
    provider.name = name
    provider.max_context_tokens = max_tokens
    return provider


def make_response(provider_name: str) -> LLMResponse:
    return LLMResponse(
        content='{"verdict": "FALSE_POSITIVE", "severity": "N/A", "cwe_id": "N/A", '
                '"confidence": 0.9, "title": "Test", "summary": "Test summary.", '
                '"evidence": "", "sanitizer_found": false, "sanitizer_description": null, '
                '"attack_vector": null, "remediation": null, "false_positive_reason": "test"}',
        provider=provider_name,
        model="test-model",
        input_tokens=100,
        output_tokens=50,
        latency_ms=150.0,
    )


SAMPLE_REQUEST = LLMRequest(
    system_prompt="You are a security expert.",
    user_message="Analyze this code.",
)


class TestOrchestratorSuccess:
    def test_returns_primary_on_success(self):
        primary = make_mock_provider("gemini")
        primary.complete.return_value = make_response("gemini")
        primary.is_retryable_error.return_value = False

        orch = LLMOrchestrator([primary])
        resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "gemini"
        primary.complete.assert_called_once()

    def test_falls_back_to_secondary_on_non_retryable_error(self):
        primary = make_mock_provider("gemini")
        primary.complete.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )
        primary.is_retryable_error.return_value = False

        secondary = make_mock_provider("groq", max_tokens=7000)
        secondary.complete.return_value = make_response("groq")
        secondary.is_retryable_error.return_value = False

        orch = LLMOrchestrator([primary, secondary])
        resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "groq"
        primary.complete.assert_called_once()
        secondary.complete.assert_called_once()


class TestOrchestratorRetry:
    def test_retries_on_retryable_error_then_succeeds(self):
        provider = make_mock_provider("gemini")
        provider.is_retryable_error.return_value = True
        provider.complete.side_effect = [
            httpx.HTTPStatusError(
                "429", request=MagicMock(), response=MagicMock(status_code=429)
            ),
            make_response("gemini"),
        ]

        orch = LLMOrchestrator([provider], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "gemini"
        assert provider.complete.call_count == 2

    def test_exhausts_all_providers_raises_runtime_error(self):
        primary = make_mock_provider("gemini")
        primary.is_retryable_error.return_value = True
        primary.complete.side_effect = Exception("rate limited")

        secondary = make_mock_provider("groq")
        secondary.is_retryable_error.return_value = True
        secondary.complete.side_effect = Exception("timeout")

        orch = LLMOrchestrator([primary, secondary], max_retries_per_provider=2)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            with pytest.raises(RuntimeError, match="All LLM providers exhausted"):
                orch.complete(SAMPLE_REQUEST)


class TestContextAdaptation:
    def test_context_trimmed_for_small_window_provider(self):
        provider = make_mock_provider("groq", max_tokens=100)  # Very small window
        provider.complete.return_value = make_response("groq")
        provider.is_retryable_error.return_value = False

        long_code = "x" * 5000
        request = LLMRequest(
            system_prompt="System.",
            user_message=f"Intro <<<CODE>>>{long_code}<<<END_CODE>>> Outro",
        )

        orch = LLMOrchestrator([provider])
        orch.complete(request)

        actual_request = provider.complete.call_args[0][0]
        assert "TRUNCATED" in actual_request.user_message
        assert len(actual_request.user_message) < len(request.user_message)

    def test_no_trimming_when_within_budget(self):
        provider = make_mock_provider("gemini", max_tokens=900_000)
        provider.complete.return_value = make_response("gemini")
        provider.is_retryable_error.return_value = False

        orch = LLMOrchestrator([provider])
        orch.complete(SAMPLE_REQUEST)

        actual = provider.complete.call_args[0][0]
        assert actual.user_message == SAMPLE_REQUEST.user_message


class TestInitialization:
    def test_empty_providers_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            LLMOrchestrator([])
