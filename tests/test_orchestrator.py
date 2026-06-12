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
    provider.min_request_interval = 0.0  # no pacing unless a test opts in
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
        """Non-429 retryable errors (e.g. 503) are retried within the same provider."""
        provider = make_mock_provider("openrouter")
        provider.is_retryable_error.return_value = True
        provider.complete.side_effect = [
            httpx.HTTPStatusError("503", request=MagicMock(), response=MagicMock(status_code=503)),
            make_response("openrouter"),
        ]

        orch = LLMOrchestrator([provider], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "openrouter"
        assert provider.complete.call_count == 2

    def test_429_sets_cooldown_skips_provider_on_second_pass(self):
        """429 puts the provider in cooldown; it is NOT retried even on the second pass."""
        provider = make_mock_provider("openrouter")
        provider.is_retryable_error.return_value = True
        provider.complete.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=MagicMock(status_code=429)
        )

        orch = LLMOrchestrator([provider], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            with pytest.raises(RuntimeError, match="All LLM providers exhausted"):
                orch.complete(SAMPLE_REQUEST)

        # Provider called exactly once — cooldown prevents any retries
        assert provider.complete.call_count == 1

    def test_429_fails_over_to_next_provider(self):
        """429 on provider 1 immediately fails over to provider 2 without retries."""
        p1 = make_mock_provider("openrouter")
        p1.is_retryable_error.return_value = True
        p1.complete.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=MagicMock(status_code=429)
        )

        p2 = make_mock_provider("groq")
        p2.is_retryable_error.return_value = False
        p2.complete.return_value = make_response("groq")

        orch = LLMOrchestrator([p1, p2], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "groq"
        assert p1.complete.call_count == 1  # tried once, then cooled down
        assert p2.complete.call_count == 1  # got the request immediately

    def test_timeout_sets_short_cooldown(self):
        """ReadTimeout on provider 1 sets a short cooldown and fails over to provider 2."""
        p1 = make_mock_provider("openrouter")
        p1.is_retryable_error.return_value = True
        p1.complete.side_effect = httpx.ReadTimeout("timed out", request=MagicMock())

        p2 = make_mock_provider("groq")
        p2.is_retryable_error.return_value = False
        p2.complete.return_value = make_response("groq")

        orch = LLMOrchestrator([p1, p2], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep"):
            resp = orch.complete(SAMPLE_REQUEST)

        assert resp.provider == "groq"
        # p1 tried once then cooldown, not retried
        assert p1.complete.call_count == 1

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


class TestAdaptive413Trimming:
    """413 Payload Too Large triggers adaptive context halving and retry."""

    def _make_413(self):
        return httpx.HTTPStatusError(
            "413 Payload Too Large",
            request=MagicMock(),
            response=MagicMock(status_code=413),
        )

    def test_413_triggers_context_halving_then_succeeds(self):
        provider = make_mock_provider("groq", max_tokens=100)
        provider.complete.side_effect = [
            self._make_413(),
            make_response("groq"),
        ]
        provider.is_retryable_error.return_value = False

        long_code = "x" * 5000
        request = LLMRequest(
            system_prompt="System.",
            user_message=f"<<<CODE>>>{long_code}<<<END_CODE>>>",
        )

        orch = LLMOrchestrator([provider], max_retries_per_provider=4)
        resp = orch.complete(request)

        assert resp.provider == "groq"
        assert provider.complete.call_count == 2
        # Second call must have a smaller message than the first
        first_msg = provider.complete.call_args_list[0][0][0].user_message
        second_msg = provider.complete.call_args_list[1][0][0].user_message
        assert len(second_msg) <= len(first_msg)

    def test_413_repeated_halving_eventually_fits(self):
        """Verify up to 3 halvings (1.0 → 0.5 → 0.25 → 0.125) before success."""
        provider = make_mock_provider("groq", max_tokens=10_000)
        provider.complete.side_effect = [
            self._make_413(),
            self._make_413(),
            make_response("groq"),
        ]
        provider.is_retryable_error.return_value = False

        long_code = "y" * 200_000
        request = LLMRequest(
            system_prompt="Sys.",
            user_message=f"<<<CODE>>>{long_code}<<<END_CODE>>>",
        )

        orch = LLMOrchestrator([provider], max_retries_per_provider=5)
        resp = orch.complete(request)
        assert resp.provider == "groq"
        assert provider.complete.call_count == 3

    def test_413_exhausted_falls_back_to_next_provider(self):
        """After too many halvings, rotate to the next provider."""
        groq = make_mock_provider("groq", max_tokens=1)
        # Always 413 — context_scale will shrink below 0.12 threshold
        groq.complete.side_effect = self._make_413()
        groq.is_retryable_error.return_value = False

        gemini = make_mock_provider("gemini", max_tokens=900_000)
        gemini.complete.return_value = make_response("gemini")
        gemini.is_retryable_error.return_value = False

        request = LLMRequest(
            system_prompt="S.",
            user_message="<<<CODE>>>" + "z" * 100 + "<<<END_CODE>>>",
        )
        orch = LLMOrchestrator([groq, gemini], max_retries_per_provider=10)
        resp = orch.complete(request)
        assert resp.provider == "gemini"


class TestPacing:
    """Consecutive requests to one provider are spaced by min_request_interval."""

    def _make_provider(self, interval: float) -> MagicMock:
        provider = make_mock_provider("openrouter")
        provider.min_request_interval = interval
        provider.complete.return_value = make_response("openrouter")
        provider.is_retryable_error.return_value = False
        return provider

    def test_first_call_is_not_paced(self):
        provider = self._make_provider(8.0)
        orch = LLMOrchestrator([provider])
        with patch("aegisdiff.llm.orchestrator.time.sleep") as mock_sleep:
            orch.complete(SAMPLE_REQUEST)
        mock_sleep.assert_not_called()

    def test_second_call_within_interval_is_paced(self):
        provider = self._make_provider(8.0)
        orch = LLMOrchestrator([provider])
        orch.complete(SAMPLE_REQUEST)
        with patch("aegisdiff.llm.orchestrator.time.sleep") as mock_sleep:
            orch.complete(SAMPLE_REQUEST)
        assert mock_sleep.call_count == 1
        assert 0 < mock_sleep.call_args[0][0] <= 8.0

    def test_zero_interval_disables_pacing(self):
        provider = self._make_provider(0.0)
        orch = LLMOrchestrator([provider])
        with patch("aegisdiff.llm.orchestrator.time.sleep") as mock_sleep:
            orch.complete(SAMPLE_REQUEST)
            orch.complete(SAMPLE_REQUEST)
        mock_sleep.assert_not_called()

    def test_pacing_is_per_provider(self):
        """Pacing on provider A must not delay a request to provider B."""
        p1 = self._make_provider(8.0)
        p1.complete.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=MagicMock(status_code=429)
        )
        p1.is_retryable_error.return_value = True
        p2 = self._make_provider(8.0)
        orch = LLMOrchestrator([p1, p2])
        with patch("aegisdiff.llm.orchestrator.time.sleep") as mock_sleep:
            resp = orch.complete(SAMPLE_REQUEST)
        assert resp.provider == "openrouter"
        mock_sleep.assert_not_called()


class TestCooldownFrom429:
    """429 cooldown honors Retry-After and benches daily-quota exhaustion."""

    def _make_429(self, headers: dict | None = None, body: str = "") -> httpx.HTTPStatusError:
        request = httpx.Request("POST", "https://api.example.com/v1/chat/completions")
        response = httpx.Response(429, headers=headers, text=body, request=request)
        return httpx.HTTPStatusError("429", request=request, response=response)

    def test_default_cooldown_without_retry_after(self):
        from aegisdiff.llm.orchestrator import _RATE_LIMIT_COOLDOWN, _cooldown_from_429

        assert _cooldown_from_429(self._make_429()) == _RATE_LIMIT_COOLDOWN

    def test_honors_retry_after_header(self):
        from aegisdiff.llm.orchestrator import _cooldown_from_429

        exc = self._make_429(headers={"retry-after": "7"})
        assert _cooldown_from_429(exc) == 8.0  # header value + 1s margin

    def test_retry_after_is_capped(self):
        from aegisdiff.llm.orchestrator import _RATE_LIMIT_COOLDOWN_MAX, _cooldown_from_429

        exc = self._make_429(headers={"retry-after": "99999"})
        assert _cooldown_from_429(exc) == _RATE_LIMIT_COOLDOWN_MAX

    def test_non_numeric_retry_after_falls_back_to_default(self):
        from aegisdiff.llm.orchestrator import _RATE_LIMIT_COOLDOWN, _cooldown_from_429

        exc = self._make_429(headers={"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"})
        assert _cooldown_from_429(exc) == _RATE_LIMIT_COOLDOWN

    def test_groq_daily_quota_benches_key(self):
        from aegisdiff.llm.orchestrator import _DAILY_QUOTA_COOLDOWN, _cooldown_from_429

        body = (
            "Rate limit reached for model llama-3.3-70b-versatile "
            "on requests per day (RPD): Limit 14400, Used 14400"
        )
        assert _cooldown_from_429(self._make_429(body=body)) == _DAILY_QUOTA_COOLDOWN

    def test_openrouter_daily_quota_benches_key(self):
        from aegisdiff.llm.orchestrator import _DAILY_QUOTA_COOLDOWN, _cooldown_from_429

        body = '{"error": {"message": "Rate limit exceeded: free-models-per-day"}}'
        assert _cooldown_from_429(self._make_429(body=body)) == _DAILY_QUOTA_COOLDOWN

    def test_per_minute_429_not_benched(self):
        from aegisdiff.llm.orchestrator import _RATE_LIMIT_COOLDOWN, _cooldown_from_429

        body = "Rate limit reached on tokens per minute (TPM): Limit 6000, Used 6000"
        assert _cooldown_from_429(self._make_429(body=body)) == _RATE_LIMIT_COOLDOWN

    def test_daily_benched_provider_not_awaited(self):
        """A daily-benched key must not trigger the all-cooled-down wait loop."""
        request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
        response = httpx.Response(
            429,
            text="rate limit reached on requests per day (RPD)",
            request=request,
        )
        provider = make_mock_provider("groq")
        provider.is_retryable_error.return_value = True
        provider.complete.side_effect = httpx.HTTPStatusError(
            "429", request=request, response=response
        )

        orch = LLMOrchestrator([provider], max_retries_per_provider=3)
        with patch("aegisdiff.llm.orchestrator.time.sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="All LLM providers exhausted"):
                orch.complete(SAMPLE_REQUEST)

        # Tried once, then benched — no pointless 65s wait cycles
        assert provider.complete.call_count == 1
        mock_sleep.assert_not_called()


class TestInitialization:
    def test_empty_providers_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            LLMOrchestrator([])
