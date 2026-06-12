"""Abstract base classes for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMRequest:
    system_prompt: str
    user_message: str
    max_tokens: int = 2048
    temperature: float = 0.1  # Low temperature = deterministic security analysis


@dataclass
class LLMResponse:
    content: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: float


class LLMProvider(ABC):
    name: str
    model: str
    max_context_tokens: int  # Providers differ: Gemini=900k, Groq/Llama=7000
    # Minimum seconds between consecutive requests to this provider instance.
    # The orchestrator paces calls so chunked scans stay under free-tier
    # per-minute rate limits instead of tripping 429s. 0 = no pacing.
    min_request_interval: float = 0.0

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a request and return the response."""
        ...

    @abstractmethod
    def is_retryable_error(self, exc: Exception) -> bool:
        """Return True if this error warrants a retry (429, timeout, 5xx)."""
        ...
