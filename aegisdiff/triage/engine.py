"""Core triage engine: diff → context → LLM → Verdict."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from ..code_context.extractor import CodeContextExtractor
from ..llm.orchestrator import LLMOrchestrator
from ..llm.providers.base import LLMRequest
from .prompts import APPSEC_SYSTEM_PROMPT, build_user_message
from .verdicts import Verdict, parse_verdict

logger = logging.getLogger(__name__)


class TriageEngine:
    """
    Orchestrates the full analysis pipeline:
    raw diff → CodeContext → LLMRequest → Verdict

    Args:
        orchestrator: Configured LLMOrchestrator with at least one provider.
        repo_root: Path to the repository root (for reading source files).
        language: Primary language hint for AST parsing (default: "python").
    """

    def __init__(
        self,
        orchestrator: LLMOrchestrator,
        repo_root: Path,
        language: str = "python",
    ) -> None:
        self._orchestrator = orchestrator
        self._repo_root = repo_root
        self._language = language

    def analyze_diff(self, raw_diff: str) -> Verdict:
        """
        Analyze a unified diff and return a security verdict.

        Returns:
            Verdict — always returns a value, never raises.
            On engine error: Verdict.error(...) with details.
        """
        t0 = time.monotonic()

        if not raw_diff or not raw_diff.strip():
            logger.info("Empty diff — skipping LLM call")
            return Verdict.no_op()

        try:
            extractor = CodeContextExtractor(self._repo_root, self._language)
            context = extractor.extract_from_diff(raw_diff)

            if not context.raw_diff_snippet.strip():
                logger.info("No relevant lines in diff — skipping LLM call")
                return Verdict.no_op()

            request = LLMRequest(
                system_prompt=APPSEC_SYSTEM_PROMPT,
                user_message=build_user_message(context),
                max_tokens=1024,
                temperature=0.05,  # Near-deterministic for security verdicts
            )

            response = self._orchestrator.complete(request)
            verdict = parse_verdict(response.content, provider=response.provider)

            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.info(
                "Verdict: %s [%s] confidence=%.2f via %s in %dms",
                verdict.verdict,
                verdict.severity,
                verdict.confidence,
                response.provider,
                elapsed_ms,
            )
            return verdict

        except RuntimeError as e:
            # All providers exhausted
            logger.error("All LLM providers failed: %s", e)
            return Verdict.error(str(e))
        except Exception as e:
            logger.exception("Unexpected error in triage engine")
            return Verdict.error(f"Unexpected error: {e}")
