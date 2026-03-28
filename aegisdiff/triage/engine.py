"""Core triage engine: diff → context → LLM → Verdict."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..code_context.extractor import CodeContextExtractor
from ..llm.orchestrator import LLMOrchestrator
from ..llm.providers.base import LLMRequest
from .prompts import APPSEC_SYSTEM_PROMPT, build_user_message
from .verdicts import Severity, Verdict, VerdictType, parse_verdict

logger = logging.getLogger(__name__)

# Verdict/severity rank used for aggregation (higher = worse / more actionable)
_VERDICT_RANK = {
    VerdictType.TRUE_POSITIVE: 3,
    VerdictType.NEEDS_REVIEW: 2,
    VerdictType.ERROR: 1,
    VerdictType.FALSE_POSITIVE: 0,
}
_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.NA: 0,
}


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
        file_cache: Optional[Dict[str, str]] = None,
        file_fetcher: Optional[callable] = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._repo_root = repo_root
        self._language = language
        self._file_cache = file_cache or {}
        self._file_fetcher = file_fetcher

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
            extractor = CodeContextExtractor(
                self._repo_root, self._language, self._file_cache, self._file_fetcher
            )
            context = extractor.extract_from_diff(raw_diff)

            if not context.raw_diff_snippet.strip():
                logger.info("No relevant lines in diff — skipping LLM call")
                return Verdict.no_op()

            # ── aegisdiff-ignore suppression ─────────────────────────────
            # If every detected sink is suppressed by an inline comment,
            # short-circuit with FALSE_POSITIVE — no LLM call needed.
            if context.paths:
                suppressed_sinks = [p.sink for p in context.paths if p.sink.suppressed]
                all_suppressed = len(suppressed_sinks) == len(context.paths)
                if all_suppressed:
                    primary = suppressed_sinks[0]
                    reason = primary.ignore_reason or "aegisdiff-ignore comment"
                    cwe_tag = f" ({primary.ignore_cwe})" if primary.ignore_cwe else ""
                    logger.info(
                        "All sinks suppressed by aegisdiff-ignore%s — skipping LLM call", cwe_tag
                    )
                    v = Verdict.suppressed(
                        cwe_id=primary.ignore_cwe or "N/A",
                        reason=reason,
                        file_path=primary.file_path,
                        line_number=primary.line_number,
                    )
                    return v

            request = LLMRequest(
                system_prompt=APPSEC_SYSTEM_PROMPT,
                user_message=build_user_message(context),
                max_tokens=1024,
                temperature=0.05,  # Near-deterministic for security verdicts
            )

            response = self._orchestrator.complete(request)
            verdict = parse_verdict(response.content, provider=response.provider)

            # Annotate with primary sink location for inline PR comment targeting.
            # Only set when a real sink was detected (line_number > 0).
            if context.paths:
                primary_sink = context.paths[0].sink
                if primary_sink.line_number > 0:
                    verdict.line_number = primary_sink.line_number
                    verdict.file_path = primary_sink.file_path

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

    def analyze_diff_chunked(self, raw_diff: str) -> List[Verdict]:
        """
        Analyze each changed file independently and return one Verdict per file.

        Use this for large diffs (>100 lines) to avoid context-window pressure
        and to get per-file findings with accurate line numbers.

        Returns a non-empty list — at minimum [Verdict.no_op()] for empty diffs.
        The caller should use aggregate_verdicts() to select the primary result.
        """
        chunks = self._split_diff_by_file(raw_diff)
        if not chunks:
            logger.info("No per-file chunks found — falling back to whole-diff analysis")
            return [self.analyze_diff(raw_diff)]

        verdicts: List[Verdict] = []
        for file_path, chunk in chunks:
            logger.info("Analyzing chunk: %s (%d lines)", file_path, chunk.count("\n"))
            verdict = self.analyze_diff(chunk)
            verdicts.append(verdict)

        # Drop no-op FALSE_POSITIVEs when more actionable findings exist
        actionable = [v for v in verdicts if v.verdict != VerdictType.FALSE_POSITIVE]
        if actionable:
            logger.info(
                "Chunked analysis: %d file(s), %d actionable finding(s)",
                len(chunks),
                len(actionable),
            )
            return verdicts  # Return all so caller can decide what to ingest

        return verdicts

    @staticmethod
    def aggregate_verdicts(verdicts: List[Verdict]) -> Verdict:
        """
        Select the primary verdict from a chunked analysis.

        Ranks by: verdict type (TRUE_POSITIVE > NEEDS_REVIEW > ERROR > FALSE_POSITIVE),
        then severity (CRITICAL → NA), then confidence.
        """
        if not verdicts:
            return Verdict.no_op()

        def _rank(v: Verdict) -> Tuple[int, int, float]:
            return (
                _VERDICT_RANK.get(v.verdict, 0),
                _SEVERITY_RANK.get(v.severity, 0),
                v.confidence,
            )

        return max(verdicts, key=_rank)

    @staticmethod
    def _split_diff_by_file(raw_diff: str) -> List[Tuple[str, str]]:
        """
        Split a unified diff into per-file chunks.

        Each chunk starts with the `diff --git` header and contains all hunks
        for that file. Returns a list of (file_path, chunk_text) tuples.
        """
        chunks: List[Tuple[str, str]] = []
        current_file: str | None = None
        current_lines: List[str] = []

        for line in raw_diff.splitlines(keepends=True):
            if line.startswith("diff --git "):
                if current_file is not None and current_lines:
                    chunks.append((current_file, "".join(current_lines)))
                # Extract the b/ path: "diff --git a/foo/bar.py b/foo/bar.py"
                m = re.search(r" b/(.+)$", line.rstrip())
                current_file = m.group(1) if m else line.split()[-1].lstrip("b/")
                current_lines = [line]
            elif current_file is not None:
                current_lines.append(line)

        if current_file is not None and current_lines:
            chunks.append((current_file, "".join(current_lines)))

        return chunks
