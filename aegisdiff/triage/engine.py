"""Core triage engine: diff → context → LLM → Verdict."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..code_context.extractor import CodeContextExtractor
from ..llm.orchestrator import LLMOrchestrator
from ..llm.providers.base import LLMRequest
from .budget import SelectionResult, select_files_for_analysis
from .coverage import CoverageMetadata, build_coverage_metadata
from .file_classifier import classify_files
from .large_pr import LargePRDetection
from .prompts import APPSEC_SYSTEM_PROMPT, LARGE_PR_PROMPT_ADDENDUM, build_user_message
from .verdicts import SEVERITY_RANK, Verdict, VerdictType, parse_verdict

logger = logging.getLogger(__name__)

# Max changed lines per sub-chunk sent to the LLM.
# Keeps each request well within provider context limits while
# still covering a meaningful amount of code per analysis call.
_MAX_HUNK_LINES = 150

# Hard cap on total LLM calls per PR to protect daily quota.
# With 3 Groq keys at ~14,400 RPD each, 20 chunks/PR supports
# ~2,100 large-PR scans per day before quota pressure.
_MAX_CHUNKS_PER_PR = 20

# Files matching these patterns carry no production security risk and are
# skipped from LLM analysis to avoid wasting quota + context budget.
_TEST_FILE_PATTERNS = re.compile(
    r"(^|/)(test_[^/]+|[^/]+_test|[^/]+\.test|[^/]+\.spec)\."
    r"(py|js|ts|go|java|rb|cs|php)$"
    r"|/(tests?|spec|__tests__|test_helpers?)/",
    re.IGNORECASE,
)


def _is_test_file(file_path: str) -> bool:
    """Return True if the file is a test/spec file with no prod security risk."""
    return bool(_TEST_FILE_PATTERNS.search(file_path))


# Verdict/severity rank used for aggregation (higher = worse / more actionable)
_VERDICT_RANK = {
    VerdictType.TRUE_POSITIVE: 3,
    VerdictType.NEEDS_REVIEW: 2,
    VerdictType.ERROR: 1,
    VerdictType.FALSE_POSITIVE: 0,
}
# Severity ordering lives in ``verdicts.SEVERITY_RANK`` — single source of
# truth shared with the entrypoints' inline-comment sorter.


def _trim_chunk_to_byte_budget(chunk: str, max_bytes: int) -> Tuple[str, bool]:
    """Trim a single-file diff chunk so its UTF-8 size fits ``max_bytes``.

    Preserves the file header (everything up to and including the first
    ``@@`` line) so the LLM still sees ``diff --git`` / ``--- a/`` / ``+++
    b/`` / ``@@`` metadata and knows what file it's looking at. Body lines
    are added one at a time until the next line would exceed the budget;
    the trim point always falls on a line boundary so we never split a
    UTF-8 codepoint or a half-line.

    Returns ``(trimmed_chunk, was_trimmed)``. When the chunk already fits,
    the original string is returned unchanged.

    Edge case: if even the header alone exceeds ``max_bytes``, fall back
    to a UTF-8-safe byte truncation of the whole chunk so we still send
    *something* security-relevant rather than an empty prompt.
    """
    if max_bytes <= 0:
        return chunk, False
    encoded = chunk.encode("utf-8")
    if len(encoded) <= max_bytes:
        return chunk, False

    lines = chunk.splitlines(keepends=True)
    header_end = 0
    for i, line in enumerate(lines):
        if line.startswith("@@"):
            header_end = i + 1
            break

    header = "".join(lines[:header_end])
    body = lines[header_end:]

    header_bytes = len(header.encode("utf-8"))
    if header_bytes >= max_bytes:
        # Pathological case — header alone is too big. Fall back to a
        # byte-safe truncation of the whole chunk so the LLM still gets
        # the most security-relevant prefix.
        truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return truncated, True

    out = header
    out_bytes = header_bytes
    for line in body:
        line_bytes = len(line.encode("utf-8"))
        if out_bytes + line_bytes > max_bytes:
            break
        out += line
        out_bytes += line_bytes

    return out, True


@dataclass
class LargePRRunResult:
    """Per-run output of ``analyze_diff_large_pr_mode``.

    The verdicts list and selection mirror the chunked path so callers can
    still aggregate / fan out inline comments, but a Large PR run also
    carries the coverage metadata + LLM-budget tracking that the summary
    comment reports back to reviewers.
    """

    verdicts: List[Verdict] = field(default_factory=list)
    coverage: Optional[CoverageMetadata] = None
    selection: Optional[SelectionResult] = None
    llm_calls_budget_used: int = 0
    llm_calls_budget_total: int = 0
    budget_exhausted: bool = False
    chunks_trimmed: int = 0  # how many sub-chunks were byte-trimmed before LLM


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

    def analyze_diff(self, raw_diff: str, large_pr_mode: bool = False) -> Verdict:
        """
        Analyze a unified diff and return a security verdict.

        Args:
            raw_diff: A unified diff fragment (typically a single file or hunk).
            large_pr_mode: When True, the Large PR Risk Triage Mode addendum
                is appended to the system prompt so the model only flags
                vulnerabilities actually introduced or exposed by the PR.
                The verdict JSON schema is unchanged.

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

            system_prompt = APPSEC_SYSTEM_PROMPT
            if large_pr_mode:
                system_prompt = APPSEC_SYSTEM_PROMPT + LARGE_PR_PROMPT_ADDENDUM

            request = LLMRequest(
                system_prompt=system_prompt,
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
        Analyze a diff at hunk level and return one Verdict per sub-chunk.

        Pipeline:
          1. Split diff into per-file chunks (_split_diff_by_file).
          2. For each file, further split into sub-hunks of ≤ _MAX_HUNK_LINES
             lines (_split_file_diff_into_hunks). This ensures lines 201+ of
             a large changed file are never silently missed.
          3. Skip test files (no prod security risk).
          4. Cap total sub-chunks at _MAX_CHUNKS_PER_PR to protect daily quota.
          5. Analyze each sub-chunk independently.

        Returns a non-empty list — at minimum [Verdict.no_op()] for empty diffs.
        The caller should use aggregate_verdicts() to select the primary result.
        """
        file_chunks = self._split_diff_by_file(raw_diff)
        if not file_chunks:
            logger.info("No per-file chunks found — falling back to whole-diff analysis")
            return [self.analyze_diff(raw_diff)]

        # Expand each file diff into ≤ _MAX_HUNK_LINES sub-chunks
        expanded: List[Tuple[str, str]] = []
        for file_path, file_diff in file_chunks:
            if _is_test_file(file_path):
                # Preserve the entry so the count stays consistent, but mark
                # it so the analysis loop below can skip the LLM call.
                expanded.append((file_path, ""))
                continue
            sub_hunks = self._split_file_diff_into_hunks(file_diff, _MAX_HUNK_LINES)
            for sub in sub_hunks:
                expanded.append((file_path, sub))

        # Quota guard — cap before any LLM calls
        if len(expanded) > _MAX_CHUNKS_PER_PR:
            logger.warning(
                "PR produces %d sub-chunks — capping at %d to protect daily quota",
                len(expanded),
                _MAX_CHUNKS_PER_PR,
            )
            expanded = expanded[:_MAX_CHUNKS_PER_PR]

        verdicts: List[Verdict] = []
        for file_path, chunk in expanded:
            if not chunk:
                logger.info("Skipping test file: %s", file_path)
                verdicts.append(Verdict.no_op())
                continue
            logger.info("Analyzing sub-chunk: %s (%d lines)", file_path, chunk.count("\n"))
            verdict = self.analyze_diff(chunk)
            verdicts.append(verdict)

        actionable = [v for v in verdicts if v.verdict != VerdictType.FALSE_POSITIVE]
        logger.info(
            "Chunked analysis: %d sub-chunk(s) across %d file(s), %d actionable",
            len(expanded),
            len(file_chunks),
            len(actionable),
        )
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
                SEVERITY_RANK.get(v.severity, 0),
                v.confidence,
            )

        return max(verdicts, key=_rank)

    def analyze_diff_large_pr_mode(
        self,
        raw_diff: str,
        detection: LargePRDetection,
    ) -> LargePRRunResult:
        """Run analysis under Large PR Risk Triage Mode.

        The full ``raw_diff`` is NEVER sent to the LLM as a single prompt.
        Instead:
          1. The diff is split per-file using the existing
             ``_split_diff_by_file`` helper (no API calls).
          2. Files are classified + risk-scored (Phase 1 helpers) and
             selected within ``budgets.max_files_analyzed``.
          3. Each selected file is split into sub-chunks of
             ``max_added_lines_per_chunk`` lines via the existing
             ``_split_file_diff_into_hunks`` helper, capped at
             ``max_chunks_per_file`` per file.
          4. Total LLM calls are capped at ``max_llm_calls_per_pr``; if the
             budget is exhausted partway through, the run continues with
             whatever findings it has — it never fails analysis.
          5. ``CoverageMetadata`` is built from the selection result so the
             summary comment can report what was scanned vs. skipped.

        SKIP files (docs / generated / assets / minified) and
        DEPENDENCY_ONLY files (lockfiles) are excluded from LLM analysis
        entirely. DEPRIORITIZE files (tests) are only analyzed if budget
        remains after high-risk files.
        """
        budgets = detection.budgets
        max_llm_calls = max(0, int(budgets.max_llm_calls_per_pr))

        file_chunks = self._split_diff_by_file(raw_diff)
        files_changed = len(file_chunks)

        # Build the file→diff map and classification list in stable input order.
        diff_by_path: Dict[str, str] = {path: diff for path, diff in file_chunks}
        classifications = classify_files(list(diff_by_path.keys()))
        selection = select_files_for_analysis(classifications, budgets)
        coverage = build_coverage_metadata(detection, selection, files_changed=files_changed)

        verdicts: List[Verdict] = []
        calls_used = 0
        chunks_trimmed = 0
        budget_exhausted_calls = False
        max_chunk_bytes = max(1, int(budgets.max_chunk_bytes))

        for cls in selection.selected:
            if calls_used >= max_llm_calls:
                budget_exhausted_calls = True
                logger.warning(
                    "Large PR Mode: LLM call budget exhausted after %d call(s) — "
                    "skipping remaining selected files",
                    max_llm_calls,
                )
                break

            file_diff = diff_by_path.get(cls.path, "")
            if not file_diff.strip():
                continue

            sub_hunks = self._split_file_diff_into_hunks(
                file_diff, max_hunk_lines=budgets.max_added_lines_per_chunk
            )
            # Per-file chunk cap — protects budget on huge single files.
            sub_hunks = sub_hunks[: max(1, int(budgets.max_chunks_per_file))]

            for idx, hunk in enumerate(sub_hunks, start=1):
                if calls_used >= max_llm_calls:
                    budget_exhausted_calls = True
                    logger.warning(
                        "Large PR Mode: LLM call budget exhausted mid-file (%s)",
                        cls.path,
                    )
                    break
                trimmed_hunk, was_trimmed = _trim_chunk_to_byte_budget(hunk, max_chunk_bytes)
                if was_trimmed:
                    chunks_trimmed += 1
                    logger.warning(
                        "Large PR Mode: chunk for %s exceeded %d bytes — trimmed",
                        cls.path,
                        max_chunk_bytes,
                    )
                logger.info(
                    "Large PR Mode: analyzing %s (risk=%d, hunk %d/%d)",
                    cls.path,
                    cls.risk_score,
                    idx,
                    len(sub_hunks),
                )
                verdict = self.analyze_diff(trimmed_hunk, large_pr_mode=True)
                verdicts.append(verdict)
                calls_used += 1

            if budget_exhausted_calls:
                break

        # Mark coverage as budget-exhausted if either selection or LLM-call
        # budget was hit during this run.
        coverage_budget_exhausted = coverage.budget_exhausted or budget_exhausted_calls
        coverage.budget_exhausted = coverage_budget_exhausted

        return LargePRRunResult(
            verdicts=verdicts or [Verdict.no_op()],
            coverage=coverage,
            selection=selection,
            llm_calls_budget_used=calls_used,
            llm_calls_budget_total=max_llm_calls,
            budget_exhausted=coverage_budget_exhausted,
            chunks_trimmed=chunks_trimmed,
        )

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

    @staticmethod
    def _split_file_diff_into_hunks(file_diff: str, max_hunk_lines: int = 150) -> List[str]:
        """
        Split a single-file diff into sub-chunks of at most max_hunk_lines lines.

        Each returned string is a self-contained diff fragment: the file header
        (diff --git / index / --- / +++ lines) followed by one or more @@ hunks,
        with the total line count kept under max_hunk_lines.

        This ensures that vulnerabilities deep in a large changed file (e.g. line
        350 of a 500-line change) are not silently missed due to context trimming.
        """
        header_lines: List[str] = []
        hunks: List[List[str]] = []
        current_hunk: List[str] = []
        in_header = True

        for line in file_diff.splitlines(keepends=True):
            if line.startswith("@@"):
                in_header = False
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = [line]
            elif in_header:
                header_lines.append(line)
            else:
                current_hunk.append(line)

        if current_hunk:
            hunks.append(current_hunk)

        if not hunks:
            # No @@ markers — return as-is (binary diff, rename-only, etc.)
            return [file_diff]

        header = "".join(header_lines)
        sub_chunks: List[str] = []
        current_lines: List[str] = []
        current_count = 0

        for hunk in hunks:
            hunk_size = len(hunk)
            if current_lines and current_count + hunk_size > max_hunk_lines:
                sub_chunks.append(header + "".join(current_lines))
                current_lines = []
                current_count = 0
            current_lines.extend(hunk)
            current_count += hunk_size

        if current_lines:
            sub_chunks.append(header + "".join(current_lines))

        return sub_chunks
