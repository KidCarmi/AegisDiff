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
from .budget import (
    SKIP_REASON_BUDGET_EXHAUSTED_LLM_CALLS,
    SelectionResult,
    select_files_for_analysis,
)
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


def _trim_user_message_to_byte_budget(user_message: str, max_bytes: int) -> Tuple[str, bool]:
    """Trim a Large PR Mode ``LLMRequest.user_message`` to fit ``max_bytes``.

    Hard contract: the returned string's UTF-8 byte length is *always*
    ``<= max_bytes`` (when ``max_bytes > 0``). The function never returns
    a message larger than the cap, even in pathological cases.

    The user_message produced by ``build_user_message`` has three regions:

      1. **Header** — DIFF SUMMARY, CHANGED FILES, DATA FLOW PATH list.
         Ends just before the ``<<<CODE>>>`` marker.
      2. **Code block** — imported definitions + raw diff snippet +
         surrounding context. Lives between ``<<<CODE>>>`` and
         ``<<<END_CODE>>>``. This is the only region that may be
         shortened first — it's the part that scales with the diff.
      3. **Trailing instruction** — everything after ``<<<END_CODE>>>``,
         including the JSON-schema reminder. Critical for verdict
         formatting and preserved as long as the cap allows.

    Trim priority (most → least preserved):

        trailing schema instruction (region 3 tail-end)
            > header (region 1)
            > "[code context trimmed]" marker
            > code block (region 2)

    Strategy:
      * Normal case (``head + tail + marker <= max_bytes``): keep both
        outer regions verbatim and byte-truncate the inner code on a
        UTF-8-safe boundary.
      * Outer regions too big for the marker: drop the marker and try to
        keep ``head + tail``.
      * ``head + tail`` still too big but ``tail <= max_bytes``: keep
        the tail intact (schema instruction is sacred), trim the head.
      * Even the tail alone exceeds the cap: keep the *end* of the tail
        (where the schema instruction lives), drop everything else.

    A final byte-level safety net always re-clips the result so the
    contract holds regardless of UTF-8 boundary rounding.

    Returns ``(trimmed, was_trimmed)``. Original is returned unchanged
    when it already fits.
    """
    if max_bytes <= 0:
        return user_message, False
    if len(user_message.encode("utf-8")) <= max_bytes:
        return user_message, False

    code_open = "<<<CODE>>>"
    code_close = "<<<END_CODE>>>"
    open_idx = user_message.find(code_open)
    close_idx = user_message.find(code_close)

    marker = "\n\n... [code context trimmed to fit Large PR prompt budget] ...\n\n"
    marker_bytes = len(marker.encode("utf-8"))

    if open_idx == -1 or close_idx == -1 or close_idx < open_idx:
        # No structural markers — keep head + tail so the trailing
        # schema instruction (likely at the very end) survives.
        encoded = user_message.encode("utf-8")
        budget = max(0, max_bytes - marker_bytes)
        half = budget // 2
        head_bytes_no_marker = encoded[:half]
        tail_bytes_no_marker = encoded[-half:] if half > 0 else b""
        result = (
            head_bytes_no_marker.decode("utf-8", errors="ignore")
            + marker
            + tail_bytes_no_marker.decode("utf-8", errors="ignore")
        )
    else:
        # Region 1 ends at the open marker (inclusive).
        head = user_message[: open_idx + len(code_open)]
        # Region 3 starts at the close marker (inclusive) and runs to EOF.
        tail = user_message[close_idx:]
        head_b = len(head.encode("utf-8"))
        tail_b = len(tail.encode("utf-8"))

        available_for_code = max_bytes - head_b - tail_b - marker_bytes

        if available_for_code > 0:
            # Normal case — only the inner code block is shortened.
            code_section = user_message[open_idx + len(code_open) : close_idx]
            code_encoded = code_section.encode("utf-8")
            if len(code_encoded) <= available_for_code:
                result = head + code_section + marker + tail
            else:
                truncated_code = code_encoded[:available_for_code].decode("utf-8", errors="ignore")
                result = head + truncated_code + marker + tail
        elif head_b + tail_b <= max_bytes:
            # Drop the marker to make room; keep both outer regions.
            result = head + tail
        elif tail_b <= max_bytes:
            # Tail (with the schema instruction) is sacred — preserve it
            # whole and trim the head from its end. Losing the trailing
            # ``<<<CODE>>>`` marker is fine; the model still has the
            # schema in the tail.
            head_budget = max_bytes - tail_b
            if head_budget > 0:
                head_truncated = head.encode("utf-8")[:head_budget].decode("utf-8", errors="ignore")
                result = head_truncated + tail
            else:
                result = tail
        else:
            # Pathological: even the tail alone exceeds the cap. Keep the
            # *end* of the tail so the schema instruction still survives,
            # and drop everything else.
            result = tail.encode("utf-8")[-max_bytes:].decode("utf-8", errors="ignore")

    # Hard cap enforcement — final safety net. Any UTF-8 rounding or
    # corner case in the structured trimming above is clipped to the
    # contract. We trim from the start so the trailing schema instruction
    # (the highest-priority content) survives even at the absolute floor.
    encoded = result.encode("utf-8")
    if len(encoded) > max_bytes:
        result = encoded[-max_bytes:].decode("utf-8", errors="ignore")

    return result, True


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

    def analyze_diff(
        self,
        raw_diff: str,
        large_pr_mode: bool = False,
        max_user_message_bytes: Optional[int] = None,
    ) -> Verdict:
        """
        Analyze a unified diff and return a security verdict.

        Args:
            raw_diff: A unified diff fragment (typically a single file or hunk).
            large_pr_mode: When True, the Large PR Risk Triage Mode addendum
                is appended to the system prompt so the model only flags
                vulnerabilities actually introduced or exposed by the PR.
                The verdict JSON schema is unchanged.
            max_user_message_bytes: When set (Large PR Mode only) the final
                ``LLMRequest.user_message`` is trimmed to fit this byte
                budget *before* the LLM call. The system prompt is never
                trimmed. ``None`` (default) preserves the legacy small-PR
                behaviour: no user_message-level trimming.

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

            user_message = build_user_message(context)
            # Large PR Mode only: cap the final user_message size. The
            # system prompt is intentionally NOT touched — calibration
            # rules, schema, and the prompt-injection defense must remain
            # intact regardless of how big the diff context grew.
            if large_pr_mode and max_user_message_bytes:
                user_message, was_trimmed = _trim_user_message_to_byte_budget(
                    user_message, max_user_message_bytes
                )
                if was_trimmed:
                    logger.warning(
                        "Large PR Mode: user_message exceeded %d bytes — "
                        "code context trimmed (header + schema preserved)",
                        max_user_message_bytes,
                    )

            request = LLMRequest(
                system_prompt=system_prompt,
                user_message=user_message,
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
          5. ``CoverageMetadata`` is finalised *after* the loop from the
             set of files that actually consumed at least one LLM call.
             Selected files that the LLM-call budget cut off are reported
             under the ``budget_exhausted_llm_calls`` skip-reason bucket,
             so the summary cannot overstate scan coverage.

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
        # Provisional coverage from the *planned* selection. Re-finalised
        # after the loop using the set of files that actually got LLM
        # calls — see the post-loop recompute below.
        coverage = build_coverage_metadata(detection, selection, files_changed=files_changed)

        verdicts: List[Verdict] = []
        calls_used = 0
        chunks_trimmed = 0
        budget_exhausted_calls = False
        max_chunk_bytes = max(1, int(budgets.max_chunk_bytes))
        # Set of file paths that actually consumed >=1 LLM call. Drives
        # the post-loop coverage recompute so we never claim a file was
        # analyzed when the LLM-call budget cut us off first.
        analyzed_paths: set = set()

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
                verdict = self.analyze_diff(
                    trimmed_hunk,
                    large_pr_mode=True,
                    max_user_message_bytes=budgets.max_user_message_bytes,
                )
                verdicts.append(verdict)
                calls_used += 1
                analyzed_paths.add(cls.path)

            if budget_exhausted_calls:
                break

        # ── Recompute coverage from executed work, not planned selection ──
        # A file counts as "analyzed" only if at least one of its chunks
        # actually consumed an LLM call. Selected files we never reached
        # (LLM-call budget exhausted, or empty file_diff edge case) are
        # demoted to ``skipped`` under the ``budget_exhausted_llm_calls``
        # bucket. files_changed is preserved from the original parse so
        # analyzed + skipped reconciles back to it.
        unreached = [c for c in selection.selected if c.path not in analyzed_paths]
        unreached_count = len(unreached)

        coverage.files_analyzed = len(analyzed_paths)
        coverage.files_skipped = len(selection.skipped) + unreached_count
        if unreached_count > 0:
            coverage.skip_reasons[SKIP_REASON_BUDGET_EXHAUSTED_LLM_CALLS] = (
                coverage.skip_reasons.get(SKIP_REASON_BUDGET_EXHAUSTED_LLM_CALLS, 0)
                + unreached_count
            )

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
