"""
Large PR detection — Phase 1 of the Large PR Risk Triage Mode.

Pure deterministic helpers. No LLM calls, no network, no I/O. The detector
flags a PR as "large" when any of the configured size thresholds is exceeded
and reports the budgets that downstream phases will use.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class LargePRBudgets:
    """Thresholds + per-PR budgets for Large PR Risk Triage Mode.

    The first three fields are *thresholds*: exceeding any of them switches
    a PR into large-PR mode. The remaining fields are *budgets* that bound
    work performed during a large-PR scan.
    """

    # ── thresholds (any one trips large-PR mode) ──────────────────────────
    changed_files_threshold: int = 25
    added_lines_threshold: int = 1000
    total_diff_bytes_threshold: int = 500_000

    # ── budgets (used by later phases) ────────────────────────────────────
    max_files_analyzed: int = 20
    max_chunks_per_file: int = 5
    max_llm_calls_per_pr: int = 40
    max_inline_comments: int = 10
    max_added_lines_per_chunk: int = 120
    # Hard byte cap on each chunk fed to the LLM in Large PR Mode. Belt-and-
    # braces over ``max_added_lines_per_chunk``: a chunk with many removed
    # lines, long context, or weird metadata can still blow past a context
    # window even when the line count is fine.
    max_chunk_bytes: int = 32_000


@dataclass
class LargePRDetection:
    """Result of evaluating a PR against ``LargePRBudgets`` thresholds."""

    is_large_pr: bool
    reasons: List[str] = field(default_factory=list)
    budgets: LargePRBudgets = field(default_factory=LargePRBudgets)

    def to_dict(self) -> dict:
        return {
            "is_large_pr": self.is_large_pr,
            "reasons": list(self.reasons),
            "budgets": asdict(self.budgets),
        }


def detect_large_pr(
    changed_files: int,
    added_lines: int,
    total_diff_bytes: int,
    budgets: Optional[LargePRBudgets] = None,
) -> LargePRDetection:
    """Return a ``LargePRDetection`` for the given PR size signals.

    A PR is considered large if *any* threshold is exceeded. Reasons are
    reported in a stable order so callers can rely on them in tests.
    """
    b = budgets or LargePRBudgets()
    reasons: List[str] = []

    if changed_files > b.changed_files_threshold:
        reasons.append(f"changed_files={changed_files} > {b.changed_files_threshold}")
    if added_lines > b.added_lines_threshold:
        reasons.append(f"added_lines={added_lines} > {b.added_lines_threshold}")
    if total_diff_bytes > b.total_diff_bytes_threshold:
        reasons.append(f"total_diff_bytes={total_diff_bytes} > {b.total_diff_bytes_threshold}")

    return LargePRDetection(
        is_large_pr=bool(reasons),
        reasons=reasons,
        budgets=b,
    )
