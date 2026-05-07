"""
File-selection helper for Large PR Risk Triage Mode.

Given a list of ``FileClassification`` records and a ``LargePRBudgets``
config, produces a deterministic selection of files to analyze, plus a
report of what was skipped and why. No LLM calls, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .file_classifier import Decision, FileClassification
from .large_pr import LargePRBudgets

# Stable skip-reason categories used in counters and coverage metadata.
SKIP_REASON_DOCS = "docs"
SKIP_REASON_GENERATED = "generated"
SKIP_REASON_STATIC_ASSET = "static_asset"
SKIP_REASON_MINIFIED = "minified"
SKIP_REASON_DEPENDENCY_ONLY = "dependency_only"
SKIP_REASON_BUDGET_EXHAUSTED = "budget_exhausted"
SKIP_REASON_DEPRIORITIZED = "deprioritized_no_budget"
SKIP_REASON_OTHER = "other"

# Map a primary classifier reason → canonical skip-reason bucket.
_CLASSIFIER_REASON_TO_BUCKET: Dict[str, str] = {
    "docs": SKIP_REASON_DOCS,
    "generated": SKIP_REASON_GENERATED,
    "static_asset": SKIP_REASON_STATIC_ASSET,
    "minified": SKIP_REASON_MINIFIED,
    "lockfile": SKIP_REASON_DEPENDENCY_ONLY,
}


def _bucket_for_skip(c: FileClassification) -> str:
    """Pick a canonical skip-reason bucket for a SKIP/DEPENDENCY_ONLY file."""
    for r in c.reasons:
        if r in _CLASSIFIER_REASON_TO_BUCKET:
            return _CLASSIFIER_REASON_TO_BUCKET[r]
    if c.decision == Decision.DEPENDENCY_ONLY:
        return SKIP_REASON_DEPENDENCY_ONLY
    return SKIP_REASON_OTHER


@dataclass
class SelectionResult:
    """Outcome of running the budget-aware selector."""

    selected: List[FileClassification] = field(default_factory=list)
    skipped: List[FileClassification] = field(default_factory=list)
    skip_reason_counts: Dict[str, int] = field(default_factory=dict)
    budget_exhausted: bool = False

    def to_dict(self) -> dict:
        return {
            "selected": [c.to_dict() for c in self.selected],
            "skipped": [c.to_dict() for c in self.skipped],
            "skip_reason_counts": dict(self.skip_reason_counts),
            "budget_exhausted": self.budget_exhausted,
        }


def select_files_for_analysis(
    classifications: List[FileClassification],
    budgets: Optional[LargePRBudgets] = None,
) -> SelectionResult:
    """Pick which classified files to send to the LLM, given a budget.

    Selection algorithm (deterministic):
      1. Files marked ``SKIP`` are excluded outright and counted by reason.
      2. Files marked ``DEPENDENCY_ONLY`` are excluded from normal LLM
         analysis (Phase 1 has no dependency-aware path yet) and counted
         under ``dependency_only``.
      3. ``ANALYZE`` files are sorted by ``risk_score`` descending. Ties
         are broken by original input order to keep results stable.
      4. ``DEPRIORITIZE`` files (tests) are appended *after* all analyze
         files, so they only consume budget once real production code is
         covered.
      5. The first ``max_files_analyzed`` of that combined list is selected.
         Any eligible files past that cap are added to ``skipped`` with
         reason ``budget_exhausted`` and ``budget_exhausted`` is set True.
    """
    b = budgets or LargePRBudgets()

    selected: List[FileClassification] = []
    skipped: List[FileClassification] = []
    skip_counts: Dict[str, int] = {}

    analyze_buf: List[tuple] = []  # (rank_key, original_index, classification)
    deprio_buf: List[tuple] = []

    for idx, c in enumerate(classifications):
        if c.decision == Decision.SKIP:
            bucket = _bucket_for_skip(c)
            skip_counts[bucket] = skip_counts.get(bucket, 0) + 1
            skipped.append(c)
            continue
        if c.decision == Decision.DEPENDENCY_ONLY:
            skip_counts[SKIP_REASON_DEPENDENCY_ONLY] = (
                skip_counts.get(SKIP_REASON_DEPENDENCY_ONLY, 0) + 1
            )
            skipped.append(c)
            continue
        if c.decision == Decision.ANALYZE:
            # Sort key: high risk first, then preserve input order.
            analyze_buf.append((-c.risk_score, idx, c))
            continue
        if c.decision == Decision.DEPRIORITIZE:
            deprio_buf.append((-c.risk_score, idx, c))
            continue

    analyze_buf.sort(key=lambda t: (t[0], t[1]))
    deprio_buf.sort(key=lambda t: (t[0], t[1]))

    eligible = [t[2] for t in analyze_buf] + [t[2] for t in deprio_buf]
    cap = max(0, int(b.max_files_analyzed))
    budget_exhausted = len(eligible) > cap

    selected = eligible[:cap]
    overflow = eligible[cap:]
    for c in overflow:
        if c.decision == Decision.DEPRIORITIZE:
            bucket = SKIP_REASON_DEPRIORITIZED
        else:
            bucket = SKIP_REASON_BUDGET_EXHAUSTED
        skip_counts[bucket] = skip_counts.get(bucket, 0) + 1
        skipped.append(c)

    return SelectionResult(
        selected=selected,
        skipped=skipped,
        skip_reason_counts=skip_counts,
        budget_exhausted=budget_exhausted,
    )
