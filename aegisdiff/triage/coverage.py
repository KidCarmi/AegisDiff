"""
Coverage metadata for Large PR Risk Triage Mode.

A small, serialisable structure that summarises what was analyzed vs.
skipped during a scan. Phase 1 only constructs and unit-tests this; later
phases will attach it to the PR summary comment and the dashboard ingest
payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .budget import SelectionResult
from .large_pr import LargePRDetection


@dataclass
class CoverageMetadata:
    mode: str  # "normal" | "large_pr"
    files_changed: int
    files_analyzed: int
    files_skipped: int
    skip_reasons: Dict[str, int] = field(default_factory=dict)
    budget_exhausted: bool = False
    large_pr_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "files_changed": self.files_changed,
            "files_analyzed": self.files_analyzed,
            "files_skipped": self.files_skipped,
            "skip_reasons": dict(self.skip_reasons),
            "budget_exhausted": self.budget_exhausted,
            "large_pr_reasons": list(self.large_pr_reasons),
        }


def build_coverage_metadata(
    detection: LargePRDetection,
    selection: SelectionResult,
    files_changed: Optional[int] = None,
) -> CoverageMetadata:
    """Build a ``CoverageMetadata`` from detection + selection results.

    ``files_changed`` defaults to ``len(selected) + len(skipped)`` when not
    explicitly provided, which matches the case where every changed file
    was classified.
    """
    analyzed = len(selection.selected)
    skipped = len(selection.skipped)
    total = files_changed if files_changed is not None else analyzed + skipped
    return CoverageMetadata(
        mode="large_pr" if detection.is_large_pr else "normal",
        files_changed=total,
        files_analyzed=analyzed,
        files_skipped=skipped,
        skip_reasons=dict(selection.skip_reason_counts),
        budget_exhausted=selection.budget_exhausted,
        large_pr_reasons=list(detection.reasons),
    )
