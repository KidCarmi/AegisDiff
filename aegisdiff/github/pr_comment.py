"""
Verdict → GitHub PR comment formatter.

Two comment modes:
- Top-level summary: verdict/severity/CWE table + summary text. Always posted.
- Inline comment: evidence quote + remediation, posted on the vulnerable line
  when a sink line number is known. If inline posting fails (line not in diff),
  the evidence is appended to the top-level comment as a fallback.

The HTML marker <!-- aegisdiff-report --> is used for idempotent upsert.
"""

from __future__ import annotations

from typing import List, Optional

from ..triage.coverage import CoverageMetadata
from ..triage.verdicts import Severity, Verdict, VerdictType

# Mandated wording for the Large PR Risk Triage Mode summary block. Phase 2
# tests assert this string appears verbatim in the summary comment.
LARGE_PR_BANNER = (
    "AegisDiff ran in Large PR Risk Triage Mode. "
    "This PR exceeded the full-scan budget, so AegisDiff prioritized "
    "security-relevant changed hunks instead of scanning every line."
)

# HTML marker used to find and update the comment on subsequent pushes
COMMENT_MARKER = "<!-- aegisdiff-report -->"

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
    Severity.NA: "✅",
}

VERDICT_EMOJI = {
    VerdictType.TRUE_POSITIVE: "🚨",
    VerdictType.FALSE_POSITIVE: "✅",
    VerdictType.NEEDS_REVIEW: "⚠️",
    VerdictType.ERROR: "❌",
}


def format_large_pr_summary(
    coverage: CoverageMetadata,
    llm_calls_used: int,
    llm_calls_total: int,
    inline_findings_shown: Optional[int] = None,
    inline_findings_overflow: Optional[int] = None,
    chunks_errored: Optional[int] = None,
) -> str:
    """Build the Large PR Risk Triage Mode block for the summary comment.

    Includes the mandated Phase 2 banner sentence verbatim, followed by a
    coverage table and budget usage. Returns an empty string when
    ``coverage`` is ``None`` so callers can append unconditionally.

    ``chunks_errored`` (F4) — when set and >0, renders a "Chunks errored"
    line so reviewers can see whether the scan's quality degraded from
    LLM JSON-parse failures, all-providers-exhausted events, or
    unexpected engine errors. The line is omitted on clean runs to keep
    happy-path summaries quiet.
    """
    if coverage is None:
        return ""

    skip_lines: List[str] = []
    for reason in sorted(coverage.skip_reasons.keys()):
        skip_lines.append(f"  - `{reason}`: {coverage.skip_reasons[reason]}")
    skip_block = "\n".join(skip_lines) if skip_lines else "  - (none)"

    reasons = "; ".join(coverage.large_pr_reasons) if coverage.large_pr_reasons else "(unknown)"
    budget_state = "yes" if coverage.budget_exhausted else "no"

    inline_line = ""
    if inline_findings_shown is not None:
        overflow = inline_findings_overflow or 0
        inline_line = f"\n- Inline comments posted: **{inline_findings_shown}**" + (
            f" (+{overflow} additional findings in summary only)" if overflow > 0 else ""
        )

    errored_line = ""
    if chunks_errored is not None and chunks_errored > 0:
        errored_line = f"\n- Chunks errored: **{chunks_errored} / {llm_calls_used}** ⚠️"

    return f"""
<details><summary>📦 Large PR Risk Triage Mode coverage</summary>

> {LARGE_PR_BANNER}

- Files changed: **{coverage.files_changed}**
- Files analyzed: **{coverage.files_analyzed}**
- Files skipped: **{coverage.files_skipped}**
- Skip reasons:
{skip_block}
- LLM calls used: **{llm_calls_used} / {llm_calls_total}**{errored_line}
- Budget exhausted: **{budget_state}**
- Large PR triggers: {reasons}{inline_line}

</details>
"""


def format_summary_comment(
    verdict: Verdict,
    pr_number: int,
    sha: str,
    inline_posted: bool = False,
    total_findings: Optional[int] = None,
    large_pr_summary: Optional[str] = None,
) -> str:
    """
    Top-level PR comment: verdict table + summary.

    When `inline_posted=True` the evidence/remediation are omitted here
    (they live in the inline comment). When False (fallback), the full
    detail is included so nothing is lost.

    `total_findings` — when >1, adds a note about the total number of
    true positive findings across all chunks (chunked analysis mode).
    """

    sev_icon = SEVERITY_EMOJI.get(verdict.severity, "")
    vrd_icon = VERDICT_EMOJI.get(verdict.verdict, "")
    confidence_pct = f"{verdict.confidence * 100:.0f}%"

    sanitizer_row = (
        f"| Sanitizer Found | ✅ {verdict.sanitizer_description} |"
        if verdict.sanitizer_found
        else "| Sanitizer Found | ❌ None detected |"
    )

    inline_note = ""
    detail_section = ""

    if inline_posted and verdict.file_path and verdict.line_number:
        inline_note = (
            f"\n> 📍 Inline comment posted on `{verdict.file_path}` line {verdict.line_number}.\n"
        )
    else:
        # Fallback: include full evidence + remediation in the top-level comment
        attack_section = (
            f"\n**Attack Vector:** `{verdict.attack_vector}`" if verdict.attack_vector else ""
        )
        remediation_section = (
            f"\n**Remediation:** {verdict.remediation}" if verdict.remediation else ""
        )
        fp_section = (
            f"\n**Why Not Exploitable:** {verdict.false_positive_reason}"
            if verdict.false_positive_reason
            else ""
        )
        evidence_block = (
            f"\n<details><summary>Evidence</summary>\n\n```\n{verdict.evidence}\n```\n</details>"
            if verdict.evidence
            else ""
        )
        detail_section = f"{attack_section}{remediation_section}{fp_section}{evidence_block}"

    findings_note = (
        f"\n> ⚠️ **{total_findings} true positive findings** across this PR "
        f"(showing highest severity). Inline comments mark each vulnerable line.\n"
        if total_findings and total_findings > 1
        else ""
    )

    large_pr_block = large_pr_summary or ""

    return f"""{COMMENT_MARKER}
## {vrd_icon} AegisDiff Security Triage — `{verdict.verdict.value}`

| Field | Value |
|---|---|
| Verdict | **{verdict.verdict.value}** |
| Severity | {sev_icon} **{verdict.severity.value}** |
| CWE | `{verdict.cwe_id}` |
| Confidence | {confidence_pct} |
| Analyzed by | `{verdict.provider}` |
{sanitizer_row}

**{verdict.title}**

{verdict.summary}
{findings_note}{inline_note}{detail_section}{large_pr_block}
<sub>Commit `{sha}` · PR #{pr_number} · Powered by [AegisDiff](https://github.com/KidCarmi/AegisDiff)</sub>
"""


def format_inline_comment(verdict: Verdict) -> str:
    """
    Inline PR review comment body: evidence quote + remediation.

    Rendered on the exact vulnerable line in the diff.
    """
    sev_icon = SEVERITY_EMOJI.get(verdict.severity, "")
    vrd_icon = VERDICT_EMOJI.get(verdict.verdict, "")

    parts = [f"**{vrd_icon} AegisDiff — {verdict.title}**"]

    if verdict.cwe_id and verdict.cwe_id != "N/A":
        parts.append(f"`{verdict.cwe_id}` · {sev_icon} {verdict.severity.value}")

    if verdict.evidence:
        parts.append(f"\n```\n{verdict.evidence}\n```")

    if verdict.attack_vector:
        parts.append(f"**Attack vector:** `{verdict.attack_vector}`")

    if verdict.remediation:
        parts.append(f"**Remediation:** {verdict.remediation}")

    if verdict.false_positive_reason:
        parts.append(f"**Why not exploitable:** {verdict.false_positive_reason}")

    return "\n\n".join(parts)


def format_verdict_comment(verdict: Verdict, pr_number: int, sha: str) -> str:
    """
    Full standalone PR comment (legacy / no-inline-comment path).

    Kept for backwards compatibility — used when no line number is available.
    """
    return format_summary_comment(verdict, pr_number, sha, inline_posted=False)
