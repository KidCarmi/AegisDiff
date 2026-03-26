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

from ..triage.verdicts import Severity, Verdict, VerdictType

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


def format_summary_comment(
    verdict: Verdict,
    pr_number: int,
    sha: str,
    inline_posted: bool = False,
) -> str:
    """
    Top-level PR comment: verdict table + summary.

    When `inline_posted=True` the evidence/remediation are omitted here
    (they live in the inline comment). When False (fallback), the full
    detail is included so nothing is lost.
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
{inline_note}{detail_section}
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
