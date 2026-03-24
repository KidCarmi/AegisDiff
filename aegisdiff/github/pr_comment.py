"""
Verdict → GitHub PR comment formatter.

Uses a clean Markdown table with severity icons.
The HTML marker <!-- aegisdiff-report --> is used for idempotent upsert.
Evidence (code quotes) is placed in a <details> block to avoid wall-of-text.
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


def format_verdict_comment(verdict: Verdict, pr_number: int, sha: str) -> str:
    """Render a Verdict as a GitHub-flavored Markdown PR comment."""
    sev_icon = SEVERITY_EMOJI.get(verdict.severity, "")
    vrd_icon = VERDICT_EMOJI.get(verdict.verdict, "")
    confidence_pct = f"{verdict.confidence * 100:.0f}%"

    sanitizer_row = (
        f"| Sanitizer Found | ✅ {verdict.sanitizer_description} |"
        if verdict.sanitizer_found
        else "| Sanitizer Found | ❌ None detected |"
    )

    attack_section = (
        f"\n**Attack Vector:** `{verdict.attack_vector}`"
        if verdict.attack_vector
        else ""
    )
    remediation_section = (
        f"\n**Remediation:** {verdict.remediation}"
        if verdict.remediation
        else ""
    )
    fp_section = (
        f"\n**Why Not Exploitable:** {verdict.false_positive_reason}"
        if verdict.false_positive_reason
        else ""
    )
    evidence_block = (
        f'\n<details><summary>Evidence</summary>\n\n```\n{verdict.evidence}\n```\n</details>'
        if verdict.evidence
        else ""
    )

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
{attack_section}
{remediation_section}
{fp_section}
{evidence_block}

<sub>Commit `{sha}` · PR #{pr_number} · Powered by [AegisDiff](https://github.com/KidCarmi/AegisDiff)</sub>
"""
