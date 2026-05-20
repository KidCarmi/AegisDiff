"""Verdict data model and JSON parser."""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class VerdictType(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NA = "N/A"


# Shared severity ordering used everywhere we need to rank findings —
# verdict aggregation in TriageEngine, inline-comment sorting in the
# entrypoints, and any future rank-aware caller. Higher = worse / more
# actionable. Single source of truth: do not duplicate this map.
SEVERITY_RANK: dict = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.NA: 0,
}


def severity_rank(severity: Severity) -> int:
    """Return the canonical numeric rank for a ``Severity``.

    Unknown values fall back to ``0`` (lowest priority) — never raises.
    """
    return SEVERITY_RANK.get(severity, 0)


@dataclass
class Verdict:
    verdict: VerdictType
    severity: Severity
    cwe_id: str
    confidence: float
    title: str
    summary: str
    evidence: str
    sanitizer_found: bool
    sanitizer_description: Optional[str]
    attack_vector: Optional[str]
    remediation: Optional[str]
    false_positive_reason: Optional[str]
    provider: str = "unknown"
    # Inline comment targeting — set when AST sink detection resolves a line
    line_number: Optional[int] = None
    file_path: Optional[str] = None

    @classmethod
    def no_op(cls) -> "Verdict":
        """Return a benign verdict for empty or irrelevant diffs."""
        return cls(
            verdict=VerdictType.FALSE_POSITIVE,
            severity=Severity.NA,
            cwe_id="N/A",
            confidence=0.99,
            title="No security-relevant changes detected",
            summary="The diff contains no code changes requiring security analysis.",
            evidence="",
            sanitizer_found=False,
            sanitizer_description=None,
            provider="aegisdiff/static-analysis",
            attack_vector=None,
            remediation=None,
            false_positive_reason="Empty or non-security diff",
        )

    @classmethod
    def suppressed(
        cls,
        cwe_id: str,
        reason: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> "Verdict":
        """Return a FALSE_POSITIVE verdict for an aegisdiff-ignore suppressed sink."""
        title = f"Suppressed by aegisdiff-ignore: {reason}"[:80]
        return cls(
            verdict=VerdictType.FALSE_POSITIVE,
            severity=Severity.NA,
            cwe_id=cwe_id,
            confidence=0.99,
            title=title,
            summary=f"Finding suppressed by inline `aegisdiff-ignore` comment. Reason: {reason}",
            evidence="",
            sanitizer_found=False,
            sanitizer_description=None,
            attack_vector=None,
            remediation=None,
            false_positive_reason=reason,
            provider="aegisdiff/suppress-rule",
            file_path=file_path,
            line_number=line_number,
        )

    @classmethod
    def error(cls, reason: str) -> "Verdict":
        """Return an error verdict when the analysis engine fails."""
        short = reason.strip()[:80] if reason.strip() else "Analysis engine error"
        return cls(
            verdict=VerdictType.ERROR,
            severity=Severity.NA,
            cwe_id="N/A",
            confidence=0.0,
            title=short,
            summary=reason,
            evidence="",
            sanitizer_found=False,
            sanitizer_description=None,
            attack_vector=None,
            remediation=None,
            false_positive_reason=None,
        )


_VALUE_STARTERS = set('"{[-tfn0123456789')


def _looks_like_terminator(text: str, i: int) -> bool:
    """Decide whether ``text[i]`` (a ``"``) plausibly terminates a JSON string.

    Local lookahead is not enough — an unescaped inner quote inside a code
    snippet often happens to be followed by ``,`` (e.g. ``f"echo {x}", shell=...``).
    So we look one structural element further: after ``,`` the next non-space
    must start a new key/value, and after ``:`` we must be inside an object key.
    """
    n = len(text)
    j = i + 1
    while j < n and text[j] in " \t\r\n":
        j += 1
    if j >= n:
        return True
    c = text[j]
    if c in "}]":
        return True
    if c == ":":
        return True  # closing a key — value follows
    if c == ",":
        k = j + 1
        while k < n and text[k] in " \t\r\n":
            k += 1
        if k >= n:
            return True
        # After `,` we must see the start of a key (`"`), an object/array
        # close (trailing comma), or a fresh value. Anything else (a bare
        # identifier, an operator, etc.) means this `"` is a literal inside
        # the previous string, not its terminator.
        return text[k] in _VALUE_STARTERS or text[k] in "}]"
    return False


def _escape_inner_string_quotes(text: str) -> str:
    """Escape literal ``"`` characters that appear inside JSON string values.

    The LLM is asked to quote source code in the ``evidence`` field. When the
    quoted code itself contains ``"`` and the model forgets to escape it, the
    JSON string boundary is broken — ``json.loads`` then fails with
    "Expecting ',' delimiter" at the offending byte.

    This walker scans the text tracking string state. A ``"`` while inside a
    string is treated as a literal (rewritten to ``\\"``) unless what follows
    it is consistent with a real JSON structural transition — see
    ``_looks_like_terminator``. Already-escaped ``\\"`` and other backslash
    escapes pass through untouched. The transform is a no-op on valid JSON.
    """
    out: list[str] = []
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # Pass through any backslash escape verbatim so \" doesn't fool us into
        # thinking the string ended.
        if ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(text[i + 1])
            i += 2
            continue
        if ch != '"':
            out.append(ch)
            i += 1
            continue
        if not in_string:
            in_string = True
            out.append(ch)
            i += 1
            continue
        if _looks_like_terminator(text, i):
            in_string = False
            out.append(ch)
        else:
            out.append('\\"')
        i += 1
    return "".join(out)


def parse_verdict(llm_output: str, provider: str = "unknown") -> Verdict:
    """
    Parse LLM JSON output into a typed Verdict.

    Handles cases where the model wraps the JSON in markdown code fences.
    Falls back to Verdict.error() on parse failure.
    """
    text = llm_output.strip()

    # Strip ```json ... ``` or ``` ... ``` fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first line (```json or ```) and last line (```)
        inner_lines = lines[1:]
        if inner_lines and inner_lines[-1].strip() == "```":
            inner_lines = inner_lines[:-1]
        text = "\n".join(inner_lines).strip()

    # Fix invalid JSON escape sequences the LLM may emit when quoting code
    # snippets (e.g. \1, \s, \d from regex strings, or \username / \path).
    # Two passes:
    #   1. \u not followed by exactly 4 hex digits  →  \\u  (e.g. \username → \\username)
    #   2. any remaining bare backslash not part of a valid JSON escape  →  \\
    text = re.sub(r"\\u(?![0-9a-fA-F]{4})", r"\\\\u", text)
    _VALID_JSON_ESCAPES = re.compile(r'\\(?!["\\/bfnrtu])')
    text = _VALID_JSON_ESCAPES.sub(r"\\\\", text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Common failure: the LLM quoted source code in `evidence` without
        # escaping inner `"` characters, prematurely terminating the string.
        # Walk the text and escape literal quotes inside string values, retry.
        repaired = _escape_inner_string_quotes(text)
        try:
            data = json.loads(repaired)
            logger.warning(
                "Recovered malformed LLM JSON by escaping unescaped inner quotes "
                "(output length: %d chars)",
                len(llm_output),
            )
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(
                "Failed to parse LLM verdict JSON: %s (output length: %d chars)",
                e,
                len(llm_output),
            )
            return Verdict.error(f"JSON parse failure: {e}")

    try:
        # Enforce calibration rules from the system prompt
        raw_verdict = data.get("verdict", "ERROR")
        # Clamp confidence to [0, 1] — LLMs can hallucinate out-of-range or NaN values
        raw_confidence = data.get("confidence", 0.0)
        confidence = (
            max(0.0, min(1.0, float(raw_confidence)))
            if isinstance(raw_confidence, (int, float)) and math.isfinite(raw_confidence)
            else 0.0
        )

        # Rule 1: TRUE_POSITIVE requires confidence >= 0.7
        if raw_verdict == "TRUE_POSITIVE" and confidence < 0.7:
            logger.warning(
                "Downgrading TRUE_POSITIVE to NEEDS_REVIEW: confidence %.2f < 0.7",
                confidence,
            )
            raw_verdict = "NEEDS_REVIEW"

        # Rule 2: confidence < 0.5 forces NEEDS_REVIEW (applies to current verdict,
        # including any already-downgraded value from rule 1)
        if confidence < 0.5 and raw_verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            logger.warning(
                "Downgrading %s to NEEDS_REVIEW: confidence %.2f < 0.5",
                raw_verdict,
                confidence,
            )
            raw_verdict = "NEEDS_REVIEW"

        return Verdict(
            verdict=VerdictType(raw_verdict),
            severity=Severity(data.get("severity", "N/A")),
            cwe_id=data.get("cwe_id", "N/A"),
            confidence=confidence,
            title=data.get("title", ""),
            summary=data.get("summary", ""),
            evidence=data.get("evidence", ""),
            sanitizer_found=bool(data.get("sanitizer_found", False)),
            sanitizer_description=data.get("sanitizer_description"),
            attack_vector=data.get("attack_vector"),
            remediation=data.get("remediation"),
            false_positive_reason=data.get("false_positive_reason"),
            provider=provider,
        )

    except (ValueError, KeyError) as e:
        logger.error(
            "Failed to parse LLM verdict JSON: %s (output length: %d chars)",
            e,
            len(llm_output),
        )
        return Verdict.error(f"JSON parse failure: {e}")
