"""Verdict data model and JSON parser."""
from __future__ import annotations

import json
import logging
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
            attack_vector=None,
            remediation=None,
            false_positive_reason="Empty or non-security diff",
        )

    @classmethod
    def error(cls, reason: str) -> "Verdict":
        """Return an error verdict when the analysis engine fails."""
        return cls(
            verdict=VerdictType.ERROR,
            severity=Severity.NA,
            cwe_id="N/A",
            confidence=0.0,
            title="Analysis engine error",
            summary=reason,
            evidence="",
            sanitizer_found=False,
            sanitizer_description=None,
            attack_vector=None,
            remediation=None,
            false_positive_reason=None,
        )


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

    try:
        data = json.loads(text)

        # Enforce calibration rules from the system prompt
        raw_verdict = data.get("verdict", "ERROR")
        confidence = float(data.get("confidence", 0.0))

        # If confidence is too low, downgrade TRUE_POSITIVE to NEEDS_REVIEW
        if raw_verdict == "TRUE_POSITIVE" and confidence < 0.7:
            logger.warning(
                "Downgrading TRUE_POSITIVE to NEEDS_REVIEW: confidence %.2f < 0.7",
                confidence,
            )
            raw_verdict = "NEEDS_REVIEW"

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

    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.error(
            "Failed to parse LLM verdict JSON: %s\nRaw output (first 500 chars): %s",
            e,
            llm_output[:500],
        )
        return Verdict.error(f"JSON parse failure: {e}")
