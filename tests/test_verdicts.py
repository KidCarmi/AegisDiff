"""Tests for verdict parsing and calibration rules."""
from __future__ import annotations

import json

import pytest

from aegisdiff.triage.verdicts import Severity, Verdict, VerdictType, parse_verdict


VALID_JSON = {
    "verdict": "TRUE_POSITIVE",
    "severity": "HIGH",
    "cwe_id": "CWE-89",
    "confidence": 0.9,
    "title": "SQL Injection via user_id",
    "summary": "User-controlled input flows directly into cursor.execute().",
    "evidence": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    "sanitizer_found": False,
    "sanitizer_description": None,
    "attack_vector": "Append ' OR 1=1 -- to the id parameter",
    "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', [user_id])",
    "false_positive_reason": None,
}


class TestParseVerdictSuccess:
    def test_parses_valid_json(self):
        verdict = parse_verdict(json.dumps(VALID_JSON))
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.severity == Severity.HIGH
        assert verdict.cwe_id == "CWE-89"
        assert verdict.confidence == 0.9

    def test_parses_json_with_markdown_fences(self):
        wrapped = f"```json\n{json.dumps(VALID_JSON)}\n```"
        verdict = parse_verdict(wrapped)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE

    def test_parses_json_with_plain_fences(self):
        wrapped = f"```\n{json.dumps(VALID_JSON)}\n```"
        verdict = parse_verdict(wrapped)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE

    def test_provider_preserved(self):
        verdict = parse_verdict(json.dumps(VALID_JSON), provider="gemini")
        assert verdict.provider == "gemini"


class TestCalibrationRules:
    def test_true_positive_low_confidence_downgraded_to_needs_review(self):
        data = {**VALID_JSON, "verdict": "TRUE_POSITIVE", "confidence": 0.5}
        verdict = parse_verdict(json.dumps(data))
        assert verdict.verdict == VerdictType.NEEDS_REVIEW

    def test_true_positive_very_low_confidence_downgraded(self):
        data = {**VALID_JSON, "verdict": "TRUE_POSITIVE", "confidence": 0.3}
        verdict = parse_verdict(json.dumps(data))
        assert verdict.verdict == VerdictType.NEEDS_REVIEW

    def test_true_positive_high_confidence_preserved(self):
        data = {**VALID_JSON, "verdict": "TRUE_POSITIVE", "confidence": 0.85}
        verdict = parse_verdict(json.dumps(data))
        assert verdict.verdict == VerdictType.TRUE_POSITIVE

    def test_false_positive_low_confidence_downgraded_to_needs_review(self):
        data = {
            **VALID_JSON,
            "verdict": "FALSE_POSITIVE",
            "confidence": 0.3,
            "severity": "N/A",
            "false_positive_reason": "ORM used",
        }
        verdict = parse_verdict(json.dumps(data))
        assert verdict.verdict == VerdictType.NEEDS_REVIEW


class TestParseVerdictFailure:
    def test_invalid_json_returns_error_verdict(self):
        verdict = parse_verdict("this is not json")
        assert verdict.verdict == VerdictType.ERROR
        assert "JSON parse failure" in verdict.summary

    def test_empty_string_returns_error_verdict(self):
        verdict = parse_verdict("")
        assert verdict.verdict == VerdictType.ERROR

    def test_unknown_verdict_type_returns_error(self):
        data = {**VALID_JSON, "verdict": "UNKNOWN_TYPE"}
        verdict = parse_verdict(json.dumps(data))
        assert verdict.verdict == VerdictType.ERROR


class TestVerdictFactories:
    def test_no_op_verdict(self):
        v = Verdict.no_op()
        assert v.verdict == VerdictType.FALSE_POSITIVE
        assert v.confidence == 0.99
        assert v.severity == Severity.NA

    def test_error_verdict(self):
        v = Verdict.error("something went wrong")
        assert v.verdict == VerdictType.ERROR
        assert "something went wrong" in v.summary


class TestInvalidJsonEscapeSanitization:
    """The LLM sometimes copies regex patterns verbatim into JSON strings,
    producing invalid escape sequences like \\1, \\d, \\s, \\w.
    parse_verdict() must handle these gracefully."""

    def _make_json(self, title: str) -> str:
        """Build a raw JSON string with the given title (may contain bad escapes)."""
        return (
            '{"verdict":"TRUE_POSITIVE","severity":"HIGH","cwe_id":"CWE-89",'
            '"confidence":0.9,'
            f'"title":"{title}",'
            '"summary":"test","evidence":"test","fix":"test"}'
        )

    def test_backslash_digit_in_title(self):
        """\\1 from a regex backreference must not crash JSON parsing."""
        raw = self._make_json(r"\1")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_backslash_d_in_title(self):
        r"""\\d from a regex character class must not crash JSON parsing."""
        raw = self._make_json(r"\d+")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_backslash_s_in_title(self):
        r"""\\s from a regex whitespace class must not crash JSON parsing."""
        raw = self._make_json(r"\s*")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_backslash_w_in_title(self):
        r"""\\w from a regex word class must not crash JSON parsing."""
        raw = self._make_json(r"\w+")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_backslash_cwe_pattern(self):
        """CWE-\\1 backreference as seen in actual LLM output."""
        raw = self._make_json(r"CWE-\1 injection")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_multiple_invalid_escapes(self):
        """Multiple bad escapes in one string must all be sanitized."""
        raw = self._make_json(r"\d+\s*\w+\1")
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR, verdict.summary

    def test_valid_json_escapes_preserved(self):
        """Standard JSON escapes (\\n, \\t, \\", \\\\) must not be corrupted."""
        # Build JSON manually with valid escapes only
        payload = {**VALID_JSON, "title": "line1\nline2\ttabbed"}
        raw = json.dumps(payload)
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR
        assert "\n" in verdict.title or "line1" in verdict.title

    def test_unicode_escape_preserved(self):
        """\\uXXXX unicode escapes must survive sanitization."""
        payload = {**VALID_JSON, "title": "SQL\u2019s injection"}
        raw = json.dumps(payload)
        verdict = parse_verdict(raw)
        assert verdict.verdict != VerdictType.ERROR

    def test_backslash_at_end_of_string(self):
        """A trailing backslash in the JSON value must not raise an exception."""
        # Manually build a string with a bare backslash before the closing quote
        raw = '{"verdict":"TRUE_POSITIVE","severity":"HIGH","cwe_id":"CWE-89",' \
              '"confidence":0.9,"title":"regex pattern\\","summary":"t","evidence":"t","fix":"t"}'
        # This is invalid JSON even after sanitization — must return ERROR, not raise
        verdict = parse_verdict(raw)
        assert isinstance(verdict, Verdict)  # must return Verdict, not raise
