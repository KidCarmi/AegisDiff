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
