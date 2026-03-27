"""Tests for Phase 7 — SARIF builder and GitHub Code Scanning integration."""
from __future__ import annotations

import base64
import gzip
import json

import pytest

from aegisdiff.triage.sarif import build_sarif, encode_sarif
from aegisdiff.triage.verdicts import Severity, VerdictType, parse_verdict


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tp(
    cwe: str = "CWE-89",
    severity: str = "HIGH",
    confidence: float = 0.92,
    file_path: str | None = "app/views.py",
    line_number: int | None = 42,
) -> object:
    v = parse_verdict(json.dumps({
        "verdict": "TRUE_POSITIVE",
        "severity": severity,
        "cwe_id": cwe,
        "confidence": confidence,
        "title": f"Injection via {cwe}",
        "summary": "User input reaches dangerous sink.",
        "evidence": "cursor.execute(query)",
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": "Craft malicious SQL",
        "remediation": "Use parameterised queries.",
        "false_positive_reason": None,
    }), provider="groq")
    if file_path is not None:
        v.file_path = file_path
    if line_number is not None:
        v.line_number = line_number
    return v


def _nr(cwe: str = "CWE-79") -> object:
    return parse_verdict(json.dumps({
        "verdict": "NEEDS_REVIEW",
        "severity": "MEDIUM",
        "cwe_id": cwe,
        "confidence": 0.45,
        "title": f"Possible {cwe}",
        "summary": "Could not confirm exploitability.",
        "evidence": "",
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": None,
        "remediation": None,
        "false_positive_reason": None,
    }), provider="groq")


def _fp() -> object:
    return parse_verdict(json.dumps({
        "verdict": "FALSE_POSITIVE",
        "severity": "N/A",
        "cwe_id": "N/A",
        "confidence": 0.95,
        "title": "ORM is safe",
        "summary": "Framework handles escaping.",
        "evidence": "",
        "sanitizer_found": True,
        "sanitizer_description": "Django ORM",
        "attack_vector": None,
        "remediation": None,
        "false_positive_reason": "Django ORM parameterises automatically",
    }), provider="groq")


REPO = "KidCarmi/AegisDiff"
SHA = "abc1234def5678901234567890123456789012345"


# ── build_sarif ───────────────────────────────────────────────────────────────

class TestBuildSarif:

    def test_version_is_2_1_0(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        assert sarif["version"] == "2.1.0"

    def test_schema_field_present(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        assert "$schema" in sarif

    def test_has_one_run(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        assert len(sarif["runs"]) == 1

    def test_tool_name_is_aegisdiff(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "AegisDiff"

    def test_true_positive_included(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-89"

    def test_needs_review_included(self):
        sarif = build_sarif([_nr()], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-79"

    def test_false_positive_excluded(self):
        sarif = build_sarif([_fp()], REPO, SHA)
        assert sarif["runs"][0]["results"] == []

    def test_error_verdict_excluded(self):
        from aegisdiff.triage.verdicts import Verdict
        err = Verdict.error("LLM timeout")
        sarif = build_sarif([err], REPO, SHA)
        assert sarif["runs"][0]["results"] == []

    def test_mixed_only_actionable_included(self):
        sarif = build_sarif([_tp(), _fp(), _nr()], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        rule_ids = {r["ruleId"] for r in results}
        assert "CWE-89" in rule_ids
        assert "CWE-79" in rule_ids

    def test_file_path_in_location(self):
        sarif = build_sarif([_tp(file_path="src/api.py", line_number=10)], REPO, SHA)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/api.py"

    def test_line_number_in_region(self):
        sarif = build_sarif([_tp(file_path="app/views.py", line_number=42)], REPO, SHA)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42

    def test_no_file_path_uses_fallback_location(self):
        sarif = build_sarif([_tp(file_path=None, line_number=None)], REPO, SHA)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc

    def test_no_line_number_omits_region(self):
        sarif = build_sarif([_tp(file_path="app/views.py", line_number=None)], REPO, SHA)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_deduplicates_rules_for_same_cwe(self):
        two_sql = [_tp(cwe="CWE-89"), _tp(cwe="CWE-89", file_path="other.py", line_number=5)]
        sarif = build_sarif(two_sql, REPO, SHA)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        cwe_ids = [r["id"] for r in rules]
        assert cwe_ids.count("CWE-89") == 1

    def test_two_results_for_two_files_same_cwe(self):
        two_sql = [_tp(cwe="CWE-89"), _tp(cwe="CWE-89", file_path="other.py", line_number=5)]
        sarif = build_sarif(two_sql, REPO, SHA)
        assert len(sarif["runs"][0]["results"]) == 2

    def test_rule_has_help_uri_for_known_cwe(self):
        sarif = build_sarif([_tp(cwe="CWE-89")], REPO, SHA)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in rule
        assert "89" in rule["helpUri"]

    def test_critical_severity_maps_to_error_level(self):
        sarif = build_sarif([_tp(severity="CRITICAL")], REPO, SHA)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self):
        sarif = build_sarif([_nr()], REPO, SHA)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_automation_details_contains_sha(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        auto = sarif["runs"][0]["automationDetails"]["id"]
        assert SHA[:7] in auto

    def test_empty_verdicts_produces_empty_results(self):
        sarif = build_sarif([], REPO, SHA)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# ── encode_sarif ──────────────────────────────────────────────────────────────

class TestEncodeSarif:

    def test_returns_string(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        encoded = encode_sarif(sarif)
        assert isinstance(encoded, str)

    def test_is_valid_base64(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        encoded = encode_sarif(sarif)
        # Should not raise
        decoded = base64.b64decode(encoded)
        assert len(decoded) > 0

    def test_decompresses_to_valid_json(self):
        sarif = build_sarif([_tp()], REPO, SHA)
        encoded = encode_sarif(sarif)
        raw = base64.b64decode(encoded)
        decompressed = gzip.decompress(raw)
        recovered = json.loads(decompressed)
        assert recovered["version"] == "2.1.0"

    def test_round_trip_preserves_results(self):
        sarif = build_sarif([_tp(cwe="CWE-78"), _nr(cwe="CWE-79")], REPO, SHA)
        encoded = encode_sarif(sarif)
        recovered = json.loads(gzip.decompress(base64.b64decode(encoded)))
        assert len(recovered["runs"][0]["results"]) == 2

    def test_compressed_smaller_than_raw(self):
        """Compression should reduce size for typical SARIF documents."""
        verdicts = [_tp(cwe=f"CWE-{i}") for i in range(10)]
        sarif = build_sarif(verdicts, REPO, SHA)
        raw_size = len(json.dumps(sarif).encode("utf-8"))
        encoded_size = len(base64.b64decode(encode_sarif(sarif)))
        assert encoded_size < raw_size
