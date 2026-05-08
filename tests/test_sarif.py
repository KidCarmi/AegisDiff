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


# ── Result-level dedup ───────────────────────────────────────────────────────

class TestSarifResultDedup:
    """Chunked / Large PR Mode can produce multiple actionable verdicts that
    point at the same finding location (same CWE + same file + same line).
    Without dedup the GitHub Security tab would show duplicate alerts. We
    collapse such groups to a single result, keeping the highest-confidence
    verdict, while preserving rule-level dedup and TRUE_POSITIVE /
    NEEDS_REVIEW filtering.
    """

    # 1. Same key → one result, highest-confidence kept
    def test_dedup_collapses_same_cwe_same_file_same_line(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/auth/login.py", line_number=6, confidence=0.85),
            _tp(cwe="CWE-78", file_path="src/auth/login.py", line_number=6, confidence=0.95),
            _tp(cwe="CWE-78", file_path="src/auth/login.py", line_number=6, confidence=0.92),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        # Highest-confidence verdict wins.
        assert results[0]["properties"]["confidence"] == 0.95
        # Rule-level dedup is also preserved.
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["CWE-78"]

    # 2. Same file + same line + different CWE → two results
    def test_dedup_keeps_separate_results_for_different_cwe_at_same_location(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10),
            _tp(cwe="CWE-89", file_path="src/x.py", line_number=10),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        rule_ids = sorted(r["ruleId"] for r in results)
        assert rule_ids == ["CWE-78", "CWE-89"]

    # 3. Same file + different line → two results
    def test_dedup_keeps_separate_results_for_different_lines_in_same_file(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=42),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        lines = sorted(
            r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results
        )
        assert lines == [10, 42]

    # 4. Different file + same CWE + same line → two results
    def test_dedup_keeps_separate_results_for_different_files_at_same_line(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/a.py", line_number=10),
            _tp(cwe="CWE-78", file_path="src/b.py", line_number=10),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        uris = sorted(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results
        )
        assert uris == ["src/a.py", "src/b.py"]

    # 5. Missing file_path / line_number must not be incorrectly collapsed
    def test_dedup_does_not_collapse_different_cwes_when_location_missing(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path=None, line_number=None),
            _tp(cwe="CWE-89", file_path=None, line_number=None),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        rule_ids = sorted(r["ruleId"] for r in results)
        assert rule_ids == ["CWE-78", "CWE-89"]

    def test_dedup_does_not_collapse_when_only_one_side_has_a_line_number(self):
        # Same CWE + same file, but one has a line_number and one does not.
        # These describe different locations to a reviewer — must not collapse.
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=42),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=None),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_dedup_collapses_missing_location_same_cwe(self):
        # Two verdicts with identical key (same CWE, both file_path=None,
        # both line_number=None) — these are indistinguishable to a SARIF
        # consumer and SHOULD collapse, keeping the highest confidence.
        verdicts = [
            _tp(cwe="CWE-78", file_path=None, line_number=None, confidence=0.80),
            _tp(cwe="CWE-78", file_path=None, line_number=None, confidence=0.94),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["properties"]["confidence"] == 0.94

    def test_dedup_treats_line_zero_and_none_as_equivalent(self):
        # ``line_number=0`` is the engine's "no real sink line" signal and
        # the existing code skips the SARIF region for it. Both 0 and None
        # mean "no specific line" so verdicts that differ only on that
        # axis must collapse.
        v_none = _tp(cwe="CWE-78", file_path="src/x.py", line_number=None, confidence=0.90)
        v_zero = _tp(cwe="CWE-78", file_path="src/x.py", line_number=None, confidence=0.93)
        v_zero.line_number = 0  # bypass the test helper which skips zero
        sarif = build_sarif([v_none, v_zero], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["properties"]["confidence"] == 0.93

    # 6. encode_sarif round-trip after dedup
    def test_encode_sarif_round_trip_after_dedup(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.80),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.95),
            _tp(cwe="CWE-89", file_path="src/y.py", line_number=22, confidence=0.91),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        recovered = json.loads(gzip.decompress(base64.b64decode(encode_sarif(sarif))))
        results = recovered["runs"][0]["results"]
        # Two unique locations after dedup.
        assert len(results) == 2
        assert recovered["version"] == "2.1.0"

    # 7. build_sarif output is deterministic
    def test_build_sarif_output_is_deterministic(self):
        verdicts = [
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.95),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.85),
            _tp(cwe="CWE-89", file_path="src/y.py", line_number=22),
            _nr(cwe="CWE-79"),
        ]
        first = build_sarif(verdicts, REPO, SHA)
        second = build_sarif(verdicts, REPO, SHA)
        # Byte-identical JSON serialization.
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
        # Result order is deterministic too (insertion-order by first
        # occurrence of each dedup key).
        assert [r["ruleId"] for r in first["runs"][0]["results"]] == [
            r["ruleId"] for r in second["runs"][0]["results"]
        ]

    def test_dedup_input_order_independence_of_highest_confidence_pick(self):
        """Whichever order the high-confidence verdict arrives in, it wins."""
        a = _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.70)
        b = _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.95)
        for ordering in ([a, b], [b, a]):
            sarif = build_sarif(ordering, REPO, SHA)
            results = sarif["runs"][0]["results"]
            assert len(results) == 1
            assert results[0]["properties"]["confidence"] == 0.95

    def test_dedup_does_not_promote_filtered_verdicts(self):
        """FALSE_POSITIVE / ERROR verdicts at the same location must not
        accidentally become the kept verdict for the group — they were
        excluded from ``actionable`` before dedup runs."""
        actionable = _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.72)
        # Higher-confidence FP at the same location.
        fp_at_same_spot = _fp()
        fp_at_same_spot.cwe_id = "CWE-78"
        fp_at_same_spot.file_path = "src/x.py"
        fp_at_same_spot.line_number = 10
        fp_at_same_spot.confidence = 0.99
        sarif = build_sarif([actionable, fp_at_same_spot], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        # The actionable verdict survives, not the higher-confidence FP.
        assert results[0]["properties"]["confidence"] == 0.72
        assert results[0]["properties"]["verdict"] == "TRUE_POSITIVE"

    # Codex review (P2): the dedup key must normalise file_path the same
    # way the SARIF emission does, so verdicts that serialise to the same
    # artifactLocation.uri also collapse.
    def test_dedup_normalises_file_path_leading_slash(self):
        """``/src/x.py`` and ``src/x.py`` both serialise to ``src/x.py``
        in artifactLocation.uri; they MUST collapse to one result."""
        verdicts = [
            _tp(cwe="CWE-78", file_path="/src/x.py", line_number=10, confidence=0.85),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.95),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        # Highest-confidence verdict wins.
        assert results[0]["properties"]["confidence"] == 0.95
        # Output URI is the normalised form (no leading slash).
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/x.py"

    def test_dedup_normalises_multiple_leading_slashes(self):
        """``lstrip("/")`` strips all leading slashes; dedup must too."""
        verdicts = [
            _tp(cwe="CWE-78", file_path="//src/x.py", line_number=10, confidence=0.80),
            _tp(cwe="CWE-78", file_path="src/x.py", line_number=10, confidence=0.92),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["properties"]["confidence"] == 0.92

    def test_dedup_collapses_falsy_file_paths_with_same_cwe(self):
        """Both ``None`` and ``""`` render to the ``"."`` fallback
        location, so they share a dedup bucket when CWE matches."""
        v_none = _tp(cwe="CWE-78", file_path=None, line_number=None, confidence=0.80)
        v_empty = _tp(cwe="CWE-78", file_path="", line_number=None, confidence=0.93)
        sarif = build_sarif([v_none, v_empty], REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["properties"]["confidence"] == 0.93

    def test_dedup_normalised_path_does_not_collapse_different_paths(self):
        """Sanity: normalisation must not over-collapse. ``a/x.py`` and
        ``b/x.py`` are still different paths after ``lstrip("/")``."""
        verdicts = [
            _tp(cwe="CWE-78", file_path="/a/x.py", line_number=10),
            _tp(cwe="CWE-78", file_path="/b/x.py", line_number=10),
        ]
        sarif = build_sarif(verdicts, REPO, SHA)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
