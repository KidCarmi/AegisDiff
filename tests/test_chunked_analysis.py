"""
Tests for Phase 3 — Per-File Chunked Analysis.

Covers:
  - TriageEngine._split_diff_by_file()
  - TriageEngine.analyze_diff_chunked()
  - TriageEngine.aggregate_verdicts()
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from aegisdiff.llm.orchestrator import LLMOrchestrator
from aegisdiff.llm.providers.base import LLMResponse
from aegisdiff.triage.engine import TriageEngine, _MAX_CHUNKS_PER_PR, _MAX_HUNK_LINES
from aegisdiff.triage.verdicts import Severity, Verdict, VerdictType, parse_verdict


# ── Helpers ───────────────────────────────────────────────────────────────────

def _llm_response(content: str, provider: str = "groq") -> LLMResponse:
    return LLMResponse(
        content=content,
        provider=provider,
        model="llama-3.3-70b",
        input_tokens=300,
        output_tokens=100,
        latency_ms=400.0,
    )


def _orch_sequence(*responses: str) -> LLMOrchestrator:
    """Mock orchestrator that returns responses in sequence."""
    mock = MagicMock(spec=LLMOrchestrator)
    mock.complete.side_effect = [_llm_response(r) for r in responses]
    return mock


def _tp(cwe: str = "CWE-89", severity: str = "HIGH", confidence: float = 0.92) -> str:
    return json.dumps({
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
    })


def _fp() -> str:
    return json.dumps({
        "verdict": "FALSE_POSITIVE",
        "severity": "N/A",
        "cwe_id": "N/A",
        "confidence": 0.95,
        "title": "ORM usage is safe",
        "summary": "Framework handles escaping.",
        "evidence": "",
        "sanitizer_found": True,
        "sanitizer_description": "Django ORM parameterises automatically",
        "attack_vector": None,
        "remediation": None,
        "false_positive_reason": "Django ORM parameterises automatically",
    })


def _nr(cwe: str = "CWE-79", confidence: float = 0.45) -> str:
    return json.dumps({
        "verdict": "NEEDS_REVIEW",
        "severity": "MEDIUM",
        "cwe_id": cwe,
        "confidence": confidence,
        "title": f"Possible {cwe} — needs review",
        "summary": "Could not confirm exploitability.",
        "evidence": "",
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": None,
        "remediation": None,
        "false_positive_reason": None,
    })


# ── Multi-file diff fixtures ───────────────────────────────────────────────────

SINGLE_FILE_DIFF = """\
diff --git a/app/views.py b/app/views.py
index abc1234..def5678 100644
--- a/app/views.py
+++ b/app/views.py
@@ -1,4 +1,6 @@
 from django.db import connection
+def search(request):
+    q = request.GET.get('q')
+    cursor = connection.cursor()
+    cursor.execute("SELECT * FROM users WHERE name = '" + q + "'")
"""

TWO_FILE_DIFF = """\
diff --git a/app/views.py b/app/views.py
index abc1234..def5678 100644
--- a/app/views.py
+++ b/app/views.py
@@ -1,3 +1,5 @@
 from django.db import connection
+def search(request):
+    cursor = connection.cursor()
+    cursor.execute("SELECT * FROM users WHERE name = '" + request.GET.get('q') + "'")
diff --git a/app/utils.py b/app/utils.py
index 1111111..2222222 100644
--- a/app/utils.py
+++ b/app/utils.py
@@ -1,3 +1,4 @@
 from django.db import models
+class User(models.Model):
+    email = models.EmailField()
+    name = models.CharField(max_length=100)
"""

THREE_FILE_DIFF = """\
diff --git a/api/auth.py b/api/auth.py
index 1111111..2222222 100644
--- a/api/auth.py
+++ b/api/auth.py
@@ -1,2 +1,4 @@
+import subprocess
+def run(cmd): subprocess.check_output(cmd, shell=True)
diff --git a/api/views.py b/api/views.py
index 3333333..4444444 100644
--- a/api/views.py
+++ b/api/views.py
@@ -1,2 +1,4 @@
+import pickle
+def restore(data): return pickle.loads(data)
diff --git a/api/safe.py b/api/safe.py
index 5555555..6666666 100644
--- a/api/safe.py
+++ b/api/safe.py
@@ -1,2 +1,3 @@
+from django.db import models
+class Item(models.Model): name = models.CharField(max_length=50)
"""


# ── _split_diff_by_file ───────────────────────────────────────────────────────

class TestSplitDiffByFile:

    def test_single_file_returns_one_chunk(self):
        chunks = TriageEngine._split_diff_by_file(SINGLE_FILE_DIFF)
        assert len(chunks) == 1
        file_path, chunk = chunks[0]
        assert file_path == "app/views.py"
        assert "diff --git" in chunk
        assert "cursor.execute" in chunk

    def test_two_files_returns_two_chunks(self):
        chunks = TriageEngine._split_diff_by_file(TWO_FILE_DIFF)
        assert len(chunks) == 2
        paths = [fp for fp, _ in chunks]
        assert "app/views.py" in paths
        assert "app/utils.py" in paths

    def test_three_files_returns_three_chunks(self):
        chunks = TriageEngine._split_diff_by_file(THREE_FILE_DIFF)
        assert len(chunks) == 3
        paths = [fp for fp, _ in chunks]
        assert "api/auth.py" in paths
        assert "api/views.py" in paths
        assert "api/safe.py" in paths

    def test_each_chunk_starts_with_diff_header(self):
        chunks = TriageEngine._split_diff_by_file(TWO_FILE_DIFF)
        for _, chunk in chunks:
            assert chunk.startswith("diff --git")

    def test_chunks_contain_only_their_own_lines(self):
        chunks = TriageEngine._split_diff_by_file(TWO_FILE_DIFF)
        views_chunk = next(c for fp, c in chunks if fp == "app/views.py")
        utils_chunk = next(c for fp, c in chunks if fp == "app/utils.py")
        assert "cursor.execute" in views_chunk
        assert "cursor.execute" not in utils_chunk
        assert "EmailField" in utils_chunk
        assert "EmailField" not in views_chunk

    def test_empty_diff_returns_empty_list(self):
        assert TriageEngine._split_diff_by_file("") == []
        assert TriageEngine._split_diff_by_file("   \n  ") == []

    def test_diff_without_git_header_returns_empty_list(self):
        plain = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n+x = 1\n"
        assert TriageEngine._split_diff_by_file(plain) == []

    def test_file_path_extracted_from_b_side(self):
        diff = "diff --git a/src/foo/bar.py b/src/foo/bar.py\n+x = 1\n"
        chunks = TriageEngine._split_diff_by_file(diff)
        assert chunks[0][0] == "src/foo/bar.py"

    def test_nested_path_preserved(self):
        diff = "diff --git a/deep/nested/path/file.go b/deep/nested/path/file.go\n+x := 1\n"
        chunks = TriageEngine._split_diff_by_file(diff)
        assert chunks[0][0] == "deep/nested/path/file.go"


# ── aggregate_verdicts ────────────────────────────────────────────────────────

class TestAggregateVerdicts:

    def _v(self, verdict: VerdictType, severity: Severity, confidence: float) -> Verdict:
        return parse_verdict(json.dumps({
            "verdict": verdict.value,
            "severity": severity.value,
            "cwe_id": "CWE-0",
            "confidence": confidence,
            "title": f"{verdict.value} {severity.value}",
            "summary": "",
            "evidence": "",
            "sanitizer_found": verdict == VerdictType.FALSE_POSITIVE,
            "sanitizer_description": None,
            "attack_vector": None,
            "remediation": None,
            "false_positive_reason": None,
        }), provider="groq")

    def test_true_positive_wins_over_false_positive(self):
        tp = self._v(VerdictType.TRUE_POSITIVE, Severity.MEDIUM, 0.8)
        fp = self._v(VerdictType.FALSE_POSITIVE, Severity.NA, 0.95)
        result = TriageEngine.aggregate_verdicts([fp, tp])
        assert result.verdict == VerdictType.TRUE_POSITIVE

    def test_needs_review_wins_over_false_positive(self):
        nr = self._v(VerdictType.NEEDS_REVIEW, Severity.LOW, 0.6)
        fp = self._v(VerdictType.FALSE_POSITIVE, Severity.NA, 0.99)
        result = TriageEngine.aggregate_verdicts([fp, nr])
        assert result.verdict == VerdictType.NEEDS_REVIEW

    def test_true_positive_wins_over_needs_review(self):
        tp = self._v(VerdictType.TRUE_POSITIVE, Severity.LOW, 0.75)
        nr = self._v(VerdictType.NEEDS_REVIEW, Severity.HIGH, 0.9)
        result = TriageEngine.aggregate_verdicts([tp, nr])
        assert result.verdict == VerdictType.TRUE_POSITIVE

    def test_higher_severity_wins_among_equal_verdicts(self):
        high = self._v(VerdictType.TRUE_POSITIVE, Severity.HIGH, 0.8)
        critical = self._v(VerdictType.TRUE_POSITIVE, Severity.CRITICAL, 0.8)
        result = TriageEngine.aggregate_verdicts([high, critical])
        assert result.severity == Severity.CRITICAL

    def test_higher_confidence_breaks_severity_tie(self):
        a = self._v(VerdictType.TRUE_POSITIVE, Severity.HIGH, 0.75)
        b = self._v(VerdictType.TRUE_POSITIVE, Severity.HIGH, 0.95)
        result = TriageEngine.aggregate_verdicts([a, b])
        assert result.confidence == 0.95

    def test_single_verdict_returns_itself(self):
        tp = self._v(VerdictType.TRUE_POSITIVE, Severity.MEDIUM, 0.9)
        result = TriageEngine.aggregate_verdicts([tp])
        assert result is tp

    def test_empty_list_returns_noop(self):
        result = TriageEngine.aggregate_verdicts([])
        assert result.verdict == VerdictType.FALSE_POSITIVE
        assert "No security-relevant" in result.title

    def test_all_false_positives_returns_false_positive(self):
        fps = [self._v(VerdictType.FALSE_POSITIVE, Severity.NA, 0.9) for _ in range(3)]
        result = TriageEngine.aggregate_verdicts(fps)
        assert result.verdict == VerdictType.FALSE_POSITIVE

    def test_error_wins_over_false_positive(self):
        err = self._v(VerdictType.ERROR, Severity.NA, 0.0)
        fp = self._v(VerdictType.FALSE_POSITIVE, Severity.NA, 0.9)
        result = TriageEngine.aggregate_verdicts([fp, err])
        assert result.verdict == VerdictType.ERROR


# ── analyze_diff_chunked ──────────────────────────────────────────────────────

class TestAnalyzeDiffChunked:

    def test_two_files_calls_llm_twice(self, tmp_path):
        orch = _orch_sequence(_tp(), _fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(TWO_FILE_DIFF)
        assert len(verdicts) == 2
        assert orch.complete.call_count == 2

    def test_three_files_calls_llm_three_times(self, tmp_path):
        orch = _orch_sequence(_tp(), _tp(cwe="CWE-502", severity="CRITICAL"), _fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(THREE_FILE_DIFF)
        assert len(verdicts) == 3
        assert orch.complete.call_count == 3

    def test_returns_all_verdicts_not_just_worst(self, tmp_path):
        orch = _orch_sequence(_tp(), _fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(TWO_FILE_DIFF)
        verdict_types = {v.verdict for v in verdicts}
        assert VerdictType.TRUE_POSITIVE in verdict_types
        assert VerdictType.FALSE_POSITIVE in verdict_types

    def test_aggregate_after_chunked_selects_worst(self, tmp_path):
        orch = _orch_sequence(_fp(), _tp(cwe="CWE-78", severity="HIGH"), _fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(THREE_FILE_DIFF)
        primary = TriageEngine.aggregate_verdicts(verdicts)
        assert primary.verdict == VerdictType.TRUE_POSITIVE
        assert primary.cwe_id == "CWE-78"

    def test_empty_diff_falls_back_to_noop(self, tmp_path):
        orch = MagicMock(spec=LLMOrchestrator)
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked("")
        assert len(verdicts) == 1
        assert verdicts[0].verdict == VerdictType.FALSE_POSITIVE
        orch.complete.assert_not_called()

    def test_single_file_diff_returns_one_verdict(self, tmp_path):
        orch = _orch_sequence(_tp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(SINGLE_FILE_DIFF)
        assert len(verdicts) == 1

    def test_needs_review_chunk_included_in_results(self, tmp_path):
        orch = _orch_sequence(_nr(), _fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(TWO_FILE_DIFF)
        types = {v.verdict for v in verdicts}
        assert VerdictType.NEEDS_REVIEW in types

    def test_critical_severity_becomes_primary(self, tmp_path):
        orch = _orch_sequence(
            _tp(cwe="CWE-89", severity="HIGH"),
            _tp(cwe="CWE-502", severity="CRITICAL"),
            _fp(),
        )
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(THREE_FILE_DIFF)
        primary = TriageEngine.aggregate_verdicts(verdicts)
        assert primary.severity == Severity.CRITICAL
        assert primary.cwe_id == "CWE-502"

    def test_no_git_header_falls_back_to_whole_diff(self, tmp_path):
        """Diff without diff --git headers → analyze as one unit."""
        plain_diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n+x = 1\n"
        orch = _orch_sequence(_fp())
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(plain_diff)
        # Falls back to single whole-diff analysis
        assert len(verdicts) == 1


# ── _split_file_diff_into_hunks ───────────────────────────────────────────────

def _make_file_diff(n_hunks: int, lines_per_hunk: int = 10) -> str:
    """Build a synthetic single-file diff with n_hunks @@ sections."""
    header = (
        "diff --git a/app/views.py b/app/views.py\n"
        "index abc..def 100644\n"
        "--- a/app/views.py\n"
        "+++ b/app/views.py\n"
    )
    hunks = ""
    for i in range(n_hunks):
        start = i * lines_per_hunk + 1
        hunks += f"@@ -{start},{lines_per_hunk} +{start},{lines_per_hunk + 1} @@\n"
        for j in range(lines_per_hunk - 1):
            hunks += f" context line {i}-{j}\n"
        hunks += f"+new line in hunk {i}\n"
    return header + hunks


class TestSplitFileHunks:

    def test_small_diff_stays_single_chunk(self):
        diff = _make_file_diff(n_hunks=2, lines_per_hunk=10)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=150)
        assert len(result) == 1

    def test_large_diff_splits_into_multiple_chunks(self):
        # 3 hunks × 60 lines = 180 lines total → should split with max=100
        diff = _make_file_diff(n_hunks=3, lines_per_hunk=60)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=100)
        assert len(result) >= 2

    def test_each_chunk_contains_file_header(self):
        diff = _make_file_diff(n_hunks=4, lines_per_hunk=60)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=100)
        for chunk in result:
            assert "diff --git" in chunk
            assert "--- a/app/views.py" in chunk
            assert "+++ b/app/views.py" in chunk

    def test_each_chunk_contains_at_least_one_hunk(self):
        diff = _make_file_diff(n_hunks=5, lines_per_hunk=60)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=100)
        for chunk in result:
            assert "@@" in chunk

    def test_all_hunks_preserved_across_chunks(self):
        n_hunks = 6
        diff = _make_file_diff(n_hunks=n_hunks, lines_per_hunk=60)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=100)
        combined = "".join(result)
        # Every hunk marker should appear (once in each chunk it's in)
        # At minimum every "new line in hunk N" should appear somewhere
        for i in range(n_hunks):
            assert f"new line in hunk {i}" in combined

    def test_no_hunk_markers_returns_original(self):
        diff = "diff --git a/x.py b/x.py\nindex abc..def 100644\nbinary files differ\n"
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=50)
        assert result == [diff]

    def test_single_oversized_hunk_not_split(self):
        # A single hunk > max still comes out as one chunk (can't split mid-hunk)
        diff = _make_file_diff(n_hunks=1, lines_per_hunk=200)
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=50)
        assert len(result) == 1

    def test_chunk_line_counts_respect_limit(self):
        diff = _make_file_diff(n_hunks=10, lines_per_hunk=20)
        max_lines = 50
        result = TriageEngine._split_file_diff_into_hunks(diff, max_hunk_lines=max_lines)
        header_lines = 4  # diff --git + index + --- + +++
        for chunk in result:
            hunk_lines = chunk.count("\n") - header_lines
            # Each chunk's hunk content must be ≤ max_lines
            # (a single hunk that exceeds the limit is allowed through as-is)
            assert hunk_lines <= max_lines or chunk.count("@@") == 1


# ── quota cap ────────────────────────────────────────────────────────────────

class TestChunkCap:

    def _many_file_diff(self, n_files: int) -> str:
        """Build a diff with n_files, each having 2 hunks of 80 lines."""
        diff = ""
        for i in range(n_files):
            diff += f"diff --git a/file{i}.py b/file{i}.py\n"
            diff += f"index {i:07x}..{i+1:07x} 100644\n"
            diff += f"--- a/file{i}.py\n+++ b/file{i}.py\n"
            for h in range(2):
                start = h * 80 + 1
                diff += f"@@ -{start},80 +{start},81 @@\n"
                for j in range(79):
                    diff += f" line {j}\n"
                diff += f"+injected line hunk {h}\n"
        return diff

    def test_chunks_capped_at_max(self, tmp_path):
        # 15 files × 2 hunks each = 30 sub-chunks → should be capped at _MAX_CHUNKS_PER_PR
        diff = self._many_file_diff(n_files=15)
        responses = [_fp()] * _MAX_CHUNKS_PER_PR
        orch = _orch_sequence(*responses)
        engine = TriageEngine(orch, tmp_path)
        verdicts = engine.analyze_diff_chunked(diff)
        assert len(verdicts) == _MAX_CHUNKS_PER_PR
        assert orch.complete.call_count == _MAX_CHUNKS_PER_PR
