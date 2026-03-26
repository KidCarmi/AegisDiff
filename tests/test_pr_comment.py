"""Tests for PR comment formatters — inline and summary modes."""
from __future__ import annotations

import pytest

from aegisdiff.github.pr_comment import (
    COMMENT_MARKER,
    format_inline_comment,
    format_summary_comment,
    format_verdict_comment,
)
from aegisdiff.triage.verdicts import Severity, Verdict, VerdictType


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _tp(
    line_number: int | None = 42,
    file_path: str | None = "app/views.py",
) -> Verdict:
    v = Verdict(
        verdict=VerdictType.TRUE_POSITIVE,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        confidence=0.92,
        title="SQL Injection via user_id parameter",
        summary="User-controlled input reaches cursor.execute without parameterization.",
        evidence='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector="Pass `1 OR 1=1` as the id parameter",
        remediation="Use parameterized queries: cursor.execute('...', (user_id,))",
        false_positive_reason=None,
        provider="gemini",
        line_number=line_number,
        file_path=file_path,
    )
    return v


def _fp() -> Verdict:
    return Verdict(
        verdict=VerdictType.FALSE_POSITIVE,
        severity=Severity.NA,
        cwe_id="N/A",
        confidence=0.95,
        title="Django ORM parameterizes automatically",
        summary="No exploitable path found.",
        evidence="",
        sanitizer_found=True,
        sanitizer_description="Django ORM",
        attack_vector=None,
        remediation=None,
        false_positive_reason="ORM handles parameterization",
        provider="gemini",
    )


def _nr() -> Verdict:
    return Verdict(
        verdict=VerdictType.NEEDS_REVIEW,
        severity=Severity.MEDIUM,
        cwe_id="CWE-79",
        confidence=0.55,
        title="Possible XSS — manual review needed",
        summary="Could not confirm exploitability.",
        evidence="el.innerHTML = data",
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector=None,
        remediation=None,
        false_positive_reason=None,
        provider="groq",
    )


# ── format_inline_comment ─────────────────────────────────────────────────────


class TestFormatInlineComment:
    def test_contains_title(self):
        body = format_inline_comment(_tp())
        assert "SQL Injection" in body

    def test_contains_cwe(self):
        body = format_inline_comment(_tp())
        assert "CWE-89" in body

    def test_contains_severity(self):
        body = format_inline_comment(_tp())
        assert "HIGH" in body

    def test_contains_evidence_code_block(self):
        body = format_inline_comment(_tp())
        assert "```" in body
        assert "cursor.execute" in body

    def test_contains_remediation(self):
        body = format_inline_comment(_tp())
        assert "parameterized" in body.lower()

    def test_contains_attack_vector(self):
        body = format_inline_comment(_tp())
        assert "1 OR 1=1" in body

    def test_no_empty_sections_when_fields_missing(self):
        v = _tp()
        v.evidence = ""
        v.attack_vector = None
        v.remediation = None
        body = format_inline_comment(v)
        # Should still have the title
        assert "SQL Injection" in body
        # Should not have empty code block
        assert "```\n\n```" not in body

    def test_false_positive_reason_shown(self):
        v = _fp()
        body = format_inline_comment(v)
        assert "ORM handles parameterization" in body


# ── format_summary_comment ────────────────────────────────────────────────────


class TestFormatSummaryComment:
    def test_contains_marker(self):
        body = format_summary_comment(_tp(), pr_number=7, sha="abc1234")
        assert COMMENT_MARKER in body

    def test_contains_verdict_value(self):
        body = format_summary_comment(_tp(), pr_number=7, sha="abc1234")
        assert "TRUE_POSITIVE" in body

    def test_contains_cwe_and_severity(self):
        body = format_summary_comment(_tp(), pr_number=7, sha="abc1234")
        assert "CWE-89" in body
        assert "HIGH" in body

    def test_contains_sha_and_pr(self):
        body = format_summary_comment(_tp(), pr_number=7, sha="abc1234")
        assert "abc1234" in body
        assert "#7" in body

    def test_inline_posted_omits_evidence_block(self):
        """When inline_posted=True, the <details> evidence block is omitted."""
        v = _tp()
        body = format_summary_comment(v, pr_number=1, sha="aaa", inline_posted=True)
        # The <details> evidence block should be absent
        assert "<details>" not in body
        assert "1 OR 1=1" not in body  # attack_vector omitted

    def test_inline_posted_shows_file_reference(self):
        v = _tp(line_number=42, file_path="app/views.py")
        body = format_summary_comment(v, pr_number=1, sha="aaa", inline_posted=True)
        assert "app/views.py" in body
        assert "42" in body

    def test_no_inline_includes_evidence(self):
        """Fallback: no inline comment → full detail in top-level comment."""
        v = _tp()
        body = format_summary_comment(v, pr_number=1, sha="aaa", inline_posted=False)
        assert "cursor.execute" in body

    def test_no_inline_includes_remediation(self):
        v = _tp()
        body = format_summary_comment(v, pr_number=1, sha="aaa", inline_posted=False)
        assert "parameterized" in body.lower()

    def test_total_findings_note_when_multiple(self):
        body = format_summary_comment(_tp(), pr_number=1, sha="aaa", total_findings=3)
        assert "3" in body

    def test_no_findings_note_for_single(self):
        body = format_summary_comment(_tp(), pr_number=1, sha="aaa", total_findings=1)
        # total_findings=1 → no note
        assert "true positive findings" not in body

    def test_false_positive_shows_why(self):
        v = _fp()
        body = format_summary_comment(v, pr_number=1, sha="aaa")
        assert "ORM handles parameterization" in body

    def test_sanitizer_row_present_when_found(self):
        v = _fp()
        body = format_summary_comment(v, pr_number=1, sha="aaa")
        assert "Django ORM" in body

    def test_sanitizer_row_none_when_not_found(self):
        body = format_summary_comment(_tp(), pr_number=1, sha="aaa")
        assert "None detected" in body

    def test_needs_review_verdict(self):
        body = format_summary_comment(_nr(), pr_number=3, sha="bbb")
        assert "NEEDS_REVIEW" in body
        assert "CWE-79" in body


# ── format_verdict_comment ────────────────────────────────────────────────────


class TestFormatVerdictComment:
    def test_is_alias_for_summary_no_inline(self):
        """format_verdict_comment is the legacy path — same as summary with inline_posted=False."""
        v = _tp()
        legacy = format_verdict_comment(v, pr_number=5, sha="fff")
        summary = format_summary_comment(v, pr_number=5, sha="fff", inline_posted=False)
        assert legacy == summary


# ── Engine → line_number annotation ──────────────────────────────────────────


class TestEngineLineNumberAnnotation:
    """Verify TriageEngine.analyze_diff() sets line_number + file_path on Verdict."""

    def test_tp_verdict_gets_line_number(self, tmp_path):
        import json
        from unittest.mock import MagicMock

        from aegisdiff.llm.orchestrator import LLMOrchestrator
        from aegisdiff.llm.providers.base import LLMResponse
        from aegisdiff.triage.engine import TriageEngine

        # Create source file with an obvious SQL sink
        app = tmp_path / "app"
        app.mkdir()
        (app / "views.py").write_text(
            "from django.db import connection\n"
            "def get_user(request):\n"
            '    uid = request.GET.get("id")\n'
            "    cursor = connection.cursor()\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
            "    return cursor.fetchone()\n"
        )

        diff = (
            "diff --git a/app/views.py b/app/views.py\n"
            "--- a/app/views.py\n"
            "+++ b/app/views.py\n"
            "@@ -1,6 +1,6 @@\n"
            "+from django.db import connection\n"
            "+def get_user(request):\n"
            '+    uid = request.GET.get("id")\n'
            "+    cursor = connection.cursor()\n"
            '+    cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
            "+    return cursor.fetchone()\n"
        )

        tp_json = json.dumps({
            "verdict": "TRUE_POSITIVE",
            "severity": "HIGH",
            "cwe_id": "CWE-89",
            "confidence": 0.92,
            "title": "SQL Injection",
            "summary": "SQLi",
            "evidence": "cursor.execute",
            "sanitizer_found": False,
            "sanitizer_description": None,
            "attack_vector": "craft id param",
            "remediation": "use params",
            "false_positive_reason": None,
        })

        mock_orch = MagicMock(spec=LLMOrchestrator)
        mock_orch.complete.return_value = LLMResponse(
            content=tp_json,
            provider="gemini",
            model="gemini-1.5-pro",
            input_tokens=100,
            output_tokens=50,
            latency_ms=500.0,
        )

        verdict = TriageEngine(mock_orch, tmp_path).analyze_diff(diff)
        assert verdict.line_number is not None
        assert verdict.line_number > 0
        assert verdict.file_path == "app/views.py"

    def test_fp_verdict_no_line_number_required(self, tmp_path):
        """FALSE_POSITIVE verdicts on safe code don't need a line number."""
        import json
        from unittest.mock import MagicMock

        from aegisdiff.llm.orchestrator import LLMOrchestrator
        from aegisdiff.llm.providers.base import LLMResponse
        from aegisdiff.triage.engine import TriageEngine

        diff = (
            "diff --git a/app/models.py b/app/models.py\n"
            "--- a/app/models.py\n"
            "+++ b/app/models.py\n"
            "@@ -1,3 +1,3 @@\n"
            "+from django.db import models\n"
            "+class User(models.Model):\n"
            "+    email = models.EmailField()\n"
        )

        fp_json = json.dumps({
            "verdict": "FALSE_POSITIVE",
            "severity": "N/A",
            "cwe_id": "N/A",
            "confidence": 0.95,
            "title": "ORM safe",
            "summary": "no issue",
            "evidence": "",
            "sanitizer_found": True,
            "sanitizer_description": "ORM",
            "attack_vector": None,
            "remediation": None,
            "false_positive_reason": "ORM safe",
        })

        mock_orch = MagicMock(spec=LLMOrchestrator)
        mock_orch.complete.return_value = LLMResponse(
            content=fp_json,
            provider="gemini",
            model="gemini-1.5-pro",
            input_tokens=50,
            output_tokens=30,
            latency_ms=200.0,
        )

        verdict = TriageEngine(mock_orch, tmp_path).analyze_diff(diff)
        assert verdict.verdict == VerdictType.FALSE_POSITIVE
        # line_number may or may not be set — just verify no crash
