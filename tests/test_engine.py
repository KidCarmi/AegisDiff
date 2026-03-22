"""Integration tests for the TriageEngine."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegisdiff.llm.orchestrator import LLMOrchestrator
from aegisdiff.llm.providers.base import LLMResponse
from aegisdiff.triage.engine import TriageEngine
from aegisdiff.triage.verdicts import Verdict, VerdictType


def make_orchestrator_with_response(content: str, provider: str = "gemini") -> LLMOrchestrator:
    mock_orch = MagicMock(spec=LLMOrchestrator)
    mock_orch.complete.return_value = LLMResponse(
        content=content,
        provider=provider,
        model="gemini-1.5-pro",
        input_tokens=500,
        output_tokens=200,
        latency_ms=1200.0,
    )
    return mock_orch


VALID_VERDICT_JSON = json.dumps({
    "verdict": "TRUE_POSITIVE",
    "severity": "HIGH",
    "cwe_id": "CWE-89",
    "confidence": 0.92,
    "title": "SQL Injection via user_id",
    "summary": "User-controlled input flows directly into cursor.execute().",
    "evidence": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
    "sanitizer_found": False,
    "sanitizer_description": None,
    "attack_vector": "Append ' OR 1=1 -- to the id parameter",
    "remediation": "Use parameterized queries.",
    "false_positive_reason": None,
})

FALSE_POSITIVE_JSON = json.dumps({
    "verdict": "FALSE_POSITIVE",
    "severity": "N/A",
    "cwe_id": "N/A",
    "confidence": 0.95,
    "title": "Django ORM filter is safe",
    "summary": "The query uses .filter() which is parameterized by default.",
    "evidence": "User.objects.filter(email=email)",
    "sanitizer_found": True,
    "sanitizer_description": "Django ORM parameterizes queries automatically",
    "attack_vector": None,
    "remediation": None,
    "false_positive_reason": "Django ORM .filter() uses bound parameters internally.",
})


class TestTriageEngineWithRealDiff:
    def test_true_positive_on_sqli_diff(self, tmp_path, sample_diff):
        # Create the file the diff references
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "views.py").write_text(
            "from django.http import HttpResponse\n"
            "from django.db import connection\n"
            "def get_user(request):\n"
            '    user_id = request.GET.get("id")\n'
            "    cursor = connection.cursor()\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            "    return HttpResponse('ok')\n"
        )
        orch = make_orchestrator_with_response(VALID_VERDICT_JSON)
        engine = TriageEngine(orch, repo_root=tmp_path)
        verdict = engine.analyze_diff(sample_diff)

        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        orch.complete.assert_called_once()

    def test_false_positive_on_safe_diff(self, tmp_path, safe_diff):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "models.py").write_text(
            "from django.db import models\n"
            "class User(models.Model):\n"
            "    name = models.CharField(max_length=100)\n"
            "    email = models.EmailField()\n"
        )
        orch = make_orchestrator_with_response(FALSE_POSITIVE_JSON)
        engine = TriageEngine(orch, repo_root=tmp_path)
        verdict = engine.analyze_diff(safe_diff)

        assert verdict.verdict == VerdictType.FALSE_POSITIVE

    def test_empty_diff_returns_no_op(self, tmp_path):
        orch = MagicMock(spec=LLMOrchestrator)
        engine = TriageEngine(orch, repo_root=tmp_path)
        verdict = engine.analyze_diff("")

        assert verdict.verdict == VerdictType.FALSE_POSITIVE
        assert "No security-relevant" in verdict.title
        orch.complete.assert_not_called()  # LLM not called for empty diff

    def test_all_providers_exhausted_returns_error_verdict(self, tmp_path, sample_diff):
        orch = MagicMock(spec=LLMOrchestrator)
        orch.complete.side_effect = RuntimeError("All providers exhausted")

        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "views.py").write_text("cursor.execute(f'SELECT {user_id}')\n")

        engine = TriageEngine(orch, repo_root=tmp_path)
        verdict = engine.analyze_diff(sample_diff)

        assert verdict.verdict == VerdictType.ERROR
        assert "All providers exhausted" in verdict.summary
