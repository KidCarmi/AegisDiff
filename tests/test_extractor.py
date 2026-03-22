"""Tests for the code context extractor."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from aegisdiff.code_context.extractor import CodeContextExtractor
from aegisdiff.code_context.models import CodeContext


class TestDiffParsing:
    def test_parses_changed_files(self, tmp_path, sample_diff):
        extractor = CodeContextExtractor(tmp_path)
        changed_files, changed_lines = extractor._parse_diff(sample_diff)
        assert "app/views.py" in changed_files

    def test_parses_added_lines(self, tmp_path, sample_diff):
        extractor = CodeContextExtractor(tmp_path)
        _, changed_lines = extractor._parse_diff(sample_diff)
        # The sample diff adds lines in app/views.py
        assert "app/views.py" in changed_lines
        assert len(changed_lines["app/views.py"]) > 0

    def test_empty_diff_returns_empty(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        changed_files, changed_lines = extractor._parse_diff("")
        assert changed_files == []
        assert changed_lines == {}


class TestSinkDetection:
    def test_detects_sql_injection_sink(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        changed_lines = {1}
        sinks = extractor._find_sinks(code, changed_lines, "test.py")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_cmd_injection_sink(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = "output = os.system(f'ls {user_dir}')"
        changed_lines = {1}
        sinks = extractor._find_sinks(code, changed_lines, "test.py")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_orm_filter_not_flagged(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = "User.objects.filter(email=email).first()"
        changed_lines = {1}
        sinks = extractor._find_sinks(code, changed_lines, "test.py")
        assert len(sinks) == 0

    def test_unchanged_lines_not_flagged(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        changed_lines = {99}  # Line 99, but code is at line 1
        sinks = extractor._find_sinks(code, changed_lines, "test.py")
        assert len(sinks) == 0


class TestSourceDetection:
    def test_detects_http_param_source(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = "user_id = request.GET.get('id')"
        changed_lines = {1}
        sources = extractor._find_sources(code, changed_lines, "test.py")
        assert any(s.source_category == "http_param" for s in sources)

    def test_detects_stdin_source(self, tmp_path):
        extractor = CodeContextExtractor(tmp_path)
        code = "name = input('Enter name: ')"
        changed_lines = {1}
        sources = extractor._find_sources(code, changed_lines, "test.py")
        assert any(s.source_category == "stdin" for s in sources)


class TestSanitizerDetection:
    def test_sanitizer_keyword_detected(self, tmp_path):
        from aegisdiff.code_context.models import DataFlowEdge

        extractor = CodeContextExtractor(tmp_path)
        edges = [
            DataFlowEdge(
                from_var="escape(user_input)",
                to_var="safe_value",
                file_path="test.py",
                line_number=5,
                operation="assign",
            )
        ]
        assert extractor._check_sanitizers(edges, "") is True

    def test_no_sanitizer_returns_false(self, tmp_path):
        from aegisdiff.code_context.models import DataFlowEdge

        extractor = CodeContextExtractor(tmp_path)
        edges = [
            DataFlowEdge(
                from_var="user_input",
                to_var="query",
                file_path="test.py",
                line_number=3,
                operation="assign",
            )
        ]
        assert extractor._check_sanitizers(edges, "") is False


class TestFullExtraction:
    def test_extract_from_diff_with_real_file(self, tmp_path, sample_diff):
        # Create the file that the diff references
        views_dir = tmp_path / "app"
        views_dir.mkdir()
        (views_dir / "views.py").write_text(
            "from django.http import HttpResponse\n"
            "from django.db import connection\n"
            "import os\n"
            "\n"
            "def get_user(request):\n"
            '    user_id = request.GET.get("id")\n'
            "    cursor = connection.cursor()\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            "    row = cursor.fetchone()\n"
            "    return HttpResponse(str(row))\n"
        )
        extractor = CodeContextExtractor(tmp_path)
        context = extractor.extract_from_diff(sample_diff)

        assert isinstance(context, CodeContext)
        assert "app/views.py" in context.changed_files
        assert len(context.raw_diff_snippet) > 0

    def test_extract_from_empty_diff(self, tmp_path, empty_diff):
        extractor = CodeContextExtractor(tmp_path)
        context = extractor.extract_from_diff(empty_diff)
        assert context.changed_files == []
        assert context.paths == []
