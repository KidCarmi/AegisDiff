"""Tests for the prompt builder."""
from __future__ import annotations

from aegisdiff.code_context.models import (
    CodeContext,
    DataFlowEdge,
    DataFlowPath,
    Sink,
    Source,
)
from aegisdiff.triage.prompts import APPSEC_SYSTEM_PROMPT, build_user_message


def make_context_with_path() -> CodeContext:
    source = Source(
        file_path="app/views.py",
        line_number=4,
        variable_name="user_id",
        source_category="http_param",
        raw_code='user_id = request.GET.get("id")',
    )
    sink = Sink(
        file_path="app/views.py",
        line_number=6,
        function_name="cursor.execute",
        argument_expressions=['f"SELECT * FROM users WHERE id = {user_id}"'],
        sink_category="sql_exec",
        raw_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )
    edge = DataFlowEdge(
        from_var='request.GET.get("id")',
        to_var="user_id",
        file_path="app/views.py",
        line_number=4,
        operation="assign",
    )
    path = DataFlowPath(source=source, sink=sink, edges=[edge], is_sanitized=False)
    return CodeContext(
        diff_summary="1 file changed, 4 insertions(+)",
        changed_files=["app/views.py"],
        paths=[path],
        raw_diff_snippet='+    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        supporting_context="   4 |     user_id = request.GET.get('id')\n   6 |     cursor.execute(...)",
    )


class TestSystemPrompt:
    def test_system_prompt_contains_mission(self):
        assert "DISPROVE" in APPSEC_SYSTEM_PROMPT

    def test_system_prompt_contains_verdict_schema(self):
        assert "TRUE_POSITIVE" in APPSEC_SYSTEM_PROMPT
        assert "FALSE_POSITIVE" in APPSEC_SYSTEM_PROMPT
        assert "NEEDS_REVIEW" in APPSEC_SYSTEM_PROMPT

    def test_system_prompt_contains_calibration_rules(self):
        assert "confidence" in APPSEC_SYSTEM_PROMPT.lower()
        assert "0.7" in APPSEC_SYSTEM_PROMPT

    def test_system_prompt_contains_anti_patterns(self):
        assert "ORM" in APPSEC_SYSTEM_PROMPT or "filter()" in APPSEC_SYSTEM_PROMPT


class TestUserMessageBuilder:
    def test_includes_data_flow_path(self):
        context = make_context_with_path()
        msg = build_user_message(context)
        assert "DATA FLOW PATH 1" in msg
        assert "sql_exec" in msg
        assert "http_param" in msg

    def test_includes_code_delimiters(self):
        context = make_context_with_path()
        msg = build_user_message(context)
        assert "<<<CODE>>>" in msg
        assert "<<<END_CODE>>>" in msg

    def test_includes_diff_summary(self):
        context = make_context_with_path()
        msg = build_user_message(context)
        assert "1 file changed" in msg

    def test_includes_raw_diff_snippet(self):
        context = make_context_with_path()
        msg = build_user_message(context)
        assert "cursor.execute" in msg

    def test_sanitized_path_marked(self):
        context = make_context_with_path()
        context.paths[0].is_sanitized = True
        context.paths[0].sanitizer_description = "bleach.clean() called"
        msg = build_user_message(context)
        assert "SANITIZED" in msg
        assert "bleach.clean()" in msg

    def test_empty_context_no_crash(self):
        context = CodeContext(
            diff_summary="0 files changed",
            changed_files=[],
            paths=[],
            raw_diff_snippet="",
            supporting_context="",
        )
        msg = build_user_message(context)
        assert isinstance(msg, str)
        assert len(msg) > 0
