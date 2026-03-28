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


class TestIgnoreSuppression:
    """aegisdiff-ignore comment detection in _find_sinks."""

    def _make_extractor(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_ignore_on_same_line(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        lines = ['cursor.execute(query)  # aegisdiff-ignore: CWE-89 reason: test only']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 0)
        assert suppressed is True
        assert cwe == "CWE-89"
        assert reason == "test only"

    def test_ignore_on_line_above(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        lines = ['# aegisdiff-ignore: CWE-89', 'cursor.execute(query)']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 1)
        assert suppressed is True
        assert cwe == "CWE-89"

    def test_ignore_no_cwe_no_reason(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        lines = ['# aegisdiff-ignore', 'cursor.execute(query)']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 1)
        assert suppressed is True
        assert cwe is None
        assert reason is None

    def test_no_ignore_comment(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        lines = ['# some other comment', 'cursor.execute(query)']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 1)
        assert suppressed is False

    def test_suppressed_sink_in_full_extraction(self, tmp_path):
        """Sinks annotated with aegisdiff-ignore are marked suppressed=True."""
        views_dir = tmp_path / "app"
        views_dir.mkdir()
        (views_dir / "views.py").write_text(
            "from django.db import connection\n"
            "\n"
            "def get_user(request):\n"
            '    user_id = request.GET.get("id")\n'
            "    cursor = connection.cursor()\n"
            "    # aegisdiff-ignore: CWE-89 reason: parameterized in prod\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        )
        diff = (
            "diff --git a/app/views.py b/app/views.py\n"
            "--- a/app/views.py\n"
            "+++ b/app/views.py\n"
            "@@ -1,7 +1,7 @@\n"
            "+from django.db import connection\n"
            "+\n"
            "+def get_user(request):\n"
            '+    user_id = request.GET.get("id")\n'
            "+    cursor = connection.cursor()\n"
            "+    # aegisdiff-ignore: CWE-89 reason: parameterized in prod\n"
            '+    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        )
        extractor = CodeContextExtractor(tmp_path)
        context = extractor.extract_from_diff(diff)
        suppressed_sinks = [p.sink for p in context.paths if p.sink.suppressed]
        assert len(suppressed_sinks) >= 1
        assert suppressed_sinks[0].ignore_cwe == "CWE-89"
        assert suppressed_sinks[0].ignore_reason == "parameterized in prod"


class TestJSTSSinkDetection:
    """JavaScript/TypeScript sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    # ── Sinks ────────────────────────────────────────────────────────────

    def test_detects_db_query_sink(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const rows = await db.query(`SELECT * FROM users WHERE id=${userId}`)'
        sinks = ext._find_sinks(code, {1}, "routes/users.ts")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_exec_sink(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const out = execSync(`ls ${userDir}`)'
        sinks = ext._find_sinks(code, {1}, "utils.js")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_inner_html_xss(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'el.innerHTML = req.query.html'
        sinks = ext._find_sinks(code, {1}, "app.ts")
        assert any(s.sink_category == "xss" for s in sinks)

    def test_detects_eval_sink(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'eval(req.body.code)'
        sinks = ext._find_sinks(code, {1}, "handler.js")
        assert any(s.sink_category == "eval_exec" for s in sinks)

    def test_detects_fetch_ssrf(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const resp = await fetch(req.query.url)'
        sinks = ext._find_sinks(code, {1}, "proxy.ts")
        assert any(s.sink_category == "ssrf" for s in sinks)

    def test_detects_fs_read_file(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const data = fs.readFileSync(req.params.path)'
        sinks = ext._find_sinks(code, {1}, "files.js")
        assert any(s.sink_category == "file_ops" for s in sinks)

    def test_detects_open_redirect(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'res.redirect(req.query.next)'
        sinks = ext._find_sinks(code, {1}, "auth.ts")
        assert any(s.sink_category == "redirect" for s in sinks)

    # ── Safe patterns (should NOT be flagged) ────────────────────────────

    def test_prisma_find_not_flagged(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const user = await prisma.user.findUnique({ where: { id } })'
        sinks = ext._find_sinks(code, {1}, "api.ts")
        assert len(sinks) == 0

    def test_mongoose_find_not_flagged(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const docs = await Model.findOne({ email: email })'
        sinks = ext._find_sinks(code, {1}, "db.ts")
        assert len(sinks) == 0

    # ── Sources ──────────────────────────────────────────────────────────

    def test_detects_req_body_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const { name } = req.body'
        sources = ext._find_sources(code, {1}, "handler.js")
        assert any(s.source_category == "req_param" for s in sources)

    def test_detects_url_search_params(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'const id = new URLSearchParams(location.search).get("id")'
        sources = ext._find_sources(code, {1}, "client.ts")
        assert any(s.source_category == "url_param" for s in sources)

    # ── aegisdiff-ignore with // syntax ─────────────────────────────────

    def test_js_ignore_comment_slash_slash(self, tmp_path):
        ext = self._ext(tmp_path)
        lines = ['// aegisdiff-ignore: CWE-79 reason: sanitized upstream',
                 'el.innerHTML = value']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 1)
        assert suppressed is True
        assert cwe == "CWE-79"
        assert reason == "sanitized upstream"

    def test_js_ignore_inline(self, tmp_path):
        ext = self._ext(tmp_path)
        lines = ['el.innerHTML = value  // aegisdiff-ignore']
        suppressed, cwe, reason = ext._check_ignore_comment(lines, 0)
        assert suppressed is True


class TestGoSinkDetection:
    """Go sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_detects_db_query(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'rows, err := db.Query("SELECT * FROM users WHERE id = " + id)'
        sinks = ext._find_sinks(code, {1}, "main.go")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_exec_command(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'cmd := exec.Command("sh", "-c", userInput)'
        sinks = ext._find_sinks(code, {1}, "runner.go")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_fmt_sprintf_sql(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'query := fmt.Sprintf("SELECT * FROM users WHERE name=\'%s\'", name)'
        sinks = ext._find_sinks(code, {1}, "db.go")
        assert any(s.sink_category == "fmt_sprintf_sql" for s in sinks)

    def test_detects_http_get_ssrf(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'resp, err := http.Get(targetURL)'
        sinks = ext._find_sinks(code, {1}, "proxy.go")
        assert any(s.sink_category == "ssrf" for s in sinks)

    def test_detects_r_form_value_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'name := r.FormValue("name")'
        sources = ext._find_sources(code, {1}, "handler.go")
        assert any(s.source_category == "http_param" for s in sources)


class TestJavaSinkDetection:
    """Java sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_detects_execute_query(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);'
        sinks = ext._find_sinks(code, {1}, "UserDao.java")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_runtime_exec(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'Runtime.getRuntime().exec(userInput);'
        sinks = ext._find_sinks(code, {1}, "Cmd.java")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_object_input_stream(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());'
        sinks = ext._find_sinks(code, {1}, "Handler.java")
        assert any(s.sink_category == "deserialize" for s in sinks)

    def test_detects_request_get_parameter_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'String id = request.getParameter("id");'
        sources = ext._find_sources(code, {1}, "Servlet.java")
        assert any(s.source_category == "request_param" for s in sources)

    def test_detects_request_param_annotation(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'public String search(@RequestParam String query) {'
        sources = ext._find_sources(code, {1}, "Controller.java")
        assert any(s.source_category == "annotation_param" for s in sources)


class TestRubySinkDetection:
    """Ruby sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_detects_find_by_sql(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'User.find_by_sql("SELECT * FROM users WHERE name=\'#{params[:name]}\'")'
        sinks = ext._find_sinks(code, {1}, "users_controller.rb")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_system_cmd(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "system(\"ls #{params[:dir]}\")"
        sinks = ext._find_sinks(code, {1}, "jobs.rb")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_eval(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "eval(params[:code])"
        sinks = ext._find_sinks(code, {1}, "runner.rb")
        assert any(s.sink_category == "eval_exec" for s in sinks)

    def test_detects_marshal_load(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "obj = Marshal.load(raw_data)"
        sinks = ext._find_sinks(code, {1}, "deserializer.rb")
        assert any(s.sink_category == "deserialize" for s in sinks)

    def test_detects_redirect_to(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "redirect_to(params[:next])"
        sinks = ext._find_sinks(code, {1}, "auth_controller.rb")
        assert any(s.sink_category == "redirect" for s in sinks)

    def test_detects_params_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "name = params[:name]"
        sources = ext._find_sources(code, {1}, "controller.rb")
        assert any(s.source_category == "http_param" for s in sources)

    def test_safe_hash_where_not_flagged(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "User.where(email: email)"
        sinks = ext._find_sinks(code, {1}, "user.rb")
        assert len(sinks) == 0


class TestPHPSinkDetection:
    """PHP sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_detects_mysqli_query(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET["id"]);'
        sinks = ext._find_sinks(code, {1}, "users.php")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_shell_exec(self, tmp_path):
        ext = self._ext(tmp_path)
        code = '$output = shell_exec("ls " . $_GET["dir"]);'
        sinks = ext._find_sinks(code, {1}, "files.php")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_eval(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "eval($_POST['code']);"
        sinks = ext._find_sinks(code, {1}, "admin.php")
        assert any(s.sink_category == "eval_exec" for s in sinks)

    def test_detects_unserialize(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "$obj = unserialize($_COOKIE['data']);"
        sinks = ext._find_sinks(code, {1}, "session.php")
        assert any(s.sink_category == "deserialize" for s in sinks)

    def test_detects_get_superglobal_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "$name = $_GET['name'];"
        sources = ext._find_sources(code, {1}, "index.php")
        assert any(s.source_category == "superglobal" for s in sources)

    def test_detects_post_superglobal_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "$data = $_POST['payload'];"
        sources = ext._find_sources(code, {1}, "api.php")
        assert any(s.source_category == "superglobal" for s in sources)

    def test_prepared_statement_not_flagged(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');"
        sinks = ext._find_sinks(code, {1}, "db.php")
        assert len(sinks) == 0


class TestCSharpSinkDetection:
    """C# sink and source pattern coverage."""

    def _ext(self, tmp_path):
        return CodeContextExtractor(tmp_path)

    def test_detects_sql_command(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=" + id, conn);'
        sinks = ext._find_sinks(code, {1}, "UserRepo.cs")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_execute_reader(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "var reader = cmd.ExecuteReader();"
        sinks = ext._find_sinks(code, {1}, "Db.cs")
        assert any(s.sink_category == "sql_exec" for s in sinks)

    def test_detects_process_start(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "Process.Start(userInput);"
        sinks = ext._find_sinks(code, {1}, "Runner.cs")
        assert any(s.sink_category == "cmd_exec" for s in sinks)

    def test_detects_response_redirect(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "Response.Redirect(Request.QueryString[\"next\"]);"
        sinks = ext._find_sinks(code, {1}, "Auth.cs")
        assert any(s.sink_category == "redirect" for s in sinks)

    def test_detects_html_raw_xss(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "@Html.Raw(Model.UserInput)"
        sinks = ext._find_sinks(code, {1}, "View.cs")
        assert any(s.sink_category == "xss" for s in sinks)

    def test_detects_xml_document_xxe(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "var doc = new XmlDocument(); doc.Load(inputStream);"
        sinks = ext._find_sinks(code, {1}, "Parser.cs")
        assert any(s.sink_category == "xxe" for s in sinks)

    def test_detects_request_querystring_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'var id = Request.QueryString["id"];'
        sources = ext._find_sources(code, {1}, "Controller.cs")
        assert any(s.source_category == "request_param" for s in sources)

    def test_detects_from_query_annotation_source(self, tmp_path):
        ext = self._ext(tmp_path)
        code = "public IActionResult Search([FromQuery] string q) {"
        sources = ext._find_sources(code, {1}, "ApiController.cs")
        assert any(s.source_category == "annotation_param" for s in sources)

    def test_sql_parameter_not_flagged(self, tmp_path):
        ext = self._ext(tmp_path)
        code = 'cmd.Parameters.AddWithValue("@id", userId);'
        sinks = ext._find_sinks(code, {1}, "Db.cs")
        assert len(sinks) == 0
