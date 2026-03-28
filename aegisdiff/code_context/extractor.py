"""
Code Context Extractor — diff → AST → sinks/sources → CodeContext.

Strategy:
1. Parse the unified diff to find changed line ranges per file.
2. For each changed file, run tree-sitter to build an AST.
3. Query the AST for:
   a. SINK patterns — calls to dangerous functions within changed lines.
   b. SOURCE patterns — user-input reads in the same function scope.
4. Walk variable assignments between source and sink lines.
5. Check for sanitizer patterns in the data-flow edges.
6. Package everything into a CodeContext for the LLM.

Falls back to regex heuristics when tree-sitter is unavailable.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .import_resolver import (
    extract_function_definitions,
    extract_tainted_function_names,
    resolve_local_imports,
)
from .models import (
    CodeContext,
    DataFlowEdge,
    DataFlowPath,
    Sink,
    Source,
)

logger = logging.getLogger(__name__)

# Matches aegisdiff-ignore in any comment style:
#   Python/Ruby/Shell:  # aegisdiff-ignore: CWE-89 reason: test only
#   JS/TS/Go/Java/C:   // aegisdiff-ignore: CWE-89 reason: test only
# CWE and reason are both optional.
_IGNORE_RE = re.compile(
    r"(?:#|//)\s*aegisdiff-ignore"
    r"(?:\s*:\s*(?P<cwe>CWE-\d+))?"
    r"(?:\s+reason\s*:\s*(?P<reason>.+?))?$",
    re.IGNORECASE,
)

# ── Sink query patterns (tree-sitter query syntax) ─────────────────────────

PYTHON_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "sql_exec": re.compile(
        r"\b(execute|executemany|raw|extra)\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\b(os\.system|subprocess\.(run|call|Popen|check_output)|popen)\s*\(",
        re.IGNORECASE,
    ),
    "file_write": re.compile(
        r"\.(write|writelines)\s*\(",
        re.IGNORECASE,
    ),
    "deserialize": re.compile(
        r"\b(pickle\.loads?|yaml\.load|marshal\.loads?|eval|exec)\s*\(",
        re.IGNORECASE,
    ),
    "template_render": re.compile(
        r"\b(render_template_string|Template\()\s*",
        re.IGNORECASE,
    ),
}

PYTHON_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "http_param": re.compile(
        r"\b(request\.(args|form|json|data|params|get_json|values|files|GET|POST|PUT|PATCH|body)"
        r"|flask\.request|bottle\.request\.params"
        r"|self\.request\.(GET|POST|DATA|body))\b",
        re.IGNORECASE,
    ),
    "stdin": re.compile(r"\binput\s*\(", re.IGNORECASE),
    "env_var": re.compile(r"\bos\.environ\b|os\.getenv\s*\(", re.IGNORECASE),
}

# Sanitizer keywords: if any assignment edge contains these, mark as sanitized
SANITIZER_KEYWORDS = [
    "escape",
    "sanitize",
    "validate",
    "parameterize",
    "quote",
    "htmlspecialchars",
    "bleach",
    "markupsafe",
    "encode",
    "strip_tags",
    "prepared_statement",
    "bindparam",
    "literal_column",
    "text(",
]

# ORM/framework patterns that are safe by default (FALSE_POSITIVE hints)
SAFE_ORM_PATTERNS = re.compile(
    r"\.(filter|filter_by|where|select_related|prefetch_related"
    r"|annotate|aggregate|order_by|values_list)\s*\(",
    re.IGNORECASE,
)

# ── JavaScript / TypeScript patterns ───────────────────────────────────────

JS_TS_SINK_PATTERNS: Dict[str, re.Pattern] = {
    # SQL — raw query methods (parameterized equivalents are safe)
    "sql_exec": re.compile(
        r"\b(db|pool|client|connection|knex|sequelize)\s*\.\s*(query|execute|raw)\s*\(",
        re.IGNORECASE,
    ),
    # OS command execution
    "cmd_exec": re.compile(
        r"\b(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("
        r"|child_process\.(exec|spawn)\s*\(",
        re.IGNORECASE,
    ),
    # XSS sinks
    "xss": re.compile(
        r"\.(innerHTML|outerHTML)\s*="
        r"|dangerouslySetInnerHTML"
        r"|\bdocument\.write\s*\("
        r"|\$\(.*\)\.(html|append|prepend|after|before|replaceWith)\s*\(",
        re.IGNORECASE,
    ),
    # eval / dynamic code execution
    "eval_exec": re.compile(
        r"\beval\s*\("
        r"|new\s+Function\s*\("
        r"|\bvm\.(runInNewContext|runInThisContext|Script)\s*\(",
        re.IGNORECASE,
    ),
    # SSRF — outbound HTTP with user-controlled URL
    "ssrf": re.compile(
        r"\b(fetch|axios\.get|axios\.post|axios\.request|axios\.put|axios\.delete"
        r"|http\.get|http\.request|https\.get|https\.request|got|superagent|request)\s*\(",
        re.IGNORECASE,
    ),
    # Path traversal / file operations
    "file_ops": re.compile(
        r"\b(fs\.readFile|fs\.readFileSync|fs\.writeFile|fs\.writeFileSync"
        r"|fs\.open|fs\.unlink|fs\.rename|readFileSync|writeFileSync)\s*\(",
        re.IGNORECASE,
    ),
    # Template injection
    "template_render": re.compile(
        r"\b(ejs\.render|ejs\.renderFile|Handlebars\.compile|nunjucks\.render"
        r"|pug\.render|_.template|jade\.render)\s*\(",
        re.IGNORECASE,
    ),
    # Open redirect
    "redirect": re.compile(
        r"\bres\.(redirect|location)\s*\(",
        re.IGNORECASE,
    ),
}

JS_TS_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "req_param": re.compile(
        r"\b(req|request)\s*\.\s*(body|query|params|cookies|headers"
        r"|files|file|fields|param|get|post)\b",
        re.IGNORECASE,
    ),
    "url_param": re.compile(
        r"\b(new URLSearchParams|location\.search|location\.hash"
        r"|window\.location|document\.location|searchParams\.get)\b",
        re.IGNORECASE,
    ),
    "env_var": re.compile(r"\bprocess\.env\b", re.IGNORECASE),
    "event_input": re.compile(
        r"\bevent\.(target|currentTarget)\.(value|checked|innerHTML)\b"
        r"|\bdocument\.(getElementById|querySelector)\s*\([^)]+\)\.(value|innerHTML)\b",
        re.IGNORECASE,
    ),
}

# Prisma / Sequelize / Mongoose / TypeORM methods are parameterized by default
SAFE_JS_PATTERNS = re.compile(
    r"\b(prisma|db)\s*\.\s*\w+\s*\.\s*(findMany|findFirst|findUnique|findOne|create|update|upsert|delete|count)\s*\("
    r"|\.(findAll|findOne|findByPk|findById|findOneAndUpdate|countDocuments|aggregate)\s*\("
    r"|\b(res\.json|res\.send|res\.status|next)\s*\(",
    re.IGNORECASE,
)

JS_SANITIZER_KEYWORDS = [
    "domPurify",
    "dompurify",
    "sanitizeHtml",
    "sanitize_html",
    "encodeURIComponent",
    "encodeURI",
    "escape",
    "validator.escape",
    "xss(",
    "sanitize(",
    "htmlspecialchars",
    "entities.encode",
    "prepared",
    "parameterized",
    "placeholder",
    "bcrypt",
    "crypto.createHash",
]

# ── Go patterns ────────────────────────────────────────────────────────────

GO_SINK_PATTERNS: Dict[str, re.Pattern] = {
    # Require db/conn/tx receiver to avoid false-positives on url.Query()
    "sql_exec": re.compile(
        r"\b(db|conn|tx|stmt|sqlDB|sqlConn)\.(Query|QueryRow|QueryContext|Exec|ExecContext|Prepare)\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\bexec\.Command\s*\(",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"\bhttp\.(Get|Post|Head|Do|NewRequest)\s*\(",
        re.IGNORECASE,
    ),
    "file_ops": re.compile(
        r"\b(os\.(Open|Create|OpenFile|Remove|Rename)|ioutil\.ReadFile|ioutil\.WriteFile"
        r"|os\.ReadFile|os\.WriteFile)\s*\(",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"\btemplate\.HTML\s*\("
        r"|\bfmt\.(Fprintf|Fprint|Fprintln)\s*\(.*ResponseWriter",
        re.IGNORECASE,
    ),
    "fmt_sprintf_sql": re.compile(
        r'\bfmt\.Sprintf\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
        re.IGNORECASE,
    ),
}

GO_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "http_param": re.compile(
        r"\b(r\.URL\.Query\(\)|r\.FormValue|r\.PostFormValue"
        r"|r\.Header\.Get|r\.Body"
        r"|c\.Param|c\.Query|c\.PostForm"  # Gin
        r"|chi\.URLParam)\s*\(?",
        re.IGNORECASE,
    ),
    "env_var": re.compile(r"\bos\.Getenv\s*\(", re.IGNORECASE),
}

SAFE_GO_PATTERNS = re.compile(
    r"\bdb\.Prepare\s*\(|sqlx\.NamedQuery|squirrel\.",
    re.IGNORECASE,
)

# ── Java patterns ──────────────────────────────────────────────────────────

JAVA_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "sql_exec": re.compile(
        r"\.(executeQuery|executeUpdate|execute|addBatch)\s*\("
        r"|\bcreateQuery\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\bRuntime\.getRuntime\(\)\.exec\s*\("
        r"|\bnew\s+ProcessBuilder\s*\(",
        re.IGNORECASE,
    ),
    "deserialize": re.compile(
        r"\bnew\s+ObjectInputStream\s*\("
        r"|\bXMLDecoder\s*\("
        r"|\bYaml\.load\s*\(",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"response\.(getWriter|getOutputStream)\(\)\.(write|print|println)\s*\(",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"response\.sendRedirect\s*\(",
        re.IGNORECASE,
    ),
    "xxe": re.compile(
        r"\bDocumentBuilderFactory\.newInstance\s*\("
        r"|\bSAXParserFactory\.newInstance\s*\(",
        re.IGNORECASE,
    ),
}

JAVA_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "request_param": re.compile(
        r"\brequest\.(getParameter|getAttribute|getHeader|getQueryString"
        r"|getCookies|getInputStream|getReader)\s*\(",
        re.IGNORECASE,
    ),
    "annotation_param": re.compile(
        r"@\s*(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\b",
        re.IGNORECASE,
    ),
}

SAFE_JAVA_PATTERNS = re.compile(
    r"\bPreparedStatement\b|\bparameterized\b|\bNamedParameterJdbcTemplate\b"
    r"|\bHibernate\b|\bEntityManager\.createQuery\b",
    re.IGNORECASE,
)

# ── Ruby patterns ──────────────────────────────────────────────────────────

RUBY_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "sql_exec": re.compile(
        r"\b(find_by_sql|execute|exec_query|connection\.execute"
        r"|where\s*\(\s*[\"'][^\"']*#\{)"  # string-interpolated where()
        r"|\bActiveRecord::Base\.connection\.(execute|query)\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\b(system|exec|spawn|IO\.popen|Open3\.popen|Kernel\.system)\s*\("
        r"|`[^`]+`"  # backtick execution
        r"|%x\{",
        re.IGNORECASE,
    ),
    "eval_exec": re.compile(
        r"\b(eval|instance_eval|class_eval|module_eval)\s*\(",
        re.IGNORECASE,
    ),
    "deserialize": re.compile(
        r"\bMarshal\.load\s*\("
        r"|\bYAML\.load\s*\("  # safe_load is OK; load is not
        r"|\bERB\.new\s*\(",
        re.IGNORECASE,
    ),
    "file_ops": re.compile(
        r"\b(File\.(open|read|write|delete|rename)|IO\.read|open\s*\()\s*",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"\bredirect_to\s*\(",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"\b(Net::HTTP\.(get|post|start)|Faraday\.new|HTTParty\.(get|post)|open-uri)\b"
        r"|\bURI\.open\s*\(",
        re.IGNORECASE,
    ),
}

RUBY_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "http_param": re.compile(
        r"\bparams\s*[\[:]"
        r"|\brequest\.(params|query_string|body|env|GET|POST|headers)\b"
        r"|\bcookies\s*\["
        r"|\bsession\s*\[",
        re.IGNORECASE,
    ),
    "env_var": re.compile(r"\bENV\s*\[", re.IGNORECASE),
}

SAFE_RUBY_PATTERNS = re.compile(
    r"\bwhere\s*\(\s*[\w:]+\s*:"  # hash-syntax where (safe)
    r"|\bsanitize\b|\bescape_sql\b|\bquote\s*\(",
    re.IGNORECASE,
)

# ── PHP patterns ───────────────────────────────────────────────────────────

PHP_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "sql_exec": re.compile(
        r"\b(mysql_query|mysqli_query|pg_query|mssql_query"
        r"|PDO::query|\$pdo\s*->\s*(query|exec|prepare)"
        r"|\$db\s*->\s*(query|execute)"
        r"|\$conn\s*->\s*query)\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\b(exec|system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\("
        r"|`[^`]+`",  # backtick shell execution
        re.IGNORECASE,
    ),
    "file_include": re.compile(
        r"\b(include|require|include_once|require_once)\s*[(\s]",
        re.IGNORECASE,
    ),
    "file_ops": re.compile(
        r"\b(file_get_contents|file_put_contents|fopen|readfile|file\s*\()\s*\(",
        re.IGNORECASE,
    ),
    "eval_exec": re.compile(
        r"\beval\s*\(",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"\b(echo|print|printf|vprintf|print_r|var_dump)\s+\$"
        r"|\bheader\s*\(\s*[\"']Location:",
        re.IGNORECASE,
    ),
    "deserialize": re.compile(
        r"\bunserialize\s*\(",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"\bheader\s*\(\s*[\"']Location:",
        re.IGNORECASE,
    ),
}

PHP_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "superglobal": re.compile(
        r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|SESSION)\b",
        re.IGNORECASE,
    ),
    "filter_input": re.compile(
        r"\bfilter_input\s*\(",
        re.IGNORECASE,
    ),
}

SAFE_PHP_PATTERNS = re.compile(
    r"\bprepare\s*\(|\bbindParam\b|\bbindValue\b"
    r"|\bhtmlspecialchars\s*\(|\bhtmlentities\s*\("
    r"|\bintval\s*\(|\bfloatval\s*\(|\bstrip_tags\s*\(",
    re.IGNORECASE,
)

PHP_SANITIZER_KEYWORDS = [
    "htmlspecialchars",
    "htmlentities",
    "strip_tags",
    "addslashes",
    "intval",
    "floatval",
    "filter_var",
    "prepared",
    "bindParam",
    "bindValue",
    "escape",
    "sanitize",
]

# ── C# patterns ────────────────────────────────────────────────────────────

CSHARP_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "sql_exec": re.compile(
        r"\b(SqlCommand|OleDbCommand|OdbcCommand|NpgsqlCommand)\s*\("
        r"|\.(ExecuteReader|ExecuteNonQuery|ExecuteScalar|ExecuteQuery)\s*\("
        r"|\bFromSqlRaw\s*\(|\bDatabase\.ExecuteSqlRaw\s*\(",
        re.IGNORECASE,
    ),
    "cmd_exec": re.compile(
        r"\bProcess\.Start\s*\("
        r"|\bnew\s+ProcessStartInfo\s*\(",
        re.IGNORECASE,
    ),
    "deserialize": re.compile(
        r"\b(BinaryFormatter|NetDataContractSerializer|ObjectStateFormatter"
        r"|LosFormatter|JavaScriptSerializer)\s*\(\s*\)\s*\.(Deserialize|Deserialize)\s*\("
        r"|\bXmlSerializer\b.*\.Deserialize\s*\("
        r"|\bJsonConvert\.DeserializeObject\s*\(",
        re.IGNORECASE,
    ),
    "file_ops": re.compile(
        r"\b(File\.(ReadAllText|WriteAllText|ReadAllBytes|WriteAllBytes|Open|Create|Delete)"
        r"|new\s+FileStream\s*\("
        r"|Path\.Combine\s*\()\s*\(",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"\bResponse\.Write\s*\("
        r"|\bHtml\.Raw\s*\("
        r"|\bMvcHtmlString\.Create\s*\(",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"\bResponse\.Redirect\s*\("
        r"|\breturn\s+Redirect\s*\("
        r"|\breturn\s+RedirectToAction\s*\(",
        re.IGNORECASE,
    ),
    "xxe": re.compile(
        r"\bnew\s+XmlDocument\s*\(\s*\)"
        r"|\bXmlReader\.Create\s*\("
        r"|\bXDocument\.Load\s*\(",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"\bnew\s+HttpClient\s*\(\s*\)"
        r"|\bWebClient\.(DownloadString|DownloadData|OpenRead)\s*\("
        r"|\bHttpWebRequest\.Create\s*\(",
        re.IGNORECASE,
    ),
}

CSHARP_SOURCE_PATTERNS: Dict[str, re.Pattern] = {
    "request_param": re.compile(
        r"\bRequest\.(QueryString|Form|Params|Headers|Cookies|Body|Path)\b"
        r"|\bHttpContext\.Request\b"
        r"|\bContext\.Request\b",
        re.IGNORECASE,
    ),
    "annotation_param": re.compile(
        r"\[From(Query|Body|Route|Header|Form|Services)\]",
        re.IGNORECASE,
    ),
    "env_var": re.compile(
        r"\bEnvironment\.GetEnvironmentVariable\s*\("
        r"|\bConfiguration\[",
        re.IGNORECASE,
    ),
}

SAFE_CSHARP_PATTERNS = re.compile(
    r"\bSqlParameter\b|\bParameters\.AddWithValue\b|\bParameters\.Add\b"
    r"|\bHtmlEncoder\.Encode\b|\bWebUtility\.HtmlEncode\b"
    r"|\bEntityFramework\b|\bDbContext\b",
    re.IGNORECASE,
)

CSHARP_SANITIZER_KEYWORDS = [
    "HtmlEncode",
    "HtmlEncoder",
    "WebUtility.HtmlEncode",
    "AntiXssEncoder",
    "SqlParameter",
    "Parameters.Add",
    "escape",
    "sanitize",
    "validate",
    "Regex.IsMatch",
]

# ── File extension → language mapping ─────────────────────────────────────

_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
}


class CodeContextExtractor:
    """
    Extracts a CodeContext from a unified diff and the surrounding repository.

    Args:
        repo_root: Path to the root of the checked-out repository.
        language: Primary programming language to parse (default: "python").
        file_cache: Optional dict mapping file paths to their full text content.
                    Used when the repo is not checked out (e.g. GitHub App path).
    """

    def __init__(
        self,
        repo_root: Path,
        language: str = "python",
        file_cache: Optional[Dict[str, str]] = None,
        file_fetcher: Optional[callable] = None,
    ) -> None:
        self._repo_root = repo_root
        self._language = language
        self._file_cache = file_cache or {}
        # Optional callable(path: str) -> Optional[str] for fetching files
        # not on disk and not already in file_cache (e.g. imported files).
        self._file_fetcher = file_fetcher
        self._ts_parser = self._load_tree_sitter(language)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_diff(self, raw_diff: str) -> CodeContext:
        """Main entry point: diff string → CodeContext."""
        changed_files, changed_lines = self._parse_diff(raw_diff)
        all_paths: List[DataFlowPath] = []

        for file_path, line_ranges in changed_lines.items():
            source_code = self._read_file(file_path)
            if source_code is None:
                continue
            paths = self._extract_paths(source_code, line_ranges, file_path)
            all_paths.extend(paths)

        snippet = self._extract_diff_snippet(raw_diff, max_lines=200)

        # Resolve cross-file imports only when sinks were found (has_paths).
        # When imported_definitions are present we tighten the surrounding
        # context window to keep total token count roughly constant.
        imported_definitions = ""
        if all_paths:
            imported_definitions = self._resolve_imported_definitions(all_paths, changed_lines)
        context_lines = 40 if imported_definitions else 120
        context = self._extract_surrounding_context(changed_lines, max_lines_per_file=context_lines)

        return CodeContext(
            diff_summary=self._summarize_diff(raw_diff, changed_files),
            changed_files=changed_files,
            paths=all_paths,
            raw_diff_snippet=snippet,
            supporting_context=context,
            imported_definitions=imported_definitions,
        )

    # ------------------------------------------------------------------
    # File reading (disk-first, cache fallback)
    # ------------------------------------------------------------------

    def _read_file(self, file_path: str) -> Optional[str]:
        """
        Return the text of file_path, trying the checked-out repo first,
        then the file_cache (populated by the GitHub App path from the
        GitHub Contents API).  Returns None if unavailable.
        """
        abs_path = self._repo_root / file_path
        if abs_path.exists() and abs_path.is_file():
            try:
                return abs_path.read_text(errors="replace")
            except OSError as exc:
                logger.warning("Cannot read %s from disk: %s", file_path, exc)
        if file_path in self._file_cache:
            logger.debug("Using cached content for %s", file_path)
            return self._file_cache[file_path]
        logger.debug("File not available (not on disk, not in cache): %s", file_path)
        return None

    # ------------------------------------------------------------------
    # Cross-file import resolution
    # ------------------------------------------------------------------

    def _resolve_imported_definitions(
        self,
        paths: List[DataFlowPath],
        changed_lines: Dict[str, List[range]],
    ) -> str:
        """
        For each function call in the taint paths, attempt to resolve it to a
        local imported file and extract its body. Returns a formatted string
        for LLM prompt injection, or "" if nothing was resolved.
        """
        func_names = extract_tainted_function_names(paths)
        if not func_names:
            return ""

        all_definitions: List[str] = []
        seen_files: set = set()

        for file_path in changed_lines:
            source_code = self._read_file(file_path)
            if not source_code:
                continue

            candidates = resolve_local_imports(source_code, func_names, file_path)
            if not candidates:
                continue

            for func_name, import_path in candidates.items():
                if import_path in seen_files:
                    continue
                # Fetch the imported file: cache → disk → file_fetcher
                content = self._file_cache.get(import_path)
                if content is None:
                    content = self._read_file(import_path)
                if content is None and self._file_fetcher is not None:
                    try:
                        content = self._file_fetcher(import_path)
                        if content:
                            self._file_cache[import_path] = content
                            logger.info("Fetched imported file for context: %s", import_path)
                    except Exception as exc:
                        logger.debug("file_fetcher failed for %s: %s", import_path, exc)

                if content is None:
                    logger.debug("Cannot resolve import: %s", import_path)
                    continue

                defs = extract_function_definitions(
                    content,
                    [func_name],
                    import_path,
                    max_lines_per_func=20,
                )
                if defs:
                    all_definitions.append(defs)
                    seen_files.add(import_path)

        return "\n\n".join(all_definitions)

    # ------------------------------------------------------------------
    # Diff parsing
    # ------------------------------------------------------------------

    def _parse_diff(self, raw_diff: str) -> Tuple[List[str], Dict[str, List[range]]]:
        """
        Parse a unified diff to extract changed files and the line ranges
        that were ADDED (not deleted) in each file.
        """
        changed_files: List[str] = []
        changed_lines: Dict[str, List[range]] = {}
        current_file: Optional[str] = None
        current_new_line = 0

        for line in raw_diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                if current_file not in changed_files:
                    changed_files.append(current_file)
                    changed_lines[current_file] = []
            elif line.startswith("@@ "):
                m = re.search(r"\+(\d+)(?:,(\d+))?", line)
                if m:
                    current_new_line = int(m.group(1))
            elif line.startswith("+") and not line.startswith("+++"):
                if current_file is not None:
                    changed_lines[current_file].append(
                        range(current_new_line, current_new_line + 1)
                    )
                    current_new_line += 1
                else:
                    logger.warning("Encountered added line before any file header — skipping")
            elif not line.startswith("-"):
                current_new_line += 1

        return changed_files, changed_lines

    # ------------------------------------------------------------------
    # Path extraction (sink + source + dataflow)
    # ------------------------------------------------------------------

    def _extract_paths(
        self,
        source_code: str,
        line_ranges: List[range],
        file_path: str,
    ) -> List[DataFlowPath]:
        """Extract data-flow paths from a single source file."""
        changed_line_set: Set[int] = set()
        for r in line_ranges:
            changed_line_set.update(r)

        sinks = self._find_sinks(source_code, changed_line_set, file_path)
        sources = self._find_sources(source_code, changed_line_set, file_path)

        if not sinks:
            return []

        _, _, _, extra_sanitizers = self._get_lang_patterns(file_path)
        paths: List[DataFlowPath] = []
        for sink in sinks:
            # Try to find a source that could taint this sink
            matching_sources = sources or [
                Source(
                    file_path=file_path,
                    line_number=0,
                    variable_name="<unknown>",
                    source_category="unknown",
                    raw_code="",
                )
            ]
            for src in matching_sources:
                edges = self._find_assignment_chain(source_code, src, sink, file_path)
                sanitized = self._check_sanitizers(edges, source_code, extra_sanitizers)
                san_desc = None
                if sanitized:
                    san_desc = self._describe_sanitizer(edges, source_code, extra_sanitizers)
                paths.append(
                    DataFlowPath(
                        source=src,
                        sink=sink,
                        edges=edges,
                        is_sanitized=sanitized,
                        sanitizer_description=san_desc,
                    )
                )
        return paths

    def _get_lang_patterns(self, file_path: str) -> tuple:
        """
        Return (sink_patterns, source_patterns, safe_pattern, extra_sanitizers)
        appropriate for the given file extension.
        """
        ext = Path(file_path).suffix.lower()
        lang = _EXT_TO_LANG.get(ext, "python")

        if lang in ("javascript", "typescript"):
            return (
                JS_TS_SINK_PATTERNS,
                JS_TS_SOURCE_PATTERNS,
                SAFE_JS_PATTERNS,
                JS_SANITIZER_KEYWORDS,
            )
        if lang == "go":
            return (GO_SINK_PATTERNS, GO_SOURCE_PATTERNS, SAFE_GO_PATTERNS, [])
        if lang == "java":
            return (JAVA_SINK_PATTERNS, JAVA_SOURCE_PATTERNS, SAFE_JAVA_PATTERNS, [])
        if lang == "ruby":
            return (RUBY_SINK_PATTERNS, RUBY_SOURCE_PATTERNS, SAFE_RUBY_PATTERNS, [])
        if lang == "php":
            return (
                PHP_SINK_PATTERNS, PHP_SOURCE_PATTERNS, SAFE_PHP_PATTERNS, PHP_SANITIZER_KEYWORDS
            )
        if lang == "csharp":
            return (
                CSHARP_SINK_PATTERNS,
                CSHARP_SOURCE_PATTERNS,
                SAFE_CSHARP_PATTERNS,
                CSHARP_SANITIZER_KEYWORDS,
            )
        # Default: Python
        return (PYTHON_SINK_PATTERNS, PYTHON_SOURCE_PATTERNS, SAFE_ORM_PATTERNS, [])

    def _find_sinks(
        self, source_code: str, changed_line_set: Set[int], file_path: str
    ) -> List[Sink]:
        sink_patterns, _, safe_pattern, _ = self._get_lang_patterns(file_path)
        lines = source_code.splitlines()
        sinks: List[Sink] = []
        for ln_idx, line in enumerate(lines):
            ln = ln_idx + 1
            if ln not in changed_line_set:
                continue
            # Skip ORM/framework safe patterns immediately
            if safe_pattern.search(line):
                continue
            for category, pattern in sink_patterns.items():
                if pattern.search(line):
                    m = pattern.search(line)
                    func_name = m.group(0).rstrip("(").strip() if m else "<unknown>"
                    # Check for aegisdiff-ignore on this line or the line above
                    suppressed, ignore_cwe, ignore_reason = self._check_ignore_comment(
                        lines, ln_idx
                    )
                    sinks.append(
                        Sink(
                            file_path=file_path,
                            line_number=ln,
                            function_name=func_name,
                            argument_expressions=self._extract_call_args(line),
                            sink_category=category,
                            raw_code=line.strip(),
                            suppressed=suppressed,
                            ignore_cwe=ignore_cwe,
                            ignore_reason=ignore_reason,
                        )
                    )
                    break  # One sink category per line is enough
        return sinks

    @staticmethod
    def _check_ignore_comment(
        lines: List[str], sink_idx: int
    ) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Look for an aegisdiff-ignore comment on the sink line or the line above.

        Returns (suppressed, cwe_id, reason).
        """
        candidates = [lines[sink_idx]]
        if sink_idx > 0:
            candidates.append(lines[sink_idx - 1])
        for candidate in candidates:
            m = _IGNORE_RE.search(candidate)
            if m:
                return True, m.group("cwe"), (m.group("reason") or "").strip() or None
        return False, None, None

    def _find_sources(
        self, source_code: str, changed_line_set: Set[int], file_path: str
    ) -> List[Source]:
        _, source_patterns, _, _ = self._get_lang_patterns(file_path)
        lines = source_code.splitlines()
        sources: List[Source] = []
        # Search a wider window: ±50 lines around changed lines
        search_lines: Set[int] = set()
        for ln in changed_line_set:
            for offset in range(-50, 51):
                search_lines.add(ln + offset)

        for ln_idx, line in enumerate(lines):
            ln = ln_idx + 1
            if ln not in search_lines:
                continue
            for category, pattern in source_patterns.items():
                if pattern.search(line):
                    # Extract the variable being assigned from this source
                    var_name = self._extract_assigned_var(line)
                    sources.append(
                        Source(
                            file_path=file_path,
                            line_number=ln,
                            variable_name=var_name,
                            source_category=category,
                            raw_code=line.strip(),
                        )
                    )
                    break
        return sources

    # ------------------------------------------------------------------
    # Data-flow tracing (simplified intraprocedural taint)
    # ------------------------------------------------------------------

    def _find_assignment_chain(
        self,
        source_code: str,
        src: Source,
        sink: Sink,
        file_path: str,
    ) -> List[DataFlowEdge]:
        """
        Walk variable assignments between src.line_number and sink.line_number.
        Returns a list of DataFlowEdge representing the taint path.
        """
        lines = source_code.splitlines()
        start = max(0, min(src.line_number, sink.line_number) - 1)
        end = min(len(lines), max(src.line_number, sink.line_number))
        edges: List[DataFlowEdge] = []
        assign_re = re.compile(r"^\s*(\w+)\s*(?:\+?=|:=)\s*(.+)")
        for ln_idx in range(start, end):
            ln = ln_idx + 1
            line = lines[ln_idx]
            m = assign_re.match(line)
            if m:
                edges.append(
                    DataFlowEdge(
                        from_var=m.group(2).strip(),
                        to_var=m.group(1),
                        file_path=file_path,
                        line_number=ln,
                        operation="assign",
                    )
                )
        return edges

    def _check_sanitizers(
        self,
        edges: List[DataFlowEdge],
        source_code: str,
        extra_keywords: Optional[List[str]] = None,
    ) -> bool:
        """Return True if any edge passes through a known sanitizer."""
        keywords = SANITIZER_KEYWORDS + (extra_keywords or [])
        for edge in edges:
            combined = (edge.from_var + " " + edge.to_var).lower()
            for kw in keywords:
                if kw.lower() in combined:
                    return True
        return False

    def _describe_sanitizer(
        self,
        edges: List[DataFlowEdge],
        source_code: str,
        extra_keywords: Optional[List[str]] = None,
    ) -> str:
        keywords = SANITIZER_KEYWORDS + (extra_keywords or [])
        for edge in edges:
            combined = (edge.from_var + " " + edge.to_var).lower()
            for kw in keywords:
                if kw.lower() in combined:
                    return f"Found '{kw}' in assignment chain at line {edge.line_number}"
        return "Sanitizer detected"

    # ------------------------------------------------------------------
    # Diff snippet + context helpers
    # ------------------------------------------------------------------

    def _extract_diff_snippet(self, raw_diff: str, max_lines: int = 200) -> str:
        relevant = [
            line
            for line in raw_diff.splitlines()
            if line.startswith(("+", "-", "@@", "diff", "---", "+++"))
        ]
        return "\n".join(relevant[:max_lines])

    def _extract_surrounding_context(
        self,
        changed_lines: Dict[str, List[range]],
        max_lines_per_file: int = 120,
    ) -> str:
        contexts: List[str] = []
        for file_path, line_ranges in changed_lines.items():
            source_code = self._read_file(file_path)
            if source_code is None:
                continue
            all_lines = source_code.splitlines()
            context_line_set: Set[int] = set()
            for r in line_ranges:
                for ln in r:
                    # ±25 lines around each changed line (was ±5)
                    for offset in range(-25, 26):
                        context_line_set.add(ln + offset)
            relevant = sorted(context_line_set & set(range(1, len(all_lines) + 1)))[
                :max_lines_per_file
            ]
            snippet = "\n".join(f"{ln:4d} | {all_lines[ln - 1]}" for ln in relevant)
            contexts.append(f"--- {file_path} ---\n{snippet}")
        return "\n\n".join(contexts)

    def _summarize_diff(self, raw_diff: str, changed_files: List[str]) -> str:
        file_count = len(changed_files)
        lines = raw_diff.splitlines()
        added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
        return f"{file_count} file(s) changed, {added} insertions(+), {removed} deletions(-)"

    # ------------------------------------------------------------------
    # Tree-sitter loader (optional, degrades to regex on ImportError)
    # ------------------------------------------------------------------

    def _load_tree_sitter(self, language: str):
        try:
            import warnings

            from tree_sitter_languages import get_parser

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                parser = get_parser(language)
            logger.debug("tree-sitter loaded for %s", language)
            return parser
        except (ImportError, Exception) as e:
            logger.info("tree-sitter not available (%s), using regex heuristics", e)
            return None

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _extract_call_args(self, line: str) -> List[str]:
        """Extract argument text from a function call line (best-effort)."""
        m = re.search(r"\(([^)]*)\)", line)
        if m:
            return [arg.strip() for arg in m.group(1).split(",") if arg.strip()]
        return []

    def _extract_assigned_var(self, line: str) -> str:
        """Extract the LHS variable name from an assignment line."""
        m = re.match(r"^\s*(\w+)\s*=", line)
        return m.group(1) if m else "<unknown>"
