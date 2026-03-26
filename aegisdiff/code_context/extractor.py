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

from .models import (
    CodeContext,
    DataFlowEdge,
    DataFlowPath,
    Sink,
    Source,
)

logger = logging.getLogger(__name__)

# Matches: # aegisdiff-ignore[: CWE-NNN] [reason: ...]
# CWE and reason are both optional.  Examples:
#   # aegisdiff-ignore
#   # aegisdiff-ignore: CWE-89
#   # aegisdiff-ignore: CWE-89 reason: test fixture only
_IGNORE_RE = re.compile(
    r"#\s*aegisdiff-ignore"
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


class CodeContextExtractor:
    """
    Extracts a CodeContext from a unified diff and the surrounding repository.

    Args:
        repo_root: Path to the root of the checked-out repository.
        language: Primary programming language to parse (default: "python").
    """

    def __init__(self, repo_root: Path, language: str = "python") -> None:
        self._repo_root = repo_root
        self._language = language
        self._ts_parser = self._load_tree_sitter(language)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_diff(self, raw_diff: str) -> CodeContext:
        """Main entry point: diff string → CodeContext."""
        changed_files, changed_lines = self._parse_diff(raw_diff)
        all_paths: List[DataFlowPath] = []

        for file_path, line_ranges in changed_lines.items():
            abs_path = self._repo_root / file_path
            if not abs_path.exists() or not abs_path.is_file():
                logger.debug("Skipping non-existent file: %s", file_path)
                continue
            try:
                source_code = abs_path.read_text(errors="replace")
            except OSError as e:
                logger.warning("Cannot read %s: %s", file_path, e)
                continue

            paths = self._extract_paths(source_code, line_ranges, file_path)
            all_paths.extend(paths)

        snippet = self._extract_diff_snippet(raw_diff, max_lines=200)
        context = self._extract_surrounding_context(changed_lines, max_lines_per_file=30)

        return CodeContext(
            diff_summary=self._summarize_diff(raw_diff, changed_files),
            changed_files=changed_files,
            paths=all_paths,
            raw_diff_snippet=snippet,
            supporting_context=context,
        )

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
                sanitized = self._check_sanitizers(edges, source_code)
                san_desc = None
                if sanitized:
                    san_desc = self._describe_sanitizer(edges, source_code)
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

    def _find_sinks(
        self, source_code: str, changed_line_set: Set[int], file_path: str
    ) -> List[Sink]:
        lines = source_code.splitlines()
        sinks: List[Sink] = []
        for ln_idx, line in enumerate(lines):
            ln = ln_idx + 1
            if ln not in changed_line_set:
                continue
            # Skip ORM/framework safe patterns immediately
            if SAFE_ORM_PATTERNS.search(line):
                continue
            for category, pattern in PYTHON_SINK_PATTERNS.items():
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
            for category, pattern in PYTHON_SOURCE_PATTERNS.items():
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

    def _check_sanitizers(self, edges: List[DataFlowEdge], source_code: str) -> bool:
        """Return True if any edge passes through a known sanitizer."""
        for edge in edges:
            combined = (edge.from_var + " " + edge.to_var).lower()
            for kw in SANITIZER_KEYWORDS:
                if kw in combined:
                    return True
        return False

    def _describe_sanitizer(self, edges: List[DataFlowEdge], source_code: str) -> str:
        for edge in edges:
            combined = (edge.from_var + " " + edge.to_var).lower()
            for kw in SANITIZER_KEYWORDS:
                if kw in combined:
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
        max_lines_per_file: int = 30,
    ) -> str:
        contexts: List[str] = []
        for file_path, line_ranges in changed_lines.items():
            abs_path = self._repo_root / file_path
            if not abs_path.exists():
                continue
            try:
                all_lines = abs_path.read_text(errors="replace").splitlines()
            except OSError:
                continue
            context_line_set: Set[int] = set()
            for r in line_ranges:
                for ln in r:
                    for offset in range(-5, 6):
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
            from tree_sitter_languages import get_parser

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
