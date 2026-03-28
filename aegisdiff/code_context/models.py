"""Data models for code context extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Sink:
    """A dangerous function call or data landing point in the code."""

    file_path: str
    line_number: int
    function_name: str
    argument_expressions: List[str]
    sink_category: str  # "sql_exec" | "cmd_exec" | "file_write" | "deserialize"
    raw_code: str
    # Set when an `# aegisdiff-ignore` comment suppresses this sink
    suppressed: bool = False
    ignore_cwe: Optional[str] = None  # e.g. "CWE-89"
    ignore_reason: Optional[str] = None  # free-text reason from the comment


@dataclass
class Source:
    """A user-controlled input entry point."""

    file_path: str
    line_number: int
    variable_name: str
    source_category: str  # "http_param" | "env_var" | "file_read" | "stdin"
    raw_code: str


@dataclass
class DataFlowEdge:
    """A single step in the taint propagation path."""

    from_var: str
    to_var: str
    file_path: str
    line_number: int
    operation: str  # "assign" | "concat" | "format" | "return" | "arg_pass"


@dataclass
class DataFlowPath:
    """A complete source → sink taint path, optionally sanitized."""

    source: Source
    sink: Sink
    edges: List[DataFlowEdge] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizer_description: Optional[str] = None


@dataclass
class CodeContext:
    """Everything the LLM needs to analyze a security finding."""

    diff_summary: str
    changed_files: List[str]
    paths: List[DataFlowPath]
    raw_diff_snippet: str  # Actual +/- lines, capped at 200 lines
    supporting_context: str  # ±25 lines of surrounding unchanged code
    imported_definitions: str = ""  # Function bodies fetched from imported local files
