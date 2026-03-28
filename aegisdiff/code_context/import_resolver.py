"""
Import resolver — extracts local function definitions from imported files.

Given taint paths from CodeContextExtractor, identifies which function calls
appear in data-flow edges, resolves them to local source files via import
statements, and extracts their body for injection into the LLM prompt.

This closes the cross-file sanitizer blindspot: if code calls sanitize_input()
from utils.py, the LLM sees the actual implementation, not just the name.

Hard limits (token budget):
  - Max 3 imported files resolved per analysis
  - Max 20 lines extracted per function body
  - Local imports only (stdlib/third-party skipped — LLM already knows them)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set

from .models import DataFlowPath

logger = logging.getLogger(__name__)

# Max files to resolve per scan (token budget guard)
MAX_IMPORTED_FILES = 3

# ── Known stdlib / well-known third-party top-level names ──────────────────

_PYTHON_STDLIB = frozenset(
    {
        "os",
        "sys",
        "re",
        "io",
        "abc",
        "ast",
        "csv",
        "json",
        "math",
        "time",
        "copy",
        "enum",
        "glob",
        "gzip",
        "hmac",
        "http",
        "html",
        "logging",
        "random",
        "shutil",
        "signal",
        "socket",
        "sqlite3",
        "string",
        "struct",
        "subprocess",
        "tempfile",
        "threading",
        "traceback",
        "typing",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "xml",
        "zipfile",
        "zlib",
        "base64",
        "collections",
        "contextlib",
        "dataclasses",
        "datetime",
        "decimal",
        "functools",
        "hashlib",
        "heapq",
        "inspect",
        "itertools",
        "operator",
        "pathlib",
        "pickle",
        "platform",
        "pprint",
        "queue",
        "secrets",
        "stat",
        "textwrap",
        "types",
        "weakref",
        "argparse",
        "configparser",
        "difflib",
        "importlib",
        "locale",
        "multiprocessing",
        "numbers",
        "pkgutil",
        "runpy",
        "sched",
        "ssl",
        "statistics",
        "tarfile",
        "unicodedata",
        "venv",
        "wave",
        # common third-party (LLM already knows these)
        "flask",
        "django",
        "fastapi",
        "sqlalchemy",
        "requests",
        "httpx",
        "pydantic",
        "celery",
        "redis",
        "boto3",
        "pytest",
        "click",
        "aiohttp",
        "starlette",
        "tornado",
        "bottle",
        "peewee",
        "jwt",
        "cryptography",
        "numpy",
        "pandas",
        "scipy",
        "sklearn",
        "tensorflow",
        "torch",
        "yaml",
        "toml",
        "dotenv",
        "sentry_sdk",
        "stripe",
        "twilio",
        "bleach",
        "markupsafe",
        "jinja2",
        "werkzeug",
        "wtforms",
    }
)

_GO_STDLIB = frozenset(
    {
        "fmt",
        "os",
        "io",
        "net",
        "log",
        "math",
        "sync",
        "sort",
        "time",
        "errors",
        "bytes",
        "bufio",
        "regexp",
        "strings",
        "strconv",
        "unicode",
        "runtime",
        "reflect",
        "context",
        "testing",
        "encoding",
        "database",
        "html",
        "http",
        "url",
        "path",
        "filepath",
        "archive",
        "compress",
        "crypto",
        "image",
        "mime",
        "text",
        "hash",
        "flag",
        "signal",
        "syscall",
    }
)

_JAVA_STDLIB_PREFIXES = (
    "java.",
    "javax.",
    "sun.",
    "com.sun.",
    "org.w3c.",
    "org.xml.",
    "org.springframework.",
    "com.fasterxml.",
    "org.apache.",
    "org.slf4j.",
    "com.google.",
    "io.micronaut.",
    "io.quarkus.",
)

_JS_BUILTINS = frozenset(
    {
        "console",
        "process",
        "Buffer",
        "Promise",
        "Error",
        "JSON",
        "Math",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Date",
        "RegExp",
        "Map",
        "Set",
        "Symbol",
        "Proxy",
        "Reflect",
        "globalThis",
    }
)


# ── Public API ───────────────────────────────────────────────────────────────


def extract_tainted_function_names(paths: List[DataFlowPath]) -> List[str]:
    """
    Return function names that appear in data-flow edges or sink calls.

    These are candidates for cross-file import resolution.
    """
    _skip = frozenset(
        {
            "if",
            "for",
            "while",
            "return",
            "not",
            "and",
            "or",
            "in",
            "is",
            "None",
            "True",
            "False",
            "len",
            "str",
            "int",
            "list",
            "dict",
            "set",
            "tuple",
            "print",
            "range",
            "type",
            "bool",
            "float",
            "bytes",
            "open",
            "super",
            "zip",
            "map",
            "filter",
            "sorted",
            "enumerate",
            "reversed",
            "hasattr",
            "getattr",
            "setattr",
            "isinstance",
            "issubclass",
        }
    )
    names: Set[str] = set()
    call_re = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")

    for path in paths:
        for edge in path.edges:
            for text in (edge.from_var, edge.to_var):
                for m in call_re.finditer(text):
                    name = m.group(1)
                    if name not in _skip and len(name) > 2:
                        names.add(name)
        # Include the sink function name (last segment after dots)
        sink_base = path.sink.function_name.split("(")[0].strip().split(".")[-1]
        if sink_base and len(sink_base) > 2:
            names.add(sink_base)

    return list(names)


def resolve_local_imports(
    source_code: str,
    func_names: List[str],
    file_path: str,
) -> Dict[str, str]:
    """
    Parse import statements in source_code and map func_names to candidate
    local file paths (capped at MAX_IMPORTED_FILES distinct files).

    Returns {func_name: candidate_file_path}.
    Skips stdlib and known third-party packages.
    """
    ext = Path(file_path).suffix.lower()
    if ext in (".py", ".pyw"):
        raw = _resolve_python(source_code, func_names, file_path)
    elif ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"):
        raw = _resolve_js(source_code, func_names, file_path)
    elif ext == ".go":
        raw = _resolve_go(source_code, func_names, file_path)
    elif ext == ".java":
        raw = _resolve_java(source_code, func_names, file_path)
    else:
        return {}

    # Cap distinct files
    seen_files: Set[str] = set()
    capped: Dict[str, str] = {}
    for name, fp in raw.items():
        if fp not in seen_files:
            if len(seen_files) >= MAX_IMPORTED_FILES:
                break
            seen_files.add(fp)
        capped[name] = fp

    return capped


def extract_function_definitions(
    file_content: str,
    func_names: List[str],
    file_path: str,
    max_lines_per_func: int = 20,
) -> str:
    """
    Extract function bodies for each name in func_names from file_content.

    Returns a formatted string ready for LLM prompt injection, or "" if
    nothing was found.
    """
    ext = Path(file_path).suffix.lower()
    found: List[str] = []
    for name in func_names:
        body = _extract_body(file_content, name, ext, max_lines_per_func)
        if body:
            found.append(f"# {file_path} — {name}()\n{body}")
            logger.debug("Extracted definition: %s from %s", name, file_path)

    return "\n\n".join(found)


# ── Language-specific import parsers ────────────────────────────────────────


def _resolve_python(source_code: str, func_names: List[str], file_path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    base_dir = str(Path(file_path).parent)

    # from .utils import sanitize, validate
    # from utils import sanitize
    from_re = re.compile(r"^from\s+(\.{0,2}[\w.]*)\s+import\s+(.+)$", re.MULTILINE)
    # import utils  (used as utils.func_name)
    import_re = re.compile(r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?", re.MULTILINE)

    for m in from_re.finditer(source_code):
        module = m.group(1).strip()
        top = module.lstrip(".").split(".")[0]
        if top in _PYTHON_STDLIB:
            continue

        candidate = _python_module_to_path(module, base_dir)
        if not candidate:
            continue

        imports_str = re.sub(r"[()\\]", "", m.group(2))
        imported = [n.split(" as ")[0].strip() for n in imports_str.split(",")]
        for name in imported:
            if name in func_names:
                result[name] = candidate

    for m in import_re.finditer(source_code):
        module, alias = m.group(1), m.group(2) or m.group(1).split(".")[0]
        top = module.split(".")[0]
        if top in _PYTHON_STDLIB:
            continue
        candidate = _python_module_to_path(module, base_dir)
        if not candidate:
            continue
        for name in func_names:
            if re.search(rf"\b{re.escape(alias)}\.{re.escape(name)}\s*\(", source_code):
                result[name] = candidate

    return result


def _python_module_to_path(module: str, base_dir: str) -> Optional[str]:
    if module.startswith(".."):
        return None  # two-level relative — skip
    if module.startswith("."):
        rel = module.lstrip(".")
        if not rel:
            return None
        parts = rel.replace(".", "/")
        path = f"{base_dir}/{parts}.py" if base_dir != "." else f"{parts}.py"
        return path.lstrip("/")
    parts = module.replace(".", "/")
    return f"{parts}.py"


def _resolve_js(source_code: str, func_names: List[str], file_path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}

    # import { a, b } from './path'  OR  import def from './path'
    # const { a } = require('./path')
    stmt_re = re.compile(
        r"(?:import\s+([\s\S]*?)\s+from\s*|"
        r"(?:const|let|var)\s+([\s\S]*?)\s*=\s*require\s*\()"
        r'[\'"]([./][^\'"]+)[\'"]',
        re.MULTILINE,
    )

    for m in stmt_re.finditer(source_code):
        rel = m.group(3)
        if not rel.startswith(("./", "../")):
            continue
        candidate = _js_resolve(rel, file_path)
        if not candidate:
            continue

        clause = m.group(1) or m.group(2) or ""
        # Extract named imports: { a, b as c }
        named = re.findall(r"\b(\w+)(?:\s+as\s+\w+)?", clause)
        for name in func_names:
            if name in named and name not in _JS_BUILTINS:
                result[name] = candidate

    return result


def _js_resolve(rel: str, importing_file: str) -> Optional[str]:
    base = PurePosixPath(importing_file).parent
    resolved = base / rel
    # Return without extension — caller tries GitHub API which handles it
    try:
        s = str(resolved)
        if not s.startswith(".."):
            # Add .js default if no extension
            if not Path(s).suffix:
                return s + ".js"
            return s
    except Exception:
        pass
    return None


def _resolve_go(source_code: str, func_names: List[str], file_path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    import_re = re.compile(r'"([^"]+)"')
    block_re = re.compile(r"import\s*\((.*?)\)", re.DOTALL)
    single_re = re.compile(r'import\s+"([^"]+)"')

    all_imports: List[str] = []
    for bm in block_re.finditer(source_code):
        all_imports.extend(import_re.findall(bm.group(1)))
    for sm in single_re.finditer(source_code):
        all_imports.append(sm.group(1))

    for imp in all_imports:
        parts = imp.split("/")
        # Skip stdlib (no dot in first segment, in known set)
        if "." not in parts[0] and parts[0] in _GO_STDLIB:
            continue
        pkg = parts[-1]
        for name in func_names:
            if re.search(rf"\b{re.escape(pkg)}\.{re.escape(name)}\s*\(", source_code):
                candidate = f"{imp}/{pkg}.go"
                result[name] = candidate

    return result


def _resolve_java(source_code: str, func_names: List[str], file_path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    import_re = re.compile(r"^import\s+(?:static\s+)?([\w.]+);", re.MULTILINE)

    for m in import_re.finditer(source_code):
        fqn = m.group(1)
        if any(fqn.startswith(p) for p in _JAVA_STDLIB_PREFIXES):
            continue
        class_name = fqn.split(".")[-1]
        path = f"src/main/java/{fqn.replace('.', '/')}.java"
        for name in func_names:
            if name == class_name or re.search(
                rf"\b{re.escape(class_name)}\.{re.escape(name)}\s*\(", source_code
            ):
                result[name] = path

    return result


# ── Function body extractors ────────────────────────────────────────────────


def _extract_body(source: str, func_name: str, ext: str, max_lines: int) -> Optional[str]:
    if ext in (".py", ".pyw", ".rb"):
        return _python_body(source, func_name, max_lines)
    if ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"):
        return _brace_body(source, func_name, max_lines, "js")
    if ext == ".go":
        return _brace_body(source, func_name, max_lines, "go")
    if ext == ".java":
        return _brace_body(source, func_name, max_lines, "java")
    return None


def _python_body(source: str, func_name: str, max_lines: int) -> Optional[str]:
    lines = source.splitlines()
    func_re = re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(func_name)}\s*\(")
    for i, line in enumerate(lines):
        if not func_re.match(line):
            continue
        indent = len(line) - len(line.lstrip())
        body = [line]
        for j in range(i + 1, min(i + max_lines + 1, len(lines))):
            nxt = lines[j]
            if nxt.strip() == "":
                body.append(nxt)
                continue
            if len(nxt) - len(nxt.lstrip()) <= indent and nxt.strip():
                break
            body.append(nxt)
        if len(body) >= max_lines:
            body.append("    # [...truncated]")
        return "\n".join(body)
    return None


def _brace_body(source: str, func_name: str, max_lines: int, lang: str) -> Optional[str]:
    if lang == "js":
        pat = re.compile(
            rf"(?:function\s+{re.escape(func_name)}\s*\("
            rf"|(?:const|let|var)\s+{re.escape(func_name)}\s*=\s*(?:async\s+)?(?:function\s*)?\("
            rf"|{re.escape(func_name)}\s*[=:]\s*(?:async\s+)?\()",
        )
    elif lang == "go":
        pat = re.compile(rf"func\s+(?:\([^)]+\)\s+)?{re.escape(func_name)}\s*\(")
    else:  # java
        pat = re.compile(
            rf"(?:public|private|protected|static|\s)+\s+\w[\w<>\[\]]*\s+{re.escape(func_name)}\s*\("
        )

    lines = source.splitlines()
    for i, line in enumerate(lines):
        if not pat.search(line):
            continue
        body: List[str] = []
        depth = 0
        for j in range(i, min(i + max_lines + 1, len(lines))):
            body.append(lines[j])
            stripped = re.sub(r'(["\']).*?\1', "", lines[j])
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0 and j > i:
                break
        if len(body) >= max_lines:
            body.append("  // [...truncated]")
        return "\n".join(body)
    return None
