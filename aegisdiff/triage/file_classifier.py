"""
Deterministic per-file classification used by Large PR Risk Triage Mode.

The classifier never calls an LLM and never touches the filesystem — it
operates purely on the file path string. Classification decides whether a
changed file is worth sending to the LLM at all, and if so how to rank it
against other changed files when budget is tight.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


class Decision(str, Enum):
    """What the engine should do with a changed file."""

    ANALYZE = "analyze"
    DEPRIORITIZE = "deprioritize"
    SKIP = "skip"
    DEPENDENCY_ONLY = "dependency_only"


@dataclass
class FileClassification:
    path: str
    decision: Decision
    risk_score: int = 0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
        }


# ── Skip rules ────────────────────────────────────────────────────────────
# Order: docs/assets/generated/minified are skipped *before* keyword scoring
# so an asset path that incidentally contains a risk keyword still skips.

_DOC_BASENAMES = {"readme", "license", "licence", "copying", "notice", "changelog", "authors"}
_DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".adoc")

_GENERATED_DIR_SEGMENTS = {
    "dist",
    "build",
    "coverage",
    "node_modules",
    "vendor",
    "target",
    "out",
    ".next",
    ".nuxt",
}

_ASSET_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
)

_MINIFIED_RE = re.compile(r"\.min\.(js|css|mjs|cjs)$", re.IGNORECASE)

# ── Dependency-only files ─────────────────────────────────────────────────

_LOCKFILE_BASENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "pipfile.lock",
    "gemfile.lock",
}

# ── Test detection (deprioritize, not skip) ───────────────────────────────

_TEST_DIR_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs"}
_TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]+|[^/]+_test|[^/]+\.test|[^/]+\.spec)\."
    r"(py|js|jsx|ts|tsx|mjs|cjs|go|java|rb|cs|php)$",
    re.IGNORECASE,
)

# ── Risk keyword scoring ──────────────────────────────────────────────────
# Score is path-substring based, case-insensitive, deterministic. Each
# matched keyword adds its weight; the total is capped at 100.

_BASE_ANALYZE_SCORE = 25  # neutral application file
_BASE_DEPRIORITIZE_SCORE = 10  # test files
_RISK_SCORE_CAP = 100

# Tier weights, applied per matched keyword.
_KEYWORD_WEIGHTS: Tuple[Tuple[int, Tuple[str, ...]], ...] = (
    # High-risk: auth & secrets directly compromise the system
    (
        20,
        (
            "auth",
            "login",
            "session",
            "jwt",
            "token",
            "permission",
            "rbac",
            "payment",
            "billing",
            "secret",
        ),
    ),
    # Medium-risk: request handlers, persistence, integrations, uploads
    (
        15,
        (
            "api",
            "route",
            "controller",
            "handler",
            "db",
            "query",
            "sql",
            "webhook",
            "upload",
        ),
    ),
    # Lower-risk but still security-relevant
    (
        10,
        (
            "file",
            "path",
            "network",
            "request",
            "fetch",
            "http",
            "config",
            "env",
        ),
    ),
)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _path_segments(path: str) -> List[str]:
    return [seg for seg in path.split("/") if seg]


def _is_doc(path: str) -> bool:
    p = path.lower()
    if p.endswith(_DOC_SUFFIXES):
        return True
    base = _basename(p)
    stem = base.rsplit(".", 1)[0] if "." in base else base
    if stem in _DOC_BASENAMES:
        return True
    segs = _path_segments(p)
    return "docs" in segs or "doc" in segs


def _is_generated(path: str) -> bool:
    segs = _path_segments(path.lower())
    return any(seg in _GENERATED_DIR_SEGMENTS for seg in segs)


def _is_asset(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_minified(path: str) -> bool:
    return bool(_MINIFIED_RE.search(path))


def _is_lockfile(path: str) -> bool:
    return _basename(path).lower() in _LOCKFILE_BASENAMES


def _is_test(path: str) -> bool:
    if _TEST_FILE_RE.search(path):
        return True
    segs = _path_segments(path.lower())
    return any(seg in _TEST_DIR_SEGMENTS for seg in segs)


# Tokens are runs of [a-z0-9]; everything else (including "/", "_", "-",
# ".", whitespace, punctuation) is a token boundary. This is what gives
# the classifier its "match whole word, not arbitrary substring" property:
# "src/authors/x.py" tokenises to {"src", "authors", "x", "py"} so the
# keyword "auth" no longer matches.
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _tokenize(path: str) -> set:
    """Split a path into a set of normalised lowercase alphanumeric tokens.

    Examples:
        "src/auth/login.py"      → {"src", "auth", "login", "py"}
        "src/path/user_file.py"  → {"src", "path", "user", "file", "py"}
        "src/authors/svc.py"     → {"src", "authors", "svc", "py"}
        "src/pathology/model.py" → {"src", "pathology", "model", "py"}
    """
    return {t for t in _TOKEN_SPLIT_RE.split(path.lower()) if t}


def _score_keywords(path: str) -> Tuple[int, List[str]]:
    """Return (added_score, matched_keywords) for the given path.

    Keywords are matched as *whole tokens*, not substrings — so
    ``pathology`` does not match ``path``, ``authors`` does not match
    ``auth``, ``filecoin`` does not match ``file``, etc. Tokens are
    produced by splitting on any non-alphanumeric character (``/``, ``_``,
    ``-``, ``.``, whitespace, …), so compound names like ``user_file`` or
    ``orders_controller`` still match each of their underlying tokens.
    """
    tokens = _tokenize(path)
    added = 0
    matched: List[str] = []
    seen: set = set()
    for weight, keywords in _KEYWORD_WEIGHTS:
        for kw in keywords:
            if kw in tokens and kw not in seen:
                added += weight
                matched.append(kw)
                seen.add(kw)
    return added, matched


def classify_file(path: str) -> FileClassification:
    """Classify a single changed file path.

    Decision precedence:
      1. ``skip`` — docs, generated/build folders, static assets, minified files.
      2. ``dependency_only`` — package/dependency lockfiles.
      3. ``deprioritize`` — test/spec files.
      4. ``analyze`` — everything else, scored by risk keywords.

    The first matching rule wins, so an asset that happens to live under
    ``api/`` still skips, and a lockfile inside a generated folder still
    skips (generated wins over lockfile by precedence).
    """
    if not path or not path.strip():
        return FileClassification(
            path=path,
            decision=Decision.SKIP,
            risk_score=0,
            reasons=["empty_path"],
        )

    # 1. Skip rules — applied before keyword scoring on purpose so an
    # asset like `web/public/api-icon.svg` doesn't get treated as risky.
    if _is_doc(path):
        return FileClassification(path, Decision.SKIP, 0, ["docs"])
    if _is_minified(path):
        return FileClassification(path, Decision.SKIP, 0, ["minified"])
    if _is_asset(path):
        return FileClassification(path, Decision.SKIP, 0, ["static_asset"])
    if _is_generated(path):
        return FileClassification(path, Decision.SKIP, 0, ["generated"])

    # 2. Dependency-only — lockfiles still get tracked but don't go through
    # normal LLM analysis. Phase 2+ may run a dedicated SCA-style check.
    if _is_lockfile(path):
        return FileClassification(
            path,
            Decision.DEPENDENCY_ONLY,
            risk_score=0,
            reasons=["lockfile"],
        )

    # 3. Tests — deprioritized so they only get analyzed if budget remains
    # after real production code.
    if _is_test(path):
        return FileClassification(
            path,
            Decision.DEPRIORITIZE,
            risk_score=_BASE_DEPRIORITIZE_SCORE,
            reasons=["test_file"],
        )

    # 4. Analyze — base score + keyword bonuses, capped at 100.
    added, matched = _score_keywords(path)
    score = min(_BASE_ANALYZE_SCORE + added, _RISK_SCORE_CAP)
    reasons = ["application_code"]
    reasons.extend(f"keyword:{kw}" for kw in matched)
    return FileClassification(
        path=path,
        decision=Decision.ANALYZE,
        risk_score=score,
        reasons=reasons,
    )


def classify_files(paths: List[str]) -> List[FileClassification]:
    """Classify a list of paths, preserving input order."""
    return [classify_file(p) for p in paths]
