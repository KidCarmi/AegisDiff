"""Unit tests for the Phase-1 prefetch gate in app_entrypoint.py.

The GitHub App path used to eagerly call ``GitHub Contents API`` for
*every* changed file before classification ran, wasting traffic on
docs / generated / static / lockfile changes that are never analyzed.
After F3 hardening the prefetch loop runs Phase-1 classification first
and only fetches files in the ``ANALYZE`` / ``DEPRIORITIZE`` buckets.

These tests exercise the loop in isolation with a fake ``app_client``,
so they're independent of the wider ``main()`` plumbing and run fast
without respx.
"""

from __future__ import annotations

import re
from typing import Optional

from aegisdiff.triage.engine import TriageEngine
from aegisdiff.triage.file_classifier import Decision, classify_files


def _diff_block(path: str, lines: list[str]) -> str:
    body = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,1 +1,{len(lines) + 1} @@\n"
        f" import os\n"
        f"{body}\n"
    )


class _FakeAppClient:
    """Minimal stand-in for ``GitHubAppClient`` used by the prefetch loop.

    Records every path that ``get_file_content`` is asked for, so tests
    can assert which paths were fetched and which weren't.
    """

    def __init__(self) -> None:
        self.fetched_paths: list[str] = []

    def get_file_content(
        self,
        token: str,
        owner: str,
        repo: str,
        path: str,
        ref: str,
    ) -> Optional[str]:
        self.fetched_paths.append(path)
        # Return content for files that look like real code; None for
        # the rest. This shape matches the real client's contract.
        if path.endswith((".py", ".ts", ".js", ".go")):
            return f"# fake content for {path}\n"
        return None


def _run_prefetch(raw_diff: str, app_client: _FakeAppClient) -> dict:
    """Run *only* the prefetch loop from ``app_entrypoint.main`` against a
    diff and a fake app client. Mirrors the production code path
    one-to-one (same splitter, same classifier, same gate).
    """
    file_chunks = TriageEngine._split_diff_by_file(raw_diff)
    changed_file_paths = [path for path, _diff in file_chunks]
    if not changed_file_paths:
        changed_file_paths = re.findall(r"^\+\+\+ b/(.+)$", raw_diff, re.MULTILINE)

    classifications = classify_files(changed_file_paths)
    worth_fetching = {
        c.path for c in classifications if c.decision in (Decision.ANALYZE, Decision.DEPRIORITIZE)
    }

    file_cache: dict = {}
    for fp in changed_file_paths:
        if fp not in worth_fetching:
            continue
        content = app_client.get_file_content(
            token="t",
            owner="acme",
            repo="webapp",
            path=fp,
            ref="abc1234",
        )
        if content is not None:
            file_cache[fp] = content

    return file_cache


# ── Tests ─────────────────────────────────────────────────────────────────


def test_skip_files_are_not_prefetched():
    """Docs / generated / static / minified files must never reach the
    Contents API."""
    raw = (
        _diff_block("README.md", ["Updated section"])
        + _diff_block("docs/page.md", ["Documentation update"])
        + _diff_block("dist/bundle.js", ["console.log('built')"])
        + _diff_block("web/public/icon.svg", ["<svg/>"])
        + _diff_block("static/styles.min.css", [".x{color:red}"])
        + _diff_block("src/auth/login.py", ["def login(): pass"])
    )
    client = _FakeAppClient()
    cache = _run_prefetch(raw, client)

    assert client.fetched_paths == ["src/auth/login.py"]
    assert "src/auth/login.py" in cache
    for forbidden in (
        "README.md",
        "docs/page.md",
        "dist/bundle.js",
        "web/public/icon.svg",
        "static/styles.min.css",
    ):
        assert forbidden not in client.fetched_paths
        assert forbidden not in cache


def test_dependency_only_files_are_not_prefetched():
    """Lockfiles bucket as DEPENDENCY_ONLY → no Contents API fetch."""
    raw = (
        _diff_block("package-lock.json", ['"version": "1.0.1"'])
        + _diff_block("yarn.lock", ['"resolved": "x"'])
        + _diff_block("poetry.lock", ['name = "foo"'])
        + _diff_block("Cargo.lock", ['name = "bar"'])
        + _diff_block("go.sum", ["foo v1.0.0/go.mod h1:abc"])
        + _diff_block("src/auth/login.py", ["def login(): pass"])
    )
    client = _FakeAppClient()
    cache = _run_prefetch(raw, client)

    assert client.fetched_paths == ["src/auth/login.py"]
    for lockfile in (
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
    ):
        assert lockfile not in client.fetched_paths
        assert lockfile not in cache


def test_analyze_files_are_prefetched_in_input_order():
    """Files in the ANALYZE bucket get fetched, preserving diff order."""
    raw = (
        _diff_block("src/auth/login.py", ["def login(): pass"])
        + _diff_block("src/api/users.py", ["def list_users(): pass"])
        + _diff_block("src/db/connection.py", ["def connect(): pass"])
    )
    client = _FakeAppClient()
    cache = _run_prefetch(raw, client)

    assert client.fetched_paths == [
        "src/auth/login.py",
        "src/api/users.py",
        "src/db/connection.py",
    ]
    assert len(cache) == 3


def test_deprioritized_files_are_prefetched():
    """Test files (DEPRIORITIZE) are still fetched — the engine may run
    them once analyze-priority files are covered."""
    raw = _diff_block("src/auth/login.py", ["def login(): pass"]) + _diff_block(
        "tests/test_auth.py", ["def test_login(): pass"]
    )
    client = _FakeAppClient()
    cache = _run_prefetch(raw, client)

    assert "tests/test_auth.py" in client.fetched_paths
    assert "tests/test_auth.py" in cache


def test_mixed_28_file_pr_only_fetches_analyze_and_deprioritize():
    """End-to-end shape of the Large PR fixture used in the E2E tests:
    1 auth (analyze) + 12 docs (skip) + 8 generated (skip) + 3 assets
    (skip) + 1 lockfile (dep_only) + 1 test (deprio) + 2 utils (analyze)
    = 28 files, but only 4 fetches.
    """
    parts = [_diff_block("src/auth/login.py", ["def login(): pass"])]
    parts += [_diff_block(f"docs/page_{i}.md", [f"Updated {i}"]) for i in range(12)]
    parts += [_diff_block(f"dist/bundle_{i}.js", [f"console.log({i})"]) for i in range(8)]
    parts += [_diff_block(f"web/public/asset_{i}.svg", ["<svg/>"]) for i in range(3)]
    parts += [_diff_block("package-lock.json", ['"version": "1.0.1"'])]
    parts += [_diff_block("tests/test_module.py", ["def test_x(): pass"])]
    parts += [
        _diff_block(f"src/utils/helper_{i}.py", [f"def helper_{i}(): pass"]) for i in range(2)
    ]
    raw = "".join(parts)

    # Sanity: 28 files in the diff.
    assert raw.count("diff --git ") == 28

    client = _FakeAppClient()
    cache = _run_prefetch(raw, client)

    # Only the 4 ANALYZE + DEPRIORITIZE files get fetched.
    assert len(client.fetched_paths) == 4, (
        f"prefetch gate broken: expected 4 fetches, got {len(client.fetched_paths)} "
        f"({client.fetched_paths})"
    )
    expected = {
        "src/auth/login.py",
        "src/utils/helper_0.py",
        "src/utils/helper_1.py",
        "tests/test_module.py",
    }
    assert set(client.fetched_paths) == expected
    assert set(cache) == {p for p in expected if p.endswith(".py")}


def test_empty_diff_does_not_fetch_anything():
    """No diff → no fetches."""
    client = _FakeAppClient()
    cache = _run_prefetch("", client)
    assert client.fetched_paths == []
    assert cache == {}


def test_prefetch_gate_is_path_metadata_only_no_diff_content_required():
    """The classifier looks only at path tokens — diff content is never
    inspected during the gate. Verified by classifying paths directly
    and confirming the same decision shape regardless of body."""
    paths = [
        "src/auth/login.py",
        "docs/x.md",
        "dist/bundle.js",
        "package-lock.json",
        "tests/test_x.py",
    ]
    classifications = classify_files(paths)
    decisions = {c.path: c.decision for c in classifications}
    assert decisions["src/auth/login.py"] == Decision.ANALYZE
    assert decisions["docs/x.md"] == Decision.SKIP
    assert decisions["dist/bundle.js"] == Decision.SKIP
    assert decisions["package-lock.json"] == Decision.DEPENDENCY_ONLY
    assert decisions["tests/test_x.py"] == Decision.DEPRIORITIZE
