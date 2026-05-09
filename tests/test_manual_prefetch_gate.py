"""Unit tests for ``build_manual_file_cache`` — the manual entrypoint's
Phase-1 gated prefetch helper (F7).

The manual path runs in a checked-out repo so the extractor reads from
disk first; this helper only fetches Contents API content for files
that aren't on disk *and* survive Phase-1 classification into the
ANALYZE / DEPRIORITIZE buckets. SKIP and DEPENDENCY_ONLY files are
never fetched.

These tests run without respx — a tiny ``_FakeGHClient`` records every
path requested so we can assert which paths were fetched and which
weren't, against ``tmp_path`` standing in for the checked-out repo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from aegisdiff.entrypoint import build_manual_file_cache


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


class _FakeGHClient:
    """Minimal stand-in for ``GitHubClient`` for the manual prefetch loop.

    Matches the ``get_file_content(path, ref) -> Optional[str]`` shape
    that ``build_manual_file_cache`` relies on. Records every path
    requested. Returns content for paths that look like real code,
    ``None`` otherwise.
    """

    def __init__(self, returns_content_for: Optional[set[str]] = None) -> None:
        self.fetched_paths: list[str] = []
        self._returns_content_for = returns_content_for

    def get_file_content(self, path: str, ref: str) -> Optional[str]:
        self.fetched_paths.append(path)
        if self._returns_content_for is not None:
            if path not in self._returns_content_for:
                return None
        if path.endswith((".py", ".ts", ".js", ".go", ".rb", ".java")):
            return f"# fake content for {path}\n"
        return None


# ── Filtering: SKIP / DEPENDENCY_ONLY are never fetched ──────────────────


def test_skip_files_are_not_prefetched(tmp_path):
    raw = (
        _diff_block("README.md", ["Updated"])
        + _diff_block("docs/page.md", ["Updated"])
        + _diff_block("dist/bundle.js", ["console.log('built')"])
        + _diff_block("web/public/icon.svg", ["<svg/>"])
        + _diff_block("static/styles.min.css", [".x{color:red}"])
        + _diff_block("src/auth/login.py", ["def login(): pass"])
    )
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

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


def test_dependency_only_files_are_not_prefetched(tmp_path):
    raw = (
        _diff_block("package-lock.json", ['"version": "1.0.1"'])
        + _diff_block("yarn.lock", ['"resolved": "x"'])
        + _diff_block("poetry.lock", ['name = "foo"'])
        + _diff_block("Cargo.lock", ['name = "bar"'])
        + _diff_block("go.sum", ["foo v1.0.0"])
        + _diff_block("src/auth/login.py", ["def login(): pass"])
    )
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

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


# ── Disk-first: present-on-disk files are NOT fetched ────────────────────


def test_disk_first_wins_over_fetch(tmp_path):
    """A file that exists in the checked-out repo (under repo_root)
    must NOT be fetched — the extractor reads disk first anyway, so a
    Contents API call would be wasted and the cache would lose."""
    auth_file = tmp_path / "src" / "auth" / "login.py"
    auth_file.parent.mkdir(parents=True)
    auth_file.write_text("def login(): pass\n")

    raw = _diff_block("src/auth/login.py", ["def login(): return None"])
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert client.fetched_paths == []
    assert cache == {}


def test_off_disk_analyze_files_are_fetched(tmp_path):
    """When a path is ANALYZE and NOT present on disk, the helper
    fetches once and caches the content."""
    raw = (
        _diff_block("src/auth/login.py", ["def login(): pass"])
        + _diff_block("src/api/users.py", ["def list_users(): pass"])
    )
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert sorted(client.fetched_paths) == ["src/api/users.py", "src/auth/login.py"]
    assert "src/auth/login.py" in cache
    assert "src/api/users.py" in cache


def test_off_disk_deprioritize_files_are_fetched(tmp_path):
    """Test files (DEPRIORITIZE) are still fetched when off disk —
    the engine may still analyze them once analyze-priority files are
    covered, so we want their content available."""
    raw = (
        _diff_block("src/auth/login.py", ["def login(): pass"])
        + _diff_block("tests/test_auth.py", ["def test_login(): pass"])
    )
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert "tests/test_auth.py" in client.fetched_paths
    assert "tests/test_auth.py" in cache


def test_mixed_on_disk_and_off_disk_only_fetches_off_disk(tmp_path):
    """Correctness check on the full filtering chain: disk-first AND
    Phase-1 gate together. Auth file is on disk → not fetched. Helper
    file is off disk → fetched. Docs file is off disk → still skipped
    by Phase-1."""
    on_disk = tmp_path / "src" / "auth" / "login.py"
    on_disk.parent.mkdir(parents=True)
    on_disk.write_text("# already here\n")

    raw = (
        _diff_block("src/auth/login.py", ["def login(): pass"])
        + _diff_block("src/utils/helper.py", ["def helper(): pass"])
        + _diff_block("docs/api.md", ["docs"])
    )
    client = _FakeGHClient()

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert client.fetched_paths == ["src/utils/helper.py"]
    assert "src/utils/helper.py" in cache
    assert "src/auth/login.py" not in cache  # served from disk by extractor
    assert "docs/api.md" not in cache  # SKIP


# ── Edge cases ────────────────────────────────────────────────────────────


def test_returns_empty_dict_when_github_client_is_none(tmp_path):
    """No token / repo configured → no fetcher available → empty cache."""
    raw = _diff_block("src/auth/login.py", ["def login(): pass"])
    cache = build_manual_file_cache(raw, tmp_path, None, "abc1234")
    assert cache == {}


def test_returns_empty_dict_on_empty_diff(tmp_path):
    client = _FakeGHClient()
    assert build_manual_file_cache("", tmp_path, client, "abc1234") == {}
    assert build_manual_file_cache("   \n  ", tmp_path, client, "abc1234") == {}
    assert client.fetched_paths == []


def test_falls_back_to_regex_when_split_returns_empty(tmp_path):
    """For diff shapes the splitter doesn't recognise (no ``diff --git``
    header — e.g. a raw ``+++``-style diff), the helper falls back to
    the legacy regex extractor so we don't silently drop unusual diffs.
    """
    raw_no_diff_header = (
        "--- a/src/auth/login.py\n"
        "+++ b/src/auth/login.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        "+def login(): pass\n"
    )
    client = _FakeGHClient()
    cache = build_manual_file_cache(raw_no_diff_header, tmp_path, client, "abc1234")

    assert client.fetched_paths == ["src/auth/login.py"]
    assert "src/auth/login.py" in cache


def test_fetch_returning_none_is_not_cached(tmp_path):
    """If the Contents API returns ``None`` (binary, 404, too large,
    decode failure) the helper records the attempt but does not pollute
    the cache with a ``None`` value — extractor's lazy fetcher can
    still try later if needed."""
    # FakeGHClient returns None for non-code paths; force one such case.
    client = _FakeGHClient(returns_content_for=set())  # always returns None
    raw = _diff_block("src/auth/login.py", ["def login(): pass"])

    cache = build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert client.fetched_paths == ["src/auth/login.py"]
    assert cache == {}  # None content not cached


def test_passes_commit_sha_through_to_get_file_content(tmp_path):
    """The helper must use the caller's ``commit_sha`` as the ref so we
    fetch the exact tree the PR head points at, not a stale main."""
    captured: list[str] = []

    class _RefRecordingClient:
        def get_file_content(self, path: str, ref: str) -> Optional[str]:
            captured.append(ref)
            return "content"

    raw = _diff_block("src/auth/login.py", ["def login(): pass"])
    build_manual_file_cache(raw, tmp_path, _RefRecordingClient(), "deadbeef" * 5)

    assert captured == ["deadbeef" * 5]


def test_changed_file_paths_preserve_diff_order(tmp_path):
    """Iteration order is the order the diff splitter returns paths in,
    matching what the engine sees later — keeps output deterministic."""
    raw = (
        _diff_block("z.py", ["x = 1"])
        + _diff_block("a.py", ["y = 2"])
        + _diff_block("m.py", ["z = 3"])
    )
    client = _FakeGHClient()

    build_manual_file_cache(raw, tmp_path, client, "abc1234")

    assert client.fetched_paths == ["z.py", "a.py", "m.py"]
