"""
Real-GitHub integration test — live end-to-end PR scan.

Creates an actual PR on a dedicated test repo, injects deliberately vulnerable
code, runs the full AegisDiff engine with real credentials, and then verifies
ALL three outputs against real services:

  ✓ GitHub PR comment  — <!-- aegisdiff-report --> marker + TRUE_POSITIVE
  ✓ GitHub commit status — "failure" state, "AegisDiff / security" context
  ✓ Vercel dashboard   — POST /api/ingest stores it, GET /api/v1/scans returns it

Setup — one-time (see README):
  1. Create a dedicated test repo, e.g. KidCarmi/aegisdiff-integration-target
  2. Install the AegisDiff GitHub App on that repo
  3. Sign in to the dashboard, connect the test repo, copy its ingest token
  4. Create a v1 API key via GET /api/v1/key on the dashboard
  5. Add the 6 secrets below to KidCarmi/AegisDiff

Required secrets / environment variables
─────────────────────────────────────────
  INTEGRATION_TEST_GITHUB_TOKEN  — PAT with `repo` scope on the test repo
  INTEGRATION_TEST_REPO          — "owner/name"  e.g. KidCarmi/aegisdiff-integration-target
  INTEGRATION_INSTALLATION_ID    — GitHub App installation ID for the test repo
  GITHUB_APP_ID                  — AegisDiff GitHub App numeric ID (already in secrets)
  GITHUB_APP_PRIVATE_KEY         — RSA private key PEM (already in secrets)
  GITHUB_TOKEN                   — auto-injected by Actions; GitHub Models LLM fallback

Optional — enables real Vercel dashboard verification (highly recommended):
  AEGISDIFF_INGEST_URL           — https://your-app.vercel.app/api/ingest
  AEGISDIFF_INGEST_TOKEN         — per-repo ingest token (ak_...)
  INTEGRATION_DASHBOARD_URL      — https://your-app.vercel.app  (base URL, no trailing slash)
  INTEGRATION_API_KEY            — v1 REST API key (ak_...) for GET /api/v1/scans read-back

The test is automatically SKIPPED when any required variable is absent.
"""

from __future__ import annotations

import os
import random
import string
import time
from typing import Optional
from unittest.mock import patch

import httpx
import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Skip guard — skip the whole module if required secrets are absent
# ─────────────────────────────────────────────────────────────────────────────

_REQUIRED = [
    "INTEGRATION_TEST_GITHUB_TOKEN",
    "INTEGRATION_TEST_REPO",
    "INTEGRATION_INSTALLATION_ID",
    "GITHUB_APP_ID",
    "GITHUB_APP_PRIVATE_KEY",
]

_missing = [k for k in _REQUIRED if not os.environ.get(k)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=(
        f"Integration test skipped — missing env vars: {_missing}. "
        "Set them (or add as GitHub Actions secrets) to run this test."
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# Read config from env
# ─────────────────────────────────────────────────────────────────────────────

TEST_GITHUB_TOKEN = os.environ.get("INTEGRATION_TEST_GITHUB_TOKEN", "")
TEST_REPO = os.environ.get("INTEGRATION_TEST_REPO", "")  # "owner/name"
INSTALLATION_ID = int(os.environ.get("INTEGRATION_INSTALLATION_ID", "0"))

# Dashboard — optional; when set the test verifies real Vercel storage
INGEST_URL = os.environ.get("AEGISDIFF_INGEST_URL", "")
INGEST_TOKEN = os.environ.get("AEGISDIFF_INGEST_TOKEN", "")
DASHBOARD_URL = os.environ.get("INTEGRATION_DASHBOARD_URL", "").rstrip("/")
DASHBOARD_API_KEY = os.environ.get("INTEGRATION_API_KEY", "")

GITHUB_API = "https://api.github.com"

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable code pushed to the test PR
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_FILE_PATH = "src/api_handler.py"

VULNERABLE_CODE = """\
\"\"\"API handler for data processing requests.\"\"\"
# NOTE: This file is deliberately vulnerable for AegisDiff integration testing.
import subprocess
import os


def process_request(request_data: dict) -> dict:
    \"\"\"Process an incoming request and return a result.\"\"\"
    # Extract the template name from user input
    template = request_data.get("template", "default")

    # VULNERABILITY (CWE-78): unsanitised user input passed to shell command
    # An attacker can set template = "default; cat /etc/passwd" to exfiltrate data.
    output = subprocess.check_output(
        f"render_template.sh {template}", shell=True
    )
    return {"result": output.decode("utf-8")}


def get_report(query: str) -> str:
    \"\"\"Fetch a report by name.\"\"\"
    # VULNERABILITY (CWE-78): second injection point
    raw = os.popen(f"generate_report {query}").read()
    return raw
"""

# ─────────────────────────────────────────────────────────────────────────────
# GitHub API helpers
# ─────────────────────────────────────────────────────────────────────────────


class GitHubHelper:
    """Thin wrapper around the GitHub REST API for test setup/teardown."""

    def __init__(self, token: str, repo: str) -> None:
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.repo = repo

    def _get(self, path: str, **params) -> dict | list:
        resp = httpx.get(
            f"{GITHUB_API}{path}",
            headers=self._headers,
            params=params,
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: dict) -> dict:
        resp = httpx.post(
            f"{GITHUB_API}{path}",
            headers=self._headers,
            json=body,
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, body: dict) -> dict:
        resp = httpx.patch(
            f"{GITHUB_API}{path}",
            headers=self._headers,
            json=body,
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str) -> None:
        resp = httpx.delete(
            f"{GITHUB_API}{path}",
            headers=self._headers,
            timeout=15.0,
        )
        if resp.status_code not in (204, 422):
            resp.raise_for_status()

    def get_default_branch_sha(self) -> tuple[str, str]:
        """Return (default_branch_name, HEAD_sha)."""
        repo_info = self._get(f"/repos/{self.repo}")
        branch = repo_info["default_branch"]
        ref = self._get(f"/repos/{self.repo}/git/ref/heads/{branch}")
        return branch, ref["object"]["sha"]

    def create_branch(self, branch_name: str, from_sha: str) -> None:
        self._post(
            f"/repos/{self.repo}/git/refs",
            {"ref": f"refs/heads/{branch_name}", "sha": from_sha},
        )
        print(f"  → Branch created: {branch_name}")

    def push_file(self, path: str, content: str, branch: str, message: str) -> str:
        """Create or update a file. Returns the commit SHA."""
        import base64

        # Check if file already exists (need its SHA to update)
        existing_sha = None
        try:
            existing = self._get(
                f"/repos/{self.repo}/contents/{path}",
                ref=branch,
            )
            if isinstance(existing, dict):
                existing_sha = existing.get("sha")
        except httpx.HTTPStatusError:
            pass

        body: dict = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if existing_sha:
            body["sha"] = existing_sha

        resp = httpx.put(
            f"{GITHUB_API}/repos/{self.repo}/contents/{path}",
            headers=self._headers,
            json=body,
            timeout=15.0,
        )
        resp.raise_for_status()
        commit_sha = resp.json()["commit"]["sha"]
        print(f"  → File pushed: {path}  (commit {commit_sha[:7]})")
        return commit_sha

    def create_pr(self, title: str, head: str, base: str, body: str = "") -> tuple[int, str]:
        """Open a pull request. Returns (pr_number, head_sha)."""
        pr = self._post(
            f"/repos/{self.repo}/pulls",
            {"title": title, "head": head, "base": base, "body": body, "draft": False},
        )
        print(f"  → PR #{pr['number']} opened: {pr['html_url']}")
        return pr["number"], pr["head"]["sha"]

    def close_pr(self, pr_number: int) -> None:
        self._patch(f"/repos/{self.repo}/pulls/{pr_number}", {"state": "closed"})
        print(f"  → PR #{pr_number} closed")

    def delete_branch(self, branch: str) -> None:
        self._delete(f"/repos/{self.repo}/git/refs/heads/{branch}")
        print(f"  → Branch deleted: {branch}")

    def get_pr_comments(self, pr_number: int) -> list:
        return self._get(
            f"/repos/{self.repo}/issues/{pr_number}/comments",
            per_page=50,
        )

    def get_commit_statuses(self, sha: str) -> list:
        return self._get(f"/repos/{self.repo}/commits/{sha}/statuses")

    def find_aegisdiff_comment(self, pr_number: int) -> Optional[dict]:
        for comment in self.get_pr_comments(pr_number):
            if "<!-- aegisdiff-report -->" in comment.get("body", ""):
                return comment
        return None

    def find_aegisdiff_status(self, sha: str) -> Optional[dict]:
        for status in self.get_commit_statuses(sha):
            if status.get("context") == "AegisDiff / security":
                return status
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Vercel dashboard helpers
# ─────────────────────────────────────────────────────────────────────────────


class DashboardHelper:
    """
    Wraps the AegisDiff public REST API (/api/v1/scans).
    Used to verify that the ingest endpoint actually stored the scan in Neon DB.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base = base_url
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def is_configured(self) -> bool:
        return bool(self._base and self._headers["Authorization"] != "Bearer ")

    def get_scans(self, repo: str) -> list[dict]:
        """Return recent scans for the given repo slug."""
        resp = httpx.get(
            f"{self._base}/api/v1/scans",
            headers=self._headers,
            params={"repo": repo, "limit": 20},
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        # API may return {"scans": [...]} or a bare list
        return data.get("scans", data) if isinstance(data, dict) else data

    def poll_for_scan(
        self, repo: str, commit_sha: str, timeout: int = 30, interval: int = 3
    ) -> Optional[dict]:
        """Poll /api/v1/scans until a scan with matching commit_sha appears."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                scans = self.get_scans(repo)
                for scan in scans:
                    if scan.get("commit_sha") == commit_sha:
                        return scan
            except Exception as e:
                print(f"  ⚠ Dashboard poll error (retrying): {e}")
            time.sleep(interval)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# The integration test
# ─────────────────────────────────────────────────────────────────────────────


class TestRealGitHubPRScan:
    """
    Full end-to-end integration test using real GitHub + real Vercel dashboard.

    Flow:
      ~0s    Create branch + push vulnerable code → open real PR
      ~5s    Run app_entrypoint.main() (real App JWT + real LLM + real GitHub writes)
      ~30s   LLM returns verdict, PR comment posted, commit status set
      ~32s   Real POST to Vercel /api/ingest
      ~33s   Poll GET /api/v1/scans → confirm scan stored in Neon DB
      ~35s   All assertions pass, cleanup (close PR + delete branch)
    """

    @pytest.fixture(autouse=True)
    def _setup_and_teardown(self):
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.branch = f"aegisdiff-integration-test-{suffix}"
        self.gh = GitHubHelper(TEST_GITHUB_TOKEN, TEST_REPO)
        self.dashboard = DashboardHelper(DASHBOARD_URL, DASHBOARD_API_KEY)
        self.pr_number: Optional[int] = None

        yield

        print("\n  [cleanup]")
        if self.pr_number:
            try:
                self.gh.close_pr(self.pr_number)
            except Exception as e:
                print(f"  ⚠ Could not close PR: {e}")
        try:
            self.gh.delete_branch(self.branch)
        except Exception as e:
            print(f"  ⚠ Could not delete branch: {e}")

    def test_pr_scan_detects_command_injection(self):
        """
        Full pipeline with real GitHub + real Vercel:
          1. Push CWE-78 vulnerable code → open PR
          2. Run AegisDiff engine (real LLM + real GitHub App token)
          3. Verify PR comment + commit status on GitHub
          4. Verify scan stored in Vercel dashboard (if configured)
        """

        print("\n")
        print("=" * 70)
        print("  AegisDiff — Real-GitHub + Vercel Integration Test")
        print(f"  Target repo : {TEST_REPO}")
        if self.dashboard.is_configured():
            print(f"  Dashboard   : {DASHBOARD_URL}")
        else:
            print("  Dashboard   : (not configured — ingest verification skipped)")
        print("=" * 70)

        # ── [1] Create branch + push vulnerable PR ────────────────────────────
        print("\n  [1] CREATING TEST PR")
        default_branch, base_sha = self.gh.get_default_branch_sha()
        print(f"  → Base: {default_branch}  ({base_sha[:7]})")

        self.gh.create_branch(self.branch, base_sha)

        self.gh.push_file(
            path=VULNERABLE_FILE_PATH,
            content=VULNERABLE_CODE,
            branch=self.branch,
            message=(
                "feat: add API handler with data processing\n\n"
                "[aegisdiff-integration-test] Deliberately vulnerable for CI."
            ),
        )

        pr_number, head_sha = self.gh.create_pr(
            title=f"[AegisDiff CI] Integration test — add API handler ({self.branch[-6:]})",
            head=self.branch,
            base=default_branch,
            body=(
                "**Automated integration test PR — will be closed automatically.**\n\n"
                "Contains deliberate CWE-78 OS command injection to verify "
                "AegisDiff detection."
            ),
        )
        self.pr_number = pr_number
        print(f"\n  → PR #{pr_number}  head={head_sha[:7]}")

        # ── [2] Run AegisDiff engine ──────────────────────────────────────────
        print("\n  [2] RUNNING AEGISDIFF ENGINE (real credentials)")

        env_overrides = {
            "GITHUB_APP_ID": os.environ["GITHUB_APP_ID"],
            "GITHUB_APP_PRIVATE_KEY": os.environ["GITHUB_APP_PRIVATE_KEY"],
            "INSTALLATION_ID": str(INSTALLATION_ID),
            "TARGET_REPO": TEST_REPO,
            "PR_NUMBER": str(pr_number),
            "COMMIT_SHA": head_sha,
            "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
            "OPENROUTER_API_KEY": os.environ.get("OPENROUTER_API_KEY", ""),
            "OPENROUTER_API_KEY_2": os.environ.get("OPENROUTER_API_KEY_2", ""),
            "OPENROUTER_API_KEY_3": os.environ.get("OPENROUTER_API_KEY_3", ""),
            "GROQ_API_KEY": os.environ.get("GROQ_API_KEY", ""),
            "GROQ_API_KEY_2": os.environ.get("GROQ_API_KEY_2", ""),
            "GROQ_API_KEY_3": os.environ.get("GROQ_API_KEY_3", ""),
            # Real Vercel ingest — sends actual data to the dashboard
            "AEGISDIFF_INGEST_URL": INGEST_URL,
            "AEGISDIFF_INGEST_TOKEN": INGEST_TOKEN,
        }

        # Track what was sent to ingest (for assertion even if dashboard API key not set)
        ingest_captured: dict = {}

        def _capturing_send(ingest_url, ingest_token, verdicts, pr_num, sha, repo, ms):
            from aegisdiff.app_entrypoint import _build_item
            from aegisdiff.triage.verdicts import Verdict as _V

            payload = (
                _build_item(verdicts, pr_num, sha, repo, ms)
                if isinstance(verdicts, _V)
                else [_build_item(v, pr_num, sha, repo, ms) for v in verdicts]
            )
            ingest_captured["payload"] = payload
            # Call through to REAL Vercel endpoint
            _real_send(ingest_url, ingest_token, verdicts, pr_num, sha, repo, ms)

        import aegisdiff.app_entrypoint as _ep

        _real_send = _ep._send_to_ingest
        scan_start = time.monotonic()
        exit_code = None

        with patch.dict(os.environ, env_overrides, clear=False):
            with patch.object(_ep, "_send_to_ingest", side_effect=_capturing_send):
                try:
                    _ep.main()
                    exit_code = 0
                except SystemExit as e:
                    exit_code = e.code

        scan_ms = int((time.monotonic() - scan_start) * 1000)
        print(f"  → Engine done in {scan_ms}ms  (exit {exit_code})")

        # ── [3] Verify GitHub PR comment ──────────────────────────────────────
        print("\n  [3] VERIFYING GITHUB PR COMMENT")
        comment = self.gh.find_aegisdiff_comment(pr_number)
        assert comment is not None, (
            f"No AegisDiff comment found on {TEST_REPO}#{pr_number}.\n"
            "Check that the GitHub App installation has PR write permission."
        )
        comment_body = comment["body"]
        print(f"  ✓ Comment posted  (id={comment['id']})")
        print(f"    {comment_body.split(chr(10))[0]}")

        assert "<!-- aegisdiff-report -->" in comment_body
        assert any(
            kw in comment_body
            for kw in ("TRUE_POSITIVE", "True Positive", "true_positive")
        ), f"Expected TRUE_POSITIVE in comment:\n{comment_body[:400]}"
        print("  ✓ Verdict: TRUE_POSITIVE")

        # ── [4] Verify GitHub commit status ───────────────────────────────────
        print("\n  [4] VERIFYING COMMIT STATUS")
        status = self.gh.find_aegisdiff_status(head_sha)
        assert status is not None, (
            f"No commit status found for {head_sha[:7]} on {TEST_REPO}.\n"
            "Check that the GitHub App has 'commit statuses: write' permission."
        )
        print(f"  ✓ Status posted")
        print(f"    state   = {status['state']}")
        print(f"    context = {status['context']}")
        print(f"    desc    = {status['description']}")

        assert status["context"] == "AegisDiff / security"
        assert status["state"] == "failure", (
            f"Expected 'failure' for TRUE_POSITIVE, got '{status['state']}'"
        )

        # ── [5] Verify Vercel dashboard ingest ────────────────────────────────
        print("\n  [5] VERIFYING DASHBOARD INGEST")

        # 5a — verify what was sent to the real endpoint
        assert ingest_captured, "Ingest function was never called"
        payload = ingest_captured["payload"]
        item = payload[0] if isinstance(payload, list) else payload

        print(f"  ✓ Ingest called")
        print(f"    verdict    = {item['verdict']}")
        print(f"    cwe_id     = {item['cwe_id']}")
        print(f"    severity   = {item['severity']}")
        print(f"    confidence = {item['confidence']:.0%}")
        print(f"    provider   = {item['provider']}")
        print(f"    scan_ms    = {item['scan_ms']}ms")
        print(f"    pr_url     = {item['pr_url']}")

        assert item["verdict"] == "TRUE_POSITIVE"
        assert "CWE-78" in item["cwe_id"]
        assert item["pr_number"] == pr_number
        assert item["commit_sha"] == head_sha
        assert item["pr_url"] == f"https://github.com/{TEST_REPO}/pull/{pr_number}"

        # 5b — read it back from Vercel to confirm Neon DB storage
        if self.dashboard.is_configured():
            print(f"\n  → Polling {DASHBOARD_URL}/api/v1/scans for stored scan...")
            stored = self.dashboard.poll_for_scan(TEST_REPO, head_sha, timeout=30)
            assert stored is not None, (
                f"Scan with commit_sha={head_sha[:7]} not found in dashboard "
                f"after 30s. The ingest endpoint may have returned an error.\n"
                f"Check {DASHBOARD_URL}/admin for rate-limit issues."
            )
            print(f"  ✓ Scan stored in Vercel dashboard (Neon DB)")
            print(f"    id         = {stored.get('id', '?')}")
            print(f"    verdict    = {stored.get('verdict', '?')}")
            print(f"    cwe_id     = {stored.get('cwe_id', '?')}")
            print(f"    created_at = {stored.get('created_at', '?')}")

            assert stored.get("verdict") == "TRUE_POSITIVE"
            assert stored.get("pr_number") == pr_number
        else:
            print("  ℹ Dashboard read-back skipped (set INTEGRATION_DASHBOARD_URL")
            print("    and INTEGRATION_API_KEY to enable full Vercel verification)")

        # ── Final summary ─────────────────────────────────────────────────────
        dashboard_note = (
            f"dashboard=✓" if self.dashboard.is_configured() else "dashboard=skipped"
        )
        print("\n" + "=" * 70)
        print("  INTEGRATION TEST PASSED")
        print(f"  {TEST_REPO}  PR #{pr_number}  commit={head_sha[:7]}")
        print(f"  CWE: {item['cwe_id']}  •  provider: {item['provider']}  •  {scan_ms}ms")
        print(f"  comment=✓  •  status=failure  •  ingest=✓  •  {dashboard_note}")
        print("=" * 70 + "\n")
