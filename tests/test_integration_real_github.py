"""
End-user smoke test — AegisDiff as a real user experiences it.

This test does NOT call the engine directly.
It acts like a developer who just connected their repo to AegisDiff:

  1. Open a real PR with vulnerable code on the test repo
  2. Wait for the AegisDiff webhook → Vercel → repository_dispatch → Actions
     pipeline to fire automatically (just like a real user would wait)
  3. Verify the PR comment and commit status appeared on GitHub
  4. Verify the scan is visible in the dashboard (if configured)
  5. Clean up

One-time setup (do this once, then it just works):
  1. Create a test repo, e.g. KidCarmi/aegisdiff-integration-target
  2. Sign in to the AegisDiff dashboard and connect that repo
     (this installs the GitHub App and registers the webhook automatically)
  3. Add 2 secrets to KidCarmi/AegisDiff:
       INTEGRATION_TEST_GITHUB_TOKEN  — GitHub PAT with `repo` scope on the test repo
       INTEGRATION_TEST_REPO          — "owner/name" of the test repo

Optional (enables dashboard read-back verification):
       INTEGRATION_DASHBOARD_URL  — https://your-app.vercel.app
       INTEGRATION_API_KEY        — v1 REST API key for GET /api/v1/scans

That's it. The test uses the live webhook, the live App, the live Vercel deployment,
the live LLM stack, and the live Neon database — exactly what a real user gets.
"""

from __future__ import annotations

import os
import random
import string
import time
from typing import Optional

import httpx
import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Skip if required secrets are absent (safe to run locally with no creds)
# ─────────────────────────────────────────────────────────────────────────────

_REQUIRED = [
    "INTEGRATION_TEST_GITHUB_TOKEN",
    "INTEGRATION_TEST_REPO",
]

_missing = [k for k in _REQUIRED if not os.environ.get(k)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=(
        f"End-user integration test skipped — missing: {_missing}. "
        "Connect a repo to the AegisDiff dashboard, then set "
        "INTEGRATION_TEST_GITHUB_TOKEN and INTEGRATION_TEST_REPO."
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

TEST_TOKEN = os.environ.get("INTEGRATION_TEST_GITHUB_TOKEN", "")
TEST_REPO = os.environ.get("INTEGRATION_TEST_REPO", "")
DASHBOARD_URL = os.environ.get("INTEGRATION_DASHBOARD_URL", "").rstrip("/")
DASHBOARD_API_KEY = os.environ.get("INTEGRATION_API_KEY", "")

GITHUB_API = "https://api.github.com"

# How long to wait for the webhook pipeline to fire and AegisDiff to post results.
# Real flow: PR opened → GitHub webhook → Vercel → repository_dispatch → Actions
# job queued → Python engine runs → GitHub API writes. ~2–4 min end-to-end.
SCAN_TIMEOUT_SECONDS = 8 * 60   # 8 minutes
POLL_INTERVAL_SECONDS = 15

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable code for the test PR
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_FILE = "src/api_handler.py"

VULNERABLE_CODE = """\
\"\"\"API handler — deliberately vulnerable for AegisDiff integration testing.\"\"\"
import subprocess
import os


def process_request(request_data: dict) -> dict:
    template = request_data.get("template", "default")
    # CWE-78: unsanitised user input passed directly to shell=True
    output = subprocess.check_output(
        f"render_template.sh {template}", shell=True
    )
    return {"result": output.decode()}


def get_report(query: str) -> str:
    # CWE-78: second injection point via os.popen
    return os.popen(f"generate_report {query}").read()
"""

# ─────────────────────────────────────────────────────────────────────────────
# Minimal GitHub API client (just what the test needs)
# ─────────────────────────────────────────────────────────────────────────────


class GitHub:
    def __init__(self, token: str, repo: str) -> None:
        self._h = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.repo = repo

    def _req(self, method: str, path: str, **kw):
        resp = httpx.request(
            method, f"{GITHUB_API}{path}", headers=self._h, timeout=15.0, **kw
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    # ── setup helpers ──────────────────────────────────────────────────────

    def default_branch(self) -> tuple[str, str]:
        info = self._req("GET", f"/repos/{self.repo}")
        b = info["default_branch"]
        ref = self._req("GET", f"/repos/{self.repo}/git/ref/heads/{b}")
        return b, ref["object"]["sha"]

    def create_branch(self, name: str, sha: str) -> None:
        self._req("POST", f"/repos/{self.repo}/git/refs",
                  json={"ref": f"refs/heads/{name}", "sha": sha})

    def push_file(self, path: str, content: str, branch: str, message: str) -> str:
        import base64
        # Get existing SHA if file already exists
        existing_sha = None
        try:
            f = self._req("GET", f"/repos/{self.repo}/contents/{path}",
                          params={"ref": branch})
            existing_sha = f.get("sha") if isinstance(f, dict) else None
        except httpx.HTTPStatusError:
            pass

        body = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if existing_sha:
            body["sha"] = existing_sha

        resp = httpx.put(
            f"{GITHUB_API}/repos/{self.repo}/contents/{path}",
            headers=self._h, json=body, timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()["commit"]["sha"]

    def open_pr(self, title: str, head: str, base: str, body: str = "") -> tuple[int, str]:
        pr = self._req("POST", f"/repos/{self.repo}/pulls",
                       json={"title": title, "head": head, "base": base,
                             "body": body, "draft": False})
        return pr["number"], pr["head"]["sha"]

    def close_pr(self, number: int) -> None:
        try:
            self._req("PATCH", f"/repos/{self.repo}/pulls/{number}",
                      json={"state": "closed"})
        except Exception:
            pass

    def delete_branch(self, name: str) -> None:
        try:
            self._req("DELETE", f"/repos/{self.repo}/git/refs/heads/{name}")
        except Exception:
            pass

    # ── polling ────────────────────────────────────────────────────────────

    def aegisdiff_comment(self, pr_number: int) -> Optional[dict]:
        comments = self._req("GET", f"/repos/{self.repo}/issues/{pr_number}/comments",
                             params={"per_page": 50})
        for c in comments:
            if "<!-- aegisdiff-report -->" in c.get("body", ""):
                return c
        return None

    def aegisdiff_status(self, sha: str) -> Optional[dict]:
        statuses = self._req("GET", f"/repos/{self.repo}/commits/{sha}/statuses")
        for s in statuses:
            if s.get("context") == "AegisDiff / security":
                return s
        return None

    def poll_comment(self, pr_number: int,
                     timeout: int = SCAN_TIMEOUT_SECONDS,
                     interval: int = POLL_INTERVAL_SECONDS) -> Optional[dict]:
        deadline = time.monotonic() + timeout
        elapsed = 0
        while time.monotonic() < deadline:
            c = self.aegisdiff_comment(pr_number)
            if c:
                return c
            print(f"  ⏳ Waiting for AegisDiff scan... ({elapsed}s elapsed, "
                  f"up to {timeout}s)", flush=True)
            time.sleep(interval)
            elapsed += interval
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard helper
# ─────────────────────────────────────────────────────────────────────────────


class Dashboard:
    def __init__(self, base_url: str, api_key: str) -> None:
        self._base = base_url
        self._key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._base and self._key)

    def find_scan(self, repo: str, commit_sha: str, timeout: int = 30) -> Optional[dict]:
        headers = {"Authorization": f"Bearer {self._key}"}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(
                    f"{self._base}/api/v1/scans",
                    headers=headers,
                    params={"repo": repo, "limit": 20},
                    timeout=15.0,
                )
                resp.raise_for_status()
                data = resp.json()
                scans = data.get("scans", data) if isinstance(data, dict) else data
                for scan in scans:
                    if scan.get("commit_sha") == commit_sha:
                        return scan
            except Exception as e:
                print(f"  ⚠ Dashboard poll error: {e}")
            time.sleep(5)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# The test
# ─────────────────────────────────────────────────────────────────────────────


class TestEndUserPRScan:
    """
    Smoke test — behaves exactly like a real AegisDiff user.

    The test never calls the engine directly. It just opens a PR and
    waits for the App to do its job automatically.
    """

    @pytest.fixture(autouse=True)
    def _lifecycle(self):
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.branch = f"aegisdiff-e2e-{suffix}"
        self.gh = GitHub(TEST_TOKEN, TEST_REPO)
        self.db = Dashboard(DASHBOARD_URL, DASHBOARD_API_KEY)
        self.pr_number: Optional[int] = None
        yield
        # Always clean up
        if self.pr_number:
            self.gh.close_pr(self.pr_number)
        self.gh.delete_branch(self.branch)
        print(f"\n  [cleanup] PR closed, branch deleted ✓")

    def test_aegisdiff_automatically_scans_vulnerable_pr(self):
        """
        Open a PR with vulnerable code on a repo that has AegisDiff installed.
        Wait for the scan to run end-to-end (webhook → Vercel → Actions → engine).
        Verify the results appear exactly as a real user would see them.
        """

        print("\n")
        print("=" * 68)
        print("  AegisDiff — End-User Integration Test")
        print(f"  Repo : {TEST_REPO}")
        if self.db.configured:
            print(f"  Dashboard : {DASHBOARD_URL}")
        print("=" * 68)

        # ── Step 1: Open a real PR with vulnerable code ───────────────────────
        print("\n  [1] Opening PR with vulnerable code...")

        base_branch, base_sha = self.gh.default_branch()
        self.gh.create_branch(self.branch, base_sha)

        commit_sha = self.gh.push_file(
            path=VULNERABLE_FILE,
            content=VULNERABLE_CODE,
            branch=self.branch,
            message=(
                "feat: add API handler\n\n"
                "[aegisdiff-e2e-test] Contains CWE-78 for integration testing."
            ),
        )

        pr_number, head_sha = self.gh.open_pr(
            title=f"[AegisDiff E2E] Add API handler with data processing ({self.branch[-6:]})",
            head=self.branch,
            base=base_branch,
            body=(
                "This PR adds an API handler.\n\n"
                "> _Automated integration test — will be closed automatically._"
            ),
        )
        self.pr_number = pr_number

        print(f"  ✓ PR #{pr_number} opened on {TEST_REPO}")
        print(f"    Branch : {self.branch}")
        print(f"    Commit : {head_sha[:7]}")
        print(f"\n  [2] Waiting for AegisDiff to scan automatically...")
        print(f"    (webhook → Vercel → Actions → engine → GitHub API)")
        print(f"    Timeout: {SCAN_TIMEOUT_SECONDS // 60} minutes\n")

        # ── Step 2: Wait for AegisDiff to run (no engine call — just waiting) ─
        # This is exactly what a real user does: opens a PR and waits.
        opened_at = time.monotonic()
        comment = self.gh.poll_comment(pr_number)
        elapsed = int(time.monotonic() - opened_at)

        assert comment is not None, (
            f"\n\nAegisDiff did not post a PR comment on {TEST_REPO}#{pr_number} "
            f"within {SCAN_TIMEOUT_SECONDS // 60} minutes.\n\n"
            f"Possible causes:\n"
            f"  • The AegisDiff GitHub App is not installed on {TEST_REPO}\n"
            f"  • The Vercel webhook handler is not running\n"
            f"  • The dashboard has not connected this repo\n"
            f"  • The Actions workflow (aegisdiff-app.yml) failed\n\n"
            f"Check: https://github.com/{TEST_REPO}/actions\n"
            f"Check: https://github.com/settings/installations"
        )

        print(f"  ✓ AegisDiff scanned in {elapsed}s\n")

        # ── Step 3: Verify PR comment ─────────────────────────────────────────
        print("  [3] Verifying PR comment...")
        body = comment["body"]
        first_line = body.split("\n")[0]
        print(f"  ✓ Comment posted (id={comment['id']})")
        print(f"    {first_line}")

        # Must contain the AegisDiff marker
        assert "<!-- aegisdiff-report -->" in body

        # The vulnerable code is clearly CWE-78 — must be TRUE_POSITIVE
        assert any(kw in body for kw in ("TRUE_POSITIVE", "True Positive", "true_positive")), (
            f"Expected TRUE_POSITIVE verdict in comment.\nGot:\n{body[:600]}"
        )
        print("  ✓ Verdict: TRUE_POSITIVE detected")

        # ── Step 4: Verify commit status ──────────────────────────────────────
        print("\n  [4] Verifying commit status...")
        status = self.gh.aegisdiff_status(head_sha)
        assert status is not None, (
            f"No commit status posted on {head_sha[:7]}.\n"
            "The GitHub App needs 'commit statuses: write' permission."
        )
        print(f"  ✓ Commit status set")
        print(f"    state   : {status['state']}")
        print(f"    context : {status['context']}")
        print(f"    desc    : {status['description']}")

        assert status["context"] == "AegisDiff / security"
        assert status["state"] == "failure", (
            f"Expected 'failure' for TRUE_POSITIVE, got '{status['state']}'"
        )
        print("  ✓ Merge blocked (branch protection ready)")

        # ── Step 5: Verify dashboard (if configured) ──────────────────────────
        if self.db.configured:
            print(f"\n  [5] Verifying dashboard...")
            print(f"    Polling {DASHBOARD_URL}/api/v1/scans...")
            scan = self.db.find_scan(TEST_REPO, head_sha, timeout=30)
            assert scan is not None, (
                f"Scan with commit_sha={head_sha[:7]} not found in dashboard.\n"
                f"The ingest endpoint may have rejected it or the repo is not connected."
            )
            print(f"  ✓ Scan stored in dashboard (Neon DB)")
            print(f"    id         : {scan.get('id', '?')}")
            print(f"    verdict    : {scan.get('verdict', '?')}")
            print(f"    cwe_id     : {scan.get('cwe_id', '?')}")
            print(f"    created_at : {scan.get('created_at', '?')}")
            assert scan.get("verdict") == "TRUE_POSITIVE"
            assert scan.get("pr_number") == pr_number
        else:
            print("\n  [5] Dashboard check skipped")
            print("      Set INTEGRATION_DASHBOARD_URL + INTEGRATION_API_KEY to enable")

        # ── Summary ───────────────────────────────────────────────────────────
        dashboard_note = "dashboard=✓" if self.db.configured else "dashboard=skipped"
        print("\n" + "=" * 68)
        print("  END-USER INTEGRATION TEST PASSED")
        print(f"  {TEST_REPO}  PR #{pr_number}  scan in {elapsed}s")
        print(f"  comment=✓  •  status=failure  •  {dashboard_note}")
        print("=" * 68 + "\n")
