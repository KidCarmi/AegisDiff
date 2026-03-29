"""
End-user smoke test — AegisDiff as a real user experiences it.

Requires ONE secret: INTEGRATION_PAT
  A GitHub Personal Access Token with `repo` scope on this repo.
  Add it once: Settings → Secrets → Actions → New repository secret.

Why a PAT and not GITHUB_TOKEN?
  GitHub Actions intentionally blocks GITHUB_TOKEN (the bot token) from
  triggering other workflow runs on the same repo (anti-loop protection).
  Opening a PR with a real PAT fires the webhook → Vercel → aegisdiff-app.yml
  exactly as a real user's PR would.

Flow (identical to what a real user sees):
  1. Open a PR with vulnerable code on this repo
  2. Watch for AegisDiff to scan it automatically
     (webhook → Vercel → repository_dispatch → aegisdiff-app.yml → engine)
  3. Verify the PR comment and commit status appeared
  4. Optionally verify the scan is stored in the Vercel dashboard

Optional dashboard verification (2 more secrets):
  INTEGRATION_DASHBOARD_URL  — https://your-app.vercel.app
  INTEGRATION_API_KEY        — v1 REST API key
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
# Config
# ─────────────────────────────────────────────────────────────────────────────

# The one required secret — a PAT that can open PRs and trigger workflows.
# GITHUB_TOKEN (bot) cannot trigger other workflows; a real PAT can.
PAT = os.environ.get("INTEGRATION_PAT", "")

# MUST be a user repo that is connected to the AegisDiff dashboard —
# NOT KidCarmi/AegisDiff itself (the platform repo has no webhook/App install).
# Example: "KidCarmi/aegisdiff-integration-target"
TEST_REPO = os.environ.get("INTEGRATION_TEST_REPO", "")

# Optional dashboard verification
DASHBOARD_URL = os.environ.get("INTEGRATION_DASHBOARD_URL", "").rstrip("/")
DASHBOARD_API_KEY = os.environ.get("INTEGRATION_API_KEY", "")

GITHUB_API = "https://api.github.com"
SCAN_TIMEOUT = 8 * 60
POLL_INTERVAL = 15

# ─────────────────────────────────────────────────────────────────────────────
# Skip when the PAT is not available
# ─────────────────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.skipif(
    not (PAT and TEST_REPO),
    reason=(
        "Integration test skipped. Required secrets:\n"
        "  INTEGRATION_PAT       — GitHub PAT with `repo` scope\n"
        "  INTEGRATION_TEST_REPO — a user repo connected to the AegisDiff dashboard\n"
        "                          (NOT KidCarmi/AegisDiff — that is the platform repo)\n"
        "Example: INTEGRATION_TEST_REPO=KidCarmi/aegisdiff-integration-target"
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable code for the test PR
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_FILE = "tests/fixtures/_integration_test_target.py"

VULNERABLE_CODE = """\
# Integration test fixture — deliberately vulnerable, never executed.
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
# Minimal GitHub API wrapper
# ─────────────────────────────────────────────────────────────────────────────


class GitHub:
    def __init__(self, token: str, repo: str) -> None:
        self._h = {
            "Authorization": f"token {token}",
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
        existing_sha = None
        try:
            f = self._req("GET", f"/repos/{self.repo}/contents/{path}",
                          params={"ref": branch})
            existing_sha = f.get("sha") if isinstance(f, dict) else None
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
            headers=self._h, json=body, timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()["commit"]["sha"]

    def open_pr(self, title: str, head: str, base: str, body: str = "") -> tuple[int, str]:
        pr = self._req("POST", f"/repos/{self.repo}/pulls",
                       json={"title": title, "head": head,
                             "base": base, "body": body, "draft": False})
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

    def aegisdiff_comment(self, pr_number: int) -> Optional[dict]:
        comments = self._req("GET", f"/repos/{self.repo}/issues/{pr_number}/comments",
                             params={"per_page": 50})
        for c in (comments if isinstance(comments, list) else []):
            if "<!-- aegisdiff-report -->" in c.get("body", ""):
                return c
        return None

    def aegisdiff_status(self, sha: str) -> Optional[dict]:
        statuses = self._req("GET", f"/repos/{self.repo}/commits/{sha}/statuses")
        for s in (statuses if isinstance(statuses, list) else []):
            if s.get("context") == "AegisDiff / security":
                return s
        return None

    def poll_for_comment(self, pr_number: int) -> Optional[dict]:
        deadline = time.monotonic() + SCAN_TIMEOUT
        elapsed = 0
        while time.monotonic() < deadline:
            c = self.aegisdiff_comment(pr_number)
            if c:
                return c
            print(f"  ⏳ Waiting for AegisDiff... ({elapsed}s / {SCAN_TIMEOUT}s)",
                  flush=True)
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard helper (optional)
# ─────────────────────────────────────────────────────────────────────────────


class Dashboard:
    def __init__(self, base_url: str, api_key: str) -> None:
        self._base = base_url
        self._key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._base and self._key)

    def find_scan(self, repo: str, commit_sha: str) -> Optional[dict]:
        headers = {"Authorization": f"Bearer {self._key}"}
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(f"{self._base}/api/v1/scans",
                                 headers=headers,
                                 params={"repo": repo, "limit": 20},
                                 timeout=15.0)
                resp.raise_for_status()
                data = resp.json()
                scans = data.get("scans", data) if isinstance(data, dict) else data
                for scan in scans:
                    if scan.get("commit_sha") == commit_sha:
                        return scan
            except Exception as e:
                print(f"  ⚠ Dashboard poll: {e}")
            time.sleep(5)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# The test
# ─────────────────────────────────────────────────────────────────────────────


class TestEndUserPRScan:

    @pytest.fixture(autouse=True)
    def _lifecycle(self):
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.branch = f"aegisdiff-e2e-{suffix}"
        self.gh = GitHub(PAT, TEST_REPO)
        self.db = Dashboard(DASHBOARD_URL, DASHBOARD_API_KEY)
        self.pr_number: Optional[int] = None
        yield
        if self.pr_number:
            self.gh.close_pr(self.pr_number)
        self.gh.delete_branch(self.branch)
        print(f"  [cleanup] PR closed, branch deleted ✓")

    def test_aegisdiff_automatically_scans_vulnerable_pr(self):
        """
        Open a PR with vulnerable code and wait for AegisDiff to scan it
        automatically. Verify the comment, commit status, and dashboard.
        """

        print("\n")
        print("=" * 66)
        print("  AegisDiff — End-User Integration Test")
        print(f"  Repo      : {TEST_REPO}")
        print(f"  Dashboard : {DASHBOARD_URL or '(not configured)'}")
        print("=" * 66)

        # ── Preflight: verify the repo is a connected user repo ───────────────
        # KidCarmi/AegisDiff is the platform repo — it has no AegisDiff webhook.
        # The test needs a DIFFERENT repo that the user connected via the dashboard.
        current_repo = os.environ.get("GITHUB_REPOSITORY", "")
        if TEST_REPO == current_repo:
            pytest.fail(
                f"\n\nINTEGRATION_TEST_REPO is set to '{TEST_REPO}' — that is the "
                f"platform repo itself.\n\n"
                f"The test needs a DIFFERENT repo that is connected to the AegisDiff "
                f"dashboard (i.e. a user repo with the GitHub App installed).\n\n"
                f"Steps:\n"
                f"  1. Create a new repo, e.g. KidCarmi/aegisdiff-integration-target\n"
                f"  2. Sign in to the AegisDiff dashboard → connect that repo\n"
                f"  3. Set INTEGRATION_TEST_REPO=KidCarmi/aegisdiff-integration-target\n"
                f"     in your GitHub Actions secrets"
            )

        # Quick check the repo exists and the PAT can access it
        print("\n  [preflight] Checking test repo access...")
        try:
            info = self.gh._req("GET", f"/repos/{TEST_REPO}")
            print(f"  ✓ Repo accessible: {info['full_name']}")
        except Exception as e:
            pytest.fail(
                f"Cannot access {TEST_REPO} with the provided PAT: {e}\n"
                f"Make sure INTEGRATION_PAT has `repo` scope on {TEST_REPO}."
            )

        # ── [1] Open a real PR ────────────────────────────────────────────────
        print("\n  [1] Opening PR with vulnerable code...")
        base_branch, base_sha = self.gh.default_branch()
        self.gh.create_branch(self.branch, base_sha)
        self.gh.push_file(
            path=VULNERABLE_FILE,
            content=VULNERABLE_CODE,
            branch=self.branch,
            # [skip ci] prevents repo-level CI workflows (lint, tests, security
            # scans) from running on the test PR — AegisDiff still scans via
            # its webhook which is not affected by [skip ci].
            message="test: add integration test fixture with CWE-78 [skip ci]",
        )
        pr_number, head_sha = self.gh.open_pr(
            title=f"[AegisDiff E2E] Integration test ({self.branch[-6:]})",
            head=self.branch,
            base=base_branch,
            body=(
                "Automated smoke test — verifies the full AegisDiff pipeline.\n\n"
                "_This PR will be closed automatically._"
            ),
        )
        self.pr_number = pr_number
        print(f"  ✓ PR #{pr_number} opened  (commit {head_sha[:7]})")

        # ── [2] Wait for AegisDiff to run automatically ───────────────────────
        print(f"\n  [2] Waiting for AegisDiff to scan automatically...")
        print(f"      (webhook → Vercel → repository_dispatch → Actions → engine)")
        opened_at = time.monotonic()
        comment = self.gh.poll_for_comment(pr_number)
        elapsed = int(time.monotonic() - opened_at)

        assert comment is not None, (
            f"\n\nAegisDiff did not post a comment on {TEST_REPO}#{pr_number} "
            f"within {SCAN_TIMEOUT // 60} minutes.\n\n"
            "Check:\n"
            f"  • https://github.com/{TEST_REPO}/actions  (did aegisdiff-app.yml run?)\n"
            "  • Is the AegisDiff GitHub App installed on this repo?\n"
            "  • Is the Vercel webhook handler running?"
        )
        print(f"  ✓ Scanned in {elapsed}s")

        # ── [3] Verify PR comment ─────────────────────────────────────────────
        print("\n  [3] PR comment:")
        body = comment["body"]
        print(f"      {body.split(chr(10))[0]}")
        assert "<!-- aegisdiff-report -->" in body
        assert any(kw in body for kw in ("TRUE_POSITIVE", "True Positive")), (
            f"Expected TRUE_POSITIVE in comment:\n{body[:400]}"
        )
        print("  ✓ Verdict: TRUE_POSITIVE")

        # ── [4] Verify commit status ──────────────────────────────────────────
        print("\n  [4] Commit status:")
        status = self.gh.aegisdiff_status(head_sha)
        assert status is not None, (
            f"No commit status on {head_sha[:7]} — "
            "check the GitHub App has 'commit statuses: write' permission."
        )
        print(f"      state   : {status['state']}")
        print(f"      context : {status['context']}")
        print(f"      desc    : {status['description']}")
        assert status["context"] == "AegisDiff / security"
        assert status["state"] == "failure"
        print("  ✓ Merge blocked")

        # ── [5] Verify dashboard (optional) ──────────────────────────────────
        if self.db.configured:
            print(f"\n  [5] Dashboard ({DASHBOARD_URL}):")
            scan = self.db.find_scan(TEST_REPO, head_sha)
            assert scan is not None, (
                f"Scan with commit_sha={head_sha[:7]} not in dashboard. "
                "Is the repo connected?"
            )
            print(f"      verdict    : {scan.get('verdict')}")
            print(f"      cwe_id     : {scan.get('cwe_id')}")
            print(f"      created_at : {scan.get('created_at')}")
            assert scan.get("verdict") == "TRUE_POSITIVE"
            print("  ✓ Stored in Neon DB")
        else:
            print("\n  [5] Dashboard skipped (set INTEGRATION_DASHBOARD_URL + INTEGRATION_API_KEY)")

        print("\n" + "=" * 66)
        print(f"  PASSED  •  PR #{pr_number}  •  {elapsed}s  •  status=failure")
        print("=" * 66 + "\n")
