"""Thin GitHub REST API wrapper."""

from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


class GitHubClient:
    """
    Minimal GitHub REST API client for posting PR comments.

    Args:
        token: GitHub personal access token or GITHUB_TOKEN from Actions.
        repo: Repository in "owner/name" format.
    """

    def __init__(self, token: str, repo: str) -> None:
        self._repo = repo
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

    def upsert_pr_comment(self, pr_number: int, body: str, marker: str) -> None:
        """
        If a comment containing `marker` already exists on the PR, update it.
        Otherwise, create a new comment. This keeps the PR clean — one
        AegisDiff comment per PR, updated on each push.
        """
        existing_id = self._find_comment_with_marker(pr_number, marker)
        if existing_id:
            self._update_comment(existing_id, body)
            logger.info("Updated existing AegisDiff comment #%d on PR #%d", existing_id, pr_number)
        else:
            self._create_comment(pr_number, body)
            logger.info("Created new AegisDiff comment on PR #%d", pr_number)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_comment_with_marker(self, pr_number: int, marker: str) -> Optional[int]:
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/issues/{pr_number}/comments"
        try:
            resp = httpx.get(url, headers=self._headers, params={"per_page": 100}, timeout=15.0)
            resp.raise_for_status()
            for comment in resp.json():
                if marker in comment.get("body", ""):
                    return comment["id"]
        except httpx.HTTPError as e:
            logger.warning("Failed to list PR comments: %s", e)
        return None

    def _create_comment(self, pr_number: int, body: str) -> None:
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/issues/{pr_number}/comments"
        try:
            resp = httpx.post(url, headers=self._headers, json={"body": body}, timeout=15.0)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.warning("Failed to create PR comment: %s", e)

    def _update_comment(self, comment_id: int, body: str) -> None:
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/issues/comments/{comment_id}"
        try:
            resp = httpx.patch(url, headers=self._headers, json={"body": body}, timeout=15.0)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.warning("Failed to update PR comment #%d: %s", comment_id, e)

    def create_review(
        self,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> bool:
        """
        Post an inline review comment on a specific line of a PR diff.

        Uses the Pull Request Reviews API so the comment appears inline on the
        changed file. Returns False if the line is not part of the diff
        (GitHub returns 422) or any other error occurs — caller should fall
        back to a top-level comment.

        Args:
            pr_number: PR number.
            commit_sha: Full SHA of the HEAD commit being reviewed.
            path: File path relative to repo root (e.g. "src/app.py").
            line: Line number in the new version of the file (RIGHT side).
            body: Markdown body for the inline comment.
        """
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/pulls/{pr_number}/reviews"
        payload = {
            "commit_id": commit_sha,
            "event": "COMMENT",
            "comments": [
                {
                    "path": path,
                    "line": line,
                    "side": "RIGHT",
                    "body": body,
                }
            ],
        }
        try:
            resp = httpx.post(url, headers=self._headers, json=payload, timeout=15.0)
            if resp.status_code == 422:
                logger.warning(
                    "Inline review rejected (line %d not in diff for %s) — "
                    "will fall back to top-level comment",
                    line,
                    path,
                )
                return False
            resp.raise_for_status()
            logger.info("Posted inline review comment on %s:%d (PR #%d)", path, line, pr_number)
            return True
        except httpx.HTTPError as e:
            logger.warning("Failed to post inline review comment: %s", e)
            return False

    def upload_sarif(self, commit_sha: str, ref: str, sarif_b64: str) -> bool:
        """
        Upload a gzip+base64-encoded SARIF to GitHub Code Scanning.

        Requires the GITHUB_TOKEN to have `security-events: write` permission
        (or `public_repo` for public repositories).

        Returns True on success, False on any error (non-fatal — caller continues).

        Args:
            commit_sha: Full 40-char SHA of the scanned commit.
            ref:        Git ref, e.g. "refs/pull/42/head" or "refs/heads/main".
            sarif_b64:  Output of aegisdiff.triage.sarif.encode_sarif().
        """
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/code-scanning/sarifs"
        payload = {
            "commit_sha": commit_sha,
            "ref": ref,
            "sarif": sarif_b64,
            "tool_name": "AegisDiff",
        }
        try:
            resp = httpx.post(url, headers=self._headers, json=payload, timeout=20.0)
            if resp.status_code == 403:
                logger.warning(
                    "SARIF upload skipped — token lacks security-events:write "
                    "permission (add it to the workflow permissions block)"
                )
                return False
            if resp.status_code == 404:
                logger.warning(
                    "SARIF upload skipped — Code Scanning not available for this repo "
                    "(private repos need GitHub Advanced Security)"
                )
                return False
            resp.raise_for_status()
            logger.info(
                "SARIF uploaded to GitHub Code Scanning (ref=%s, sha=%s)",
                ref,
                commit_sha[:7],
            )
            return True
        except httpx.HTTPError as e:
            logger.warning("SARIF upload failed (non-fatal): %s", e)
            return False

    def get_file_content(self, path: str, ref: str) -> Optional[str]:
        """
        Fetch raw text of a file at a specific ref via GitHub Contents API.
        Returns None on any error (binary, 404, too large).
        """
        import base64

        url = f"{GITHUB_API_BASE}/repos/{self._repo}/contents/{path}"
        try:
            resp = httpx.get(
                url,
                headers=self._headers,
                params={"ref": ref},
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            logger.debug("Cannot fetch %s@%s: %s", path, ref[:7], exc)
            return None
        if not resp.is_success:
            logger.debug("Cannot fetch %s@%s: HTTP %d", path, ref[:7], resp.status_code)
            return None
        data = resp.json()
        if isinstance(data, list):
            return None
        if data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def post_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = "AegisDiff / security",
    ) -> None:
        """Post a GitHub commit status. state: success | failure | pending | error."""
        url = f"{GITHUB_API_BASE}/repos/{self._repo}/statuses/{sha}"
        try:
            resp = httpx.post(
                url,
                headers=self._headers,
                json={"state": state, "description": description[:140], "context": context},
                timeout=15.0,
            )
            resp.raise_for_status()
            logger.info("Posted commit status '%s' on %s", state, sha[:7])
        except httpx.HTTPError as e:
            logger.warning("Failed to post commit status: %s", e)
