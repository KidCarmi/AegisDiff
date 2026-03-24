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
