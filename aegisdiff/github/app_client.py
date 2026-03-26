"""
GitHub App client — mints installation access tokens via App JWT auth.

Used by app_entrypoint.py (repository_dispatch mode) to authenticate
as the installed GitHub App and fetch PR diffs without requiring a
user-supplied GITHUB_TOKEN.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx


class GitHubAppClient:
    """
    Authenticates as a GitHub App using the App's RSA private key,
    then exchanges the short-lived JWT for installation access tokens.

    Installation tokens expire after 1 hour — never store them; mint
    a fresh one per operation.
    """

    BASE_URL = "https://api.github.com"
    ACCEPT = "application/vnd.github+json"

    def __init__(self, app_id: str, private_key_pem: str) -> None:
        self._app_id = app_id
        self._private_key_pem = private_key_pem

    # ── JWT (App-level auth) ──────────────────────────────────────────────────

    def _make_jwt(self) -> str:
        """
        Create a short-lived JWT (max 10 min) signed with the App's
        RSA private key.  Required for all App-level API calls.
        """
        try:
            import jwt as pyjwt  # PyJWT
        except ImportError as exc:
            raise ImportError(
                "PyJWT is required for GitHub App auth. "
                "Add 'PyJWT[cryptography]' to your dependencies."
            ) from exc

        now = int(time.time())
        payload = {
            "iat": now - 60,  # issued 60s ago to tolerate clock skew
            "exp": now + 540,  # expires in 9 minutes (10-min max)
            "iss": self._app_id,
        }
        return pyjwt.encode(payload, self._private_key_pem, algorithm="RS256")

    # ── Installation token ────────────────────────────────────────────────────

    def get_installation_token(self, installation_id: int) -> str:
        """
        Exchange the App JWT for an installation access token.
        Valid for 1 hour.  Never persisted — call this per operation.
        """
        jwt_token = self._make_jwt()
        resp = httpx.post(
            f"{self.BASE_URL}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": self.ACCEPT,
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()["token"]

    # ── PR diff ───────────────────────────────────────────────────────────────

    def get_pr_diff(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """
        Fetch the unified diff for a pull request using the installation token.
        Returns the raw diff text.
        """
        token = self.get_installation_token(installation_id)
        resp = httpx.get(
            f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.diff",  # raw diff format
            },
            follow_redirects=True,
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.text

    # ── Inline review comment ─────────────────────────────────────────────────

    def create_review(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> bool:
        """
        Post an inline review comment on a specific line of a PR diff.

        Mirrors GitHubClient.create_review but authenticates via App token.
        Returns False if the line is not part of the diff (422) or on error.
        """
        import logging

        logger = logging.getLogger(__name__)
        token = self.get_installation_token(installation_id)
        headers = {"Authorization": f"Bearer {token}", "Accept": self.ACCEPT}
        payload = {
            "commit_id": commit_sha,
            "event": "COMMENT",
            "comments": [{"path": path, "line": line, "side": "RIGHT", "body": body}],
        }
        try:
            resp = httpx.post(
                f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
                headers=headers,
                json=payload,
                timeout=15.0,
            )
            if resp.status_code == 422:
                logger.warning(
                    "Inline review rejected (line %d not in diff for %s) — "
                    "falling back to top-level comment",
                    line,
                    path,
                )
                return False
            resp.raise_for_status()
            logger.info("Posted inline review on %s:%d (PR #%d)", path, line, pr_number)
            return True
        except httpx.HTTPError as exc:
            logger.warning("Failed to post inline review comment: %s", exc)
            return False

    # ── PR comment ────────────────────────────────────────────────────────────

    def upsert_pr_comment(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        marker: str,
    ) -> None:
        """
        Create or update a PR comment that contains `marker` in its body.
        Mirrors GitHubClient.upsert_pr_comment but authenticates via App token.
        """
        token = self.get_installation_token(installation_id)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": self.ACCEPT,
        }

        # List existing comments and find ours
        resp = httpx.get(
            f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments",
            headers=headers,
            params={"per_page": "100"},
            timeout=15.0,
        )
        resp.raise_for_status()

        existing_id: Optional[int] = None
        for comment in resp.json():
            if marker in comment.get("body", ""):
                existing_id = comment["id"]
                break

        if existing_id:
            httpx.patch(
                f"{self.BASE_URL}/repos/{owner}/{repo}/issues/comments/{existing_id}",
                headers=headers,
                json={"body": body},
                timeout=15.0,
            ).raise_for_status()
        else:
            httpx.post(
                f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments",
                headers=headers,
                json={"body": body},
                timeout=15.0,
            ).raise_for_status()
