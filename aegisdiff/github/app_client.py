"""
GitHub App client — mints installation access tokens via App JWT auth.

Used by app_entrypoint.py (repository_dispatch mode) to authenticate
as the installed GitHub App and fetch PR diffs without requiring a
user-supplied GITHUB_TOKEN.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


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
        token: Optional[str] = None,
    ) -> str:
        """
        Fetch the unified diff for a pull request using the installation token.
        Returns the raw diff text.

        Pass `token` to reuse an already-minted installation token and avoid
        a redundant API call.
        """
        if token is None:
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

    # ── File content ─────────────────────────────────────────────────────────

    def get_file_content(
        self, token: str, owner: str, repo: str, path: str, ref: str
    ) -> Optional[str]:
        """
        Fetch the raw text of a file at a specific ref via GitHub Contents API.

        Returns None on any error (file too large, binary, directory, 404).
        Transparently decodes base64 — GitHub always returns content in base64.
        """
        import base64

        try:
            resp = httpx.get(
                f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}",
                headers={"Authorization": f"Bearer {token}", "Accept": self.ACCEPT},
                params={"ref": ref},
                timeout=15.0,
            )
        except httpx.HTTPError as exc:
            logger.warning("Cannot fetch %s@%s: %s", path, ref[:7], exc)
            return None

        if not resp.is_success:
            logger.debug("Cannot fetch %s@%s: HTTP %d", path, ref[:7], resp.status_code)
            return None

        data = resp.json()
        if isinstance(data, list):
            return None  # directory listing — skip

        encoding = data.get("encoding", "")
        raw = data.get("content", "")
        if encoding == "base64":
            try:
                return base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception as exc:
                logger.debug("base64 decode failed for %s: %s", path, exc)
                return None
        return None

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

    # ── Commit status ─────────────────────────────────────────────────────────

    def post_commit_status(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "AegisDiff / security",
    ) -> None:
        """
        Post a GitHub commit status on `sha`.

        `state` must be one of: success | failure | pending | error.
        Mirrors GitHubClient.post_commit_status but authenticates via App token.
        Non-fatal — logs a warning on any error.
        """
        try:
            token = self.get_installation_token(installation_id)
            resp = httpx.post(
                f"{self.BASE_URL}/repos/{owner}/{repo}/statuses/{sha}",
                headers={"Authorization": f"Bearer {token}", "Accept": self.ACCEPT},
                json={
                    "state": state,
                    "description": description[:140],
                    "context": context,
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            logger.info("Posted commit status '%s' on %s/%s@%s", state, owner, repo, sha[:7])
        except Exception as exc:
            logger.warning("Failed to post commit status (non-fatal): %s", exc)

    def upload_sarif(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        commit_sha: str,
        ref: str,
        sarif_b64: str,
    ) -> bool:
        """
        Upload a gzip+base64-encoded SARIF to GitHub Code Scanning via App token.

        Requires the GitHub App to have the `security_events` permission.
        Returns True on success, False on any error (non-fatal).
        """
        try:
            token = self.get_installation_token(installation_id)
            headers = {"Authorization": f"Bearer {token}", "Accept": self.ACCEPT}
            resp = httpx.post(
                f"{self.BASE_URL}/repos/{owner}/{repo}/code-scanning/sarifs",
                headers=headers,
                json={
                    "commit_sha": commit_sha,
                    "ref": ref,
                    "sarif": sarif_b64,
                    "tool_name": "AegisDiff",
                },
                timeout=20.0,
            )
            if resp.status_code == 403:
                logger.warning("SARIF upload skipped — GitHub App lacks security_events permission")
                return False
            if resp.status_code == 404:
                logger.warning(
                    "SARIF upload skipped — Code Scanning not available for %s/%s",
                    owner,
                    repo,
                )
                return False
            resp.raise_for_status()
            logger.info(
                "SARIF uploaded to GitHub Code Scanning (%s/%s sha=%s)",
                owner,
                repo,
                commit_sha[:7],
            )
            return True
        except Exception as exc:
            logger.warning("SARIF upload failed (non-fatal): %s", exc)
            return False
