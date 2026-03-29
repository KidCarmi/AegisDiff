"""Tests for GitHubAppClient — GitHub App installation token auth.

All tests mock get_installation_token() so we don't need a real RSA key.
HTTP calls are intercepted with respx.
"""
from __future__ import annotations

import base64
from unittest.mock import patch

import httpx
import pytest
import respx

from aegisdiff.github.app_client import GitHubAppClient

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

FAKE_TOKEN = "ghs_fake_installation_token"
APP_ID = "123456"
PRIVATE_KEY = "fake-pem"  # never decoded in these tests (get_installation_token mocked)
OWNER = "acme"
REPO = "webapp"
INSTALLATION_ID = 99
COMMIT_SHA = "abc1234def5678901234567890abcdef12345678"
BASE_URL = "https://api.github.com"


def make_client() -> GitHubAppClient:
    return GitHubAppClient(app_id=APP_ID, private_key_pem=PRIVATE_KEY)


def mock_token(client: GitHubAppClient) -> None:
    """Patch get_installation_token so tests never need a real JWT."""
    client.get_installation_token = lambda installation_id: FAKE_TOKEN  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# post_commit_status
# ---------------------------------------------------------------------------


class TestPostCommitStatus:
    @respx.mock
    def test_posts_to_correct_url(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", "All clear"
        )

        assert route.called

    @respx.mock
    def test_sends_correct_state_and_description(self):
        import json

        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "failure", "Security issue found"
        )

        payload = json.loads(route.calls.last.request.content)
        assert payload["state"] == "failure"
        assert payload["description"] == "Security issue found"

    @respx.mock
    def test_default_context_name(self):
        import json

        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", "OK"
        )

        payload = json.loads(route.calls.last.request.content)
        assert payload["context"] == "AegisDiff / security"

    @respx.mock
    def test_custom_context_name(self):
        import json

        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "pending", "Scanning…",
            context="custom/context"
        )

        payload = json.loads(route.calls.last.request.content)
        assert payload["context"] == "custom/context"

    @respx.mock
    def test_description_truncated_to_140_chars(self):
        import json

        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        long_desc = "A" * 200
        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", long_desc
        )

        payload = json.loads(route.calls.last.request.content)
        assert len(payload["description"]) == 140

    @respx.mock
    def test_uses_bearer_token_in_auth_header(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", "OK"
        )

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"

    def test_does_not_raise_on_http_error(self):
        """post_commit_status is non-fatal — HTTP errors must be swallowed."""
        client = make_client()
        mock_token(client)

        with respx.mock:
            url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
            respx.post(url).mock(return_value=httpx.Response(422, json={"message": "error"}))

            # Should NOT raise
            client.post_commit_status(
                INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", "OK"
            )

    def test_does_not_raise_on_network_error(self):
        client = make_client()
        mock_token(client)

        with respx.mock:
            url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
            respx.post(url).mock(side_effect=httpx.ConnectError("refused"))

            # Should NOT raise
            client.post_commit_status(
                INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "success", "OK"
            )

    @respx.mock
    def test_all_four_states_accepted(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(201, json={}))

        for state in ("success", "failure", "pending", "error"):
            client.post_commit_status(
                INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, state, f"State: {state}"
            )

        assert route.call_count == 4


# ---------------------------------------------------------------------------
# upload_sarif
# ---------------------------------------------------------------------------


class TestUploadSarif:
    @respx.mock
    def test_successful_upload_returns_true(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        respx.post(url).mock(return_value=httpx.Response(202, json={"id": "abc"}))

        result = client.upload_sarif(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "refs/pull/1/head", "sarif_b64_data"
        )

        assert result is True

    @respx.mock
    def test_403_returns_false_non_fatal(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        respx.post(url).mock(return_value=httpx.Response(403, json={"message": "forbidden"}))

        result = client.upload_sarif(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "refs/pull/1/head", "data"
        )

        assert result is False

    @respx.mock
    def test_404_returns_false_non_fatal(self):
        client = make_client()
        mock_token(client)
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        respx.post(url).mock(return_value=httpx.Response(404, json={"message": "not found"}))

        result = client.upload_sarif(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "refs/pull/1/head", "data"
        )

        assert result is False

    def test_network_error_returns_false(self):
        client = make_client()
        mock_token(client)

        with respx.mock:
            url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
            respx.post(url).mock(side_effect=httpx.ConnectError("refused"))

            result = client.upload_sarif(
                INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "refs/pull/1/head", "data"
            )

        assert result is False


# ---------------------------------------------------------------------------
# upsert_pr_comment
# ---------------------------------------------------------------------------


class TestUpsertPrComment:
    PR_NUMBER = 42
    MARKER = "<!-- aegisdiff -->"

    def _list_url(self):
        return f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{self.PR_NUMBER}/comments"

    def _create_url(self):
        return f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{self.PR_NUMBER}/comments"

    def _patch_url(self, comment_id: int):
        return f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/comments/{comment_id}"

    @respx.mock
    def test_creates_new_comment_when_none_exists(self):
        import json

        client = make_client()
        mock_token(client)

        respx.get(self._list_url()).mock(return_value=httpx.Response(200, json=[]))
        create_route = respx.post(self._create_url()).mock(
            return_value=httpx.Response(201, json={"id": 1})
        )

        client.upsert_pr_comment(
            INSTALLATION_ID, OWNER, REPO, self.PR_NUMBER, f"body {self.MARKER}", self.MARKER
        )

        assert create_route.called
        payload = json.loads(create_route.calls.last.request.content)
        assert self.MARKER in payload["body"]

    @respx.mock
    def test_updates_existing_comment_when_marker_found(self):
        import json

        client = make_client()
        mock_token(client)
        existing_comment_id = 99

        respx.get(self._list_url()).mock(
            return_value=httpx.Response(
                200,
                json=[{"id": existing_comment_id, "body": f"old content {self.MARKER}"}],
            )
        )
        patch_route = respx.patch(self._patch_url(existing_comment_id)).mock(
            return_value=httpx.Response(200, json={"id": existing_comment_id})
        )

        client.upsert_pr_comment(
            INSTALLATION_ID, OWNER, REPO, self.PR_NUMBER, f"new body {self.MARKER}", self.MARKER
        )

        assert patch_route.called
        payload = json.loads(patch_route.calls.last.request.content)
        assert "new body" in payload["body"]

    @respx.mock
    def test_creates_new_comment_when_existing_comment_has_different_marker(self):
        client = make_client()
        mock_token(client)

        # Existing comment does NOT contain our marker
        respx.get(self._list_url()).mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 10, "body": "some other comment without marker"}],
            )
        )
        create_route = respx.post(self._create_url()).mock(
            return_value=httpx.Response(201, json={"id": 11})
        )

        client.upsert_pr_comment(
            INSTALLATION_ID, OWNER, REPO, self.PR_NUMBER, f"body {self.MARKER}", self.MARKER
        )

        assert create_route.called


# ---------------------------------------------------------------------------
# get_file_content
# ---------------------------------------------------------------------------


class TestGetFileContent:
    @respx.mock
    def test_returns_decoded_utf8_content(self):
        client = make_client()
        raw = "print('hello')"
        encoded = base64.b64encode(raw.encode()).decode()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/main.py"
        respx.get(url).mock(
            return_value=httpx.Response(
                200, json={"encoding": "base64", "content": encoded}
            )
        )

        result = client.get_file_content(FAKE_TOKEN, OWNER, REPO, "main.py", COMMIT_SHA)

        assert result == raw

    @respx.mock
    def test_returns_none_on_404(self):
        client = make_client()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/missing.py"
        respx.get(url).mock(return_value=httpx.Response(404, json={"message": "Not Found"}))

        result = client.get_file_content(FAKE_TOKEN, OWNER, REPO, "missing.py", COMMIT_SHA)

        assert result is None

    @respx.mock
    def test_returns_none_for_directory_listing(self):
        client = make_client()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/src"
        # GitHub returns a list when the path is a directory
        respx.get(url).mock(
            return_value=httpx.Response(
                200, json=[{"name": "file.py", "type": "file"}]
            )
        )

        result = client.get_file_content(FAKE_TOKEN, OWNER, REPO, "src", COMMIT_SHA)

        assert result is None

    def test_returns_none_on_network_error(self):
        client = make_client()

        with respx.mock:
            url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/main.py"
            respx.get(url).mock(side_effect=httpx.ConnectError("refused"))

            result = client.get_file_content(FAKE_TOKEN, OWNER, REPO, "main.py", COMMIT_SHA)

        assert result is None
