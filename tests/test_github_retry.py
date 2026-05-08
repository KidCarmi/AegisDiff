"""Tests for the GitHub API retry helper and its conservative wiring.

Covers:
  * ``aegisdiff.github._retry.request_with_retry`` — the helper itself.
  * Integration through ``GitHubClient`` (manual GitHub Actions path).
  * Integration through ``GitHubAppClient`` (GitHub App path).

This PR's retry scope is intentionally narrow:
  ✓ GET requests (list comments, get file content, get PR diff)
  ✓ POST /app/installations/{id}/access_tokens (token mint)
  ✓ POST /code-scanning/sarifs (SARIF upload — replace-style)

Non-retry contracts also asserted:
  ✗ create_review (POST /pulls/{n}/reviews)
  ✗ Create / update PR issue comments
  ✗ post_commit_status

All tests run with sleeps disabled via the autouse conftest fixture.
Tests that need to inspect sleep calls override ``_retry._sleep`` again.
"""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

import aegisdiff.github._retry as _retry
from aegisdiff.github._retry import _backoff_seconds, request_with_retry
from aegisdiff.github.app_client import GitHubAppClient
from aegisdiff.github.client import GitHubClient

# ── Constants ────────────────────────────────────────────────────────────────

OWNER = "acme"
REPO = "webapp"
PR_NUMBER = 7
COMMIT_SHA = "abc1234def5678901234567890abcdef12345678"
INSTALLATION_ID = 99
FAKE_TOKEN = "test_fake_installation_token"
BASE_URL = "https://api.github.com"


def _b64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _make_client_manual() -> GitHubClient:
    return GitHubClient("test_token", f"{OWNER}/{REPO}")


def _make_client_app() -> GitHubAppClient:
    client = GitHubAppClient(app_id="123", private_key_pem="fake-pem")
    # Bypass JWT/RSA — every test that needs an installation token mocks
    # it explicitly. Tests that exercise get_installation_token's retry
    # behaviour DO call the real method.
    client.get_installation_token = lambda installation_id: FAKE_TOKEN  # type: ignore[method-assign]
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Helper-level: request_with_retry
# ─────────────────────────────────────────────────────────────────────────────


class TestRequestWithRetry:
    URL = f"{BASE_URL}/x"

    @respx.mock
    def test_returns_200_on_first_attempt(self):
        route = respx.get(self.URL).mock(return_value=httpx.Response(200, json={"ok": True}))
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 1

    @respx.mock
    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_retries_5xx_then_succeeds(self, status):
        route = respx.get(self.URL).mock(
            side_effect=[httpx.Response(status), httpx.Response(200, json={})]
        )
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_retries_through_three_attempts(self):
        route = respx.get(self.URL).mock(
            side_effect=[
                httpx.Response(502),
                httpx.Response(503),
                httpx.Response(200, json={}),
            ]
        )
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 3

    @respx.mock
    def test_returns_final_5xx_after_exhausted_retries(self):
        route = respx.get(self.URL).mock(return_value=httpx.Response(500))
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 500
        # Default max_attempts = 3 → 1 initial + 2 retries.
        assert route.call_count == 3

    @respx.mock
    def test_retries_on_timeout_then_succeeds(self):
        route = respx.get(self.URL).mock(
            side_effect=[httpx.ReadTimeout("slow"), httpx.Response(200)]
        )
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_retries_on_connect_error_then_succeeds(self):
        route = respx.get(self.URL).mock(
            side_effect=[httpx.ConnectError("refused"), httpx.Response(200)]
        )
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_retries_on_remote_protocol_error_then_succeeds(self):
        route = respx.get(self.URL).mock(
            side_effect=[
                httpx.RemoteProtocolError("server hung up"),
                httpx.Response(200),
            ]
        )
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == 200
        assert route.call_count == 2

    @respx.mock
    def test_reraises_final_timeout_after_exhausted_retries(self):
        route = respx.get(self.URL).mock(side_effect=httpx.ReadTimeout("never"))
        with pytest.raises(httpx.ReadTimeout):
            request_with_retry("GET", self.URL)
        assert route.call_count == 3

    @respx.mock
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 429])
    def test_does_not_retry_4xx(self, status):
        route = respx.get(self.URL).mock(return_value=httpx.Response(status))
        resp = request_with_retry("GET", self.URL)
        assert resp.status_code == status
        assert route.call_count == 1

    @respx.mock
    def test_max_attempts_one_never_retries(self):
        route = respx.get(self.URL).mock(return_value=httpx.Response(500))
        resp = request_with_retry("GET", self.URL, max_attempts=1)
        assert resp.status_code == 500
        assert route.call_count == 1

    @respx.mock
    def test_backoff_applied_between_retries(self, monkeypatch):
        sleeps: list[float] = []
        monkeypatch.setattr(_retry, "_sleep", lambda s: sleeps.append(s))
        respx.get(self.URL).mock(return_value=httpx.Response(500))
        request_with_retry("GET", self.URL)
        # 3 attempts → 2 sleeps between them.
        assert len(sleeps) == 2
        # All non-negative; second is non-decreasing relative to first
        # under the 0.5/2.0 schedule (with ±20% jitter, the lower bound
        # of the second still exceeds the upper bound of the first).
        assert all(s >= 0 for s in sleeps)
        # Lower bound of attempt-2 backoff (2.0s × 0.8 = 1.6s) is well
        # above the upper bound of attempt-1 (0.5s × 1.2 = 0.6s).
        assert sleeps[1] > sleeps[0]

    def test_backoff_seconds_schedule(self):
        # With ±20% jitter: 0.4-0.6, 1.6-2.4, 6.4-9.6 (capped at 8.0).
        for _ in range(20):
            assert 0.4 <= _backoff_seconds(1) <= 0.6
            assert 1.6 <= _backoff_seconds(2) <= 2.4
            # Cap kicks in for attempt 3: 8.0 × 0.8 = 6.4 to 8.0 × 1.2
            # would be 9.6, but the cap is applied *before* jitter.
            assert 6.4 <= _backoff_seconds(3) <= 9.6


# ─────────────────────────────────────────────────────────────────────────────
# GitHubClient — manual path retries
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubClientRetriesIdempotentCalls:
    @respx.mock
    def test_get_file_content_retries_500_then_succeeds(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/main.py"
        route = respx.get(url).mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(
                    200,
                    json={"encoding": "base64", "content": _b64_encode("print(1)")},
                ),
            ]
        )

        result = client.get_file_content("main.py", COMMIT_SHA)

        assert result == "print(1)"
        assert route.call_count == 2

    @respx.mock
    def test_get_file_content_does_not_retry_404(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/missing.py"
        route = respx.get(url).mock(return_value=httpx.Response(404, json={}))

        result = client.get_file_content("missing.py", COMMIT_SHA)

        assert result is None
        assert route.call_count == 1

    @respx.mock
    def test_find_comment_get_retries_500_then_succeeds(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        # 500 then 200 with a list that contains our marker.
        marker = "<!-- aegisdiff-report -->"
        route = respx.get(url).mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(
                    200,
                    json=[{"id": 42, "body": f"{marker}\nstale"}],
                ),
            ]
        )
        # Patch the PATCH (no retry) so the upsert can finish without
        # registering an unmocked route.
        respx.patch(
            f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/comments/42"
        ).mock(return_value=httpx.Response(200, json={}))

        client.upsert_pr_comment(PR_NUMBER, "fresh body", marker)

        # The GET retried, then succeeded → patched the existing comment.
        assert route.call_count == 2

    @respx.mock
    def test_upload_sarif_retries_503_then_succeeds(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        route = respx.post(url).mock(
            side_effect=[httpx.Response(503), httpx.Response(202, json={"id": "x"})]
        )

        ok = client.upload_sarif(COMMIT_SHA, "refs/pull/7/head", "fake-sarif")

        assert ok is True
        assert route.call_count == 2

    @respx.mock
    def test_upload_sarif_does_not_retry_403(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        route = respx.post(url).mock(return_value=httpx.Response(403, json={}))

        ok = client.upload_sarif(COMMIT_SHA, "refs/pull/7/head", "fake-sarif")

        assert ok is False
        assert route.call_count == 1

    @respx.mock
    def test_upload_sarif_does_not_retry_404(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        route = respx.post(url).mock(return_value=httpx.Response(404, json={}))

        ok = client.upload_sarif(COMMIT_SHA, "refs/pull/7/head", "fake-sarif")

        assert ok is False
        assert route.call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# GitHubClient — non-idempotent contracts intentionally NOT retried
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubClientNonIdempotentNotRetried:
    @respx.mock
    def test_create_review_does_not_retry_500(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        route = respx.post(url).mock(return_value=httpx.Response(500))

        ok = client.create_review(PR_NUMBER, COMMIT_SHA, "src/x.py", 10, "body")

        assert ok is False
        assert route.call_count == 1, "create_review POST must not be retried"

    @respx.mock
    def test_create_pr_comment_does_not_retry_500(self):
        client = _make_client_manual()
        list_url = f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        # GET returns empty list (no existing comment) → upsert calls
        # POST to create a new one. The POST must NOT be retried.
        respx.get(list_url).mock(return_value=httpx.Response(200, json=[]))
        post_route = respx.post(list_url).mock(return_value=httpx.Response(500))

        client.upsert_pr_comment(PR_NUMBER, "new body", "<!-- aegisdiff-report -->")

        assert post_route.call_count == 1, "create-comment POST must not be retried"

    @respx.mock
    def test_update_pr_comment_does_not_retry_500(self):
        client = _make_client_manual()
        list_url = f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        marker = "<!-- aegisdiff-report -->"
        respx.get(list_url).mock(
            return_value=httpx.Response(200, json=[{"id": 42, "body": f"{marker}\nold"}])
        )
        patch_route = respx.patch(
            f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/comments/42"
        ).mock(return_value=httpx.Response(500))

        client.upsert_pr_comment(PR_NUMBER, "fresh", marker)

        assert patch_route.call_count == 1, "update-comment PATCH must not be retried"

    @respx.mock
    def test_post_commit_status_does_not_retry_500(self):
        client = _make_client_manual()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(500))

        client.post_commit_status(COMMIT_SHA, "failure", "boom")

        assert route.call_count == 1, "post_commit_status must not be retried"


# ─────────────────────────────────────────────────────────────────────────────
# GitHubAppClient — App path retries
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubAppClientRetriesIdempotentCalls:
    @respx.mock
    def test_get_installation_token_retries_500_then_succeeds(self, monkeypatch):
        client = GitHubAppClient(app_id="123", private_key_pem="fake-pem")
        # Bypass real JWT signing — return a stub.
        monkeypatch.setattr(client, "_make_jwt", lambda: "fake-jwt")

        url = f"{BASE_URL}/app/installations/{INSTALLATION_ID}/access_tokens"
        route = respx.post(url).mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(201, json={"token": "real-token"}),
            ]
        )

        token = client.get_installation_token(INSTALLATION_ID)

        assert token == "real-token"
        assert route.call_count == 2

    @respx.mock
    def test_get_pr_diff_retries_503_then_succeeds(self):
        client = _make_client_app()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}"
        route = respx.get(url).mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, text="diff --git a/x b/x\n"),
            ]
        )

        diff = client.get_pr_diff(INSTALLATION_ID, OWNER, REPO, PR_NUMBER, token=FAKE_TOKEN)

        assert "diff --git" in diff
        assert route.call_count == 2

    @respx.mock
    def test_get_file_content_retries_500_then_succeeds(self):
        client = _make_client_app()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/contents/main.py"
        route = respx.get(url).mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(
                    200,
                    json={"encoding": "base64", "content": _b64_encode("print(1)")},
                ),
            ]
        )

        result = client.get_file_content(FAKE_TOKEN, OWNER, REPO, "main.py", COMMIT_SHA)

        assert result == "print(1)"
        assert route.call_count == 2

    @respx.mock
    def test_upload_sarif_retries_503_then_succeeds(self):
        client = _make_client_app()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        route = respx.post(url).mock(
            side_effect=[httpx.Response(503), httpx.Response(202, json={"id": "x"})]
        )

        ok = client.upload_sarif(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "refs/pull/7/head", "fake-sarif"
        )

        assert ok is True
        assert route.call_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# GitHubAppClient — non-idempotent contracts intentionally NOT retried
# ─────────────────────────────────────────────────────────────────────────────


class TestGitHubAppClientNonIdempotentNotRetried:
    @respx.mock
    def test_app_create_review_does_not_retry_500(self):
        client = _make_client_app()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        route = respx.post(url).mock(return_value=httpx.Response(500))

        ok = client.create_review(
            INSTALLATION_ID, OWNER, REPO, PR_NUMBER, COMMIT_SHA, "src/x.py", 10, "body"
        )

        assert ok is False
        assert route.call_count == 1, "App-path create_review must not be retried"

    @respx.mock
    def test_app_create_pr_comment_does_not_retry_500(self):
        client = _make_client_app()
        list_url = f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        respx.get(list_url).mock(return_value=httpx.Response(200, json=[]))
        post_route = respx.post(list_url).mock(return_value=httpx.Response(500))

        # App-path upsert raises on 500 (existing fatal contract), but we
        # only care that the POST is not retried before that raise.
        with pytest.raises(httpx.HTTPStatusError):
            client.upsert_pr_comment(
                INSTALLATION_ID, OWNER, REPO, PR_NUMBER, "body", "<!-- aegisdiff-report -->"
            )

        assert post_route.call_count == 1, "App-path create-comment POST must not be retried"

    @respx.mock
    def test_app_update_pr_comment_does_not_retry_500(self):
        client = _make_client_app()
        list_url = f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        marker = "<!-- aegisdiff-report -->"
        respx.get(list_url).mock(
            return_value=httpx.Response(200, json=[{"id": 42, "body": f"{marker}\nold"}])
        )
        patch_route = respx.patch(
            f"{BASE_URL}/repos/{OWNER}/{REPO}/issues/comments/42"
        ).mock(return_value=httpx.Response(500))

        with pytest.raises(httpx.HTTPStatusError):
            client.upsert_pr_comment(INSTALLATION_ID, OWNER, REPO, PR_NUMBER, "fresh", marker)

        assert patch_route.call_count == 1, "App-path update-comment PATCH must not be retried"

    @respx.mock
    def test_app_post_commit_status_does_not_retry_500(self):
        client = _make_client_app()
        url = f"{BASE_URL}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        route = respx.post(url).mock(return_value=httpx.Response(500))

        client.post_commit_status(
            INSTALLATION_ID, OWNER, REPO, COMMIT_SHA, "failure", "boom"
        )

        assert route.call_count == 1, "App-path post_commit_status must not be retried"
