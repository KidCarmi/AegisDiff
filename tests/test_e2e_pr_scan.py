"""
End-to-end integration test — full PR scan pipeline (GitHub App path).

Simulates the complete flow triggered by a pull_request webhook:

  [1] app_entrypoint.main() starts
        ↓
  [2] GitHubAppClient.get_installation_token() → fake token
        ↓
  [3] GET  /repos/acme/webapp/pulls/7         → sample.diff (OS command injection)
        ↓
  [4] GET  /repos/acme/webapp/contents/...    → full file content (for AST context)
        ↓
  [5] POST https://models.inference.ai.azure.com/chat/completions
           → LLM returns TRUE_POSITIVE: CWE-78 OS Command Injection
        ↓
  [6] POST /repos/acme/webapp/pulls/7/reviews            → inline comment on vuln line
  [7] GET  /repos/acme/webapp/issues/7/comments          → no existing comment
  [8] POST /repos/acme/webapp/issues/7/comments          → summary comment
  [9] POST /repos/acme/webapp/statuses/{sha}             → commit status "failure"
  [10] POST /repos/acme/webapp/code-scanning/sarifs      → SARIF upload
  [11] POST https://aegisdiff.app/api/ingest             → metadata to dashboard

No real GitHub API calls, no real LLM calls, no real RSA key needed.
All external HTTP is intercepted by respx.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from aegisdiff.llm.providers.github_models import GITHUB_MODELS_URL

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

OWNER = "acme"
REPO = "webapp"
PR_NUMBER = 7
COMMIT_SHA = "abc1234def5678901234567890abcdef12345678"
INSTALLATION_ID = 99
FAKE_TOKEN = "ghs_fake_installation_token"
INGEST_URL = "https://aegisdiff.app/api/ingest"
INGEST_TOKEN = "ak_test_ingest_token_xyz"
GITHUB_API = "https://api.github.com"

SAMPLE_DIFF = (Path(__file__).parent / "fixtures" / "sample.diff").read_text()

# The LLM returns this verdict for the sample diff (CWE-78 OS Command Injection)
LLM_VERDICT_JSON = json.dumps(
    {
        "verdict": "TRUE_POSITIVE",
        "severity": "HIGH",
        "cwe_id": "CWE-78",
        "confidence": 0.95,
        "title": "OS Command Injection via shell=True",
        "summary": (
            "run_report() passes unsanitised user input directly to "
            "subprocess.check_output with shell=True, enabling OS command injection. "
            "An attacker can supply report_name='; rm -rf /' to execute arbitrary commands."
        ),
        "evidence": (
            'subprocess.check_output(f"generate_report.sh {report_name}", shell=True)'
        ),
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": "report_name HTTP query parameter",
        "remediation": (
            "Pass a list to subprocess instead of a shell string and validate "
            "report_name against a strict allowlist of known report identifiers."
        ),
        "false_positive_reason": None,
    }
)

GITHUB_MODELS_RESPONSE = {
    "id": "chatcmpl-e2e-test",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": LLM_VERDICT_JSON},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 312, "completion_tokens": 148, "total_tokens": 460},
    "model": "Llama-3.3-70B-Instruct",
}

FILE_CONTENT_PYTHON = """\
from django.http import HttpResponse, FileResponse
import subprocess
import os

def health(request):
    return HttpResponse("ok")

def run_report(request):
    report_name = request.GET.get('report', 'summary')
    result = subprocess.check_output(f"generate_report.sh {report_name}", shell=True)
    return HttpResponse(result)

def download_file(request):
    filename = request.GET.get('file', 'readme.txt')
    path = f"/var/app/uploads/{filename}"
    with open(path, 'rb') as f:
        return FileResponse(f)
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _env_vars() -> dict:
    """Environment variables that would normally be injected by the Actions workflow."""
    return {
        "GITHUB_APP_ID": "123456",
        "GITHUB_APP_PRIVATE_KEY": "fake-pem-never-decoded",
        "INSTALLATION_ID": str(INSTALLATION_ID),
        "TARGET_REPO": f"{OWNER}/{REPO}",
        "PR_NUMBER": str(PR_NUMBER),
        "COMMIT_SHA": COMMIT_SHA,
        # Only GitHub Models available — the zero-config fallback.
        # No OPENROUTER_API_KEY / GROQ_API_KEY so the provider list is minimal.
        "GITHUB_TOKEN": "ghs_github_actions_token",
        "AEGISDIFF_INGEST_URL": INGEST_URL,
        "AEGISDIFF_INGEST_TOKEN": INGEST_TOKEN,
    }


import base64 as _b64


def _b64_encode(text: str) -> str:
    return _b64.b64encode(text.encode()).decode()


# ─────────────────────────────────────────────────────────────────────────────
# The end-to-end test
# ─────────────────────────────────────────────────────────────────────────────


class TestE2EPRScan:
    """
    Full pipeline integration test.

    Every external HTTP call is mocked so the test is:
      - Deterministic  (LLM always returns CWE-78 TRUE_POSITIVE)
      - Offline        (no real GitHub / LLM / dashboard calls)
      - Fast           (no real network I/O, no sleep)
    """

    @respx.mock
    def test_full_pipeline_true_positive(self, capsys, monkeypatch):
        """
        Feeds the sample.diff (OS command injection) through the full pipeline and
        verifies that:
          1. The LLM was called with the diff
          2. A PR comment was posted with the TRUE_POSITIVE verdict
          3. A commit status of "failure" was posted (blocks merge)
          4. A SARIF upload was attempted
          5. The dashboard /api/ingest received the scan metadata
        """
        # ── Set environment variables ────────────────────────────────────────
        for key, val in _env_vars().items():
            monkeypatch.setenv(key, val)

        # ── Register all mocked HTTP routes ─────────────────────────────────

        # [3] Fetch PR diff (Accept: application/vnd.github.v3.diff)
        diff_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}"
        ).mock(return_value=httpx.Response(200, text=SAMPLE_DIFF))

        # [4] Fetch full file content for code-context extractor
        file_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": _b64_encode(FILE_CONTENT_PYTHON),
                },
            )
        )

        # [5] GitHub Models LLM call
        llm_route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=GITHUB_MODELS_RESPONSE)
        )

        # [6] Create inline review comment (may or may not be called depending on AST)
        review_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        ).mock(return_value=httpx.Response(200, json={"id": 1}))

        # [7] List existing PR comments (none exist)
        list_comments_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(200, json=[]))

        # [8] Create PR summary comment
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 42}))

        # [9] Post commit status
        status_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        ).mock(return_value=httpx.Response(201, json={}))

        # [10] Upload SARIF to Code Scanning
        sarif_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        ).mock(return_value=httpx.Response(202, json={"id": "sarif-abc"}))

        # [11] Send metadata to dashboard
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        # ── Patch: bypass RSA JWT (no real private key in tests) ─────────────
        # ── Patch: skip OIDC token fetch (not available outside Actions) ─────
        from aegisdiff.github.app_client import GitHubAppClient

        with (
            patch.object(
                GitHubAppClient,
                "get_installation_token",
                return_value=FAKE_TOKEN,
            ),
            patch(
                "aegisdiff.llm.platform_keys.get_oidc_token",
                return_value=None,
            ),
        ):
            # ── Run the pipeline — expects sys.exit(1) for high-confidence TP ─
            from aegisdiff.app_entrypoint import main

            with pytest.raises(SystemExit) as exc_info:
                main()

        exit_code = exc_info.value.code

        # ── Print a human-readable trace of what happened ────────────────────
        print("\n" + "=" * 70)
        print("  AegisDiff End-to-End PR Scan — Pipeline Trace")
        print("=" * 70)
        print(f"  Repo    : {OWNER}/{REPO}  PR #{PR_NUMBER}")
        print(f"  Commit  : {COMMIT_SHA[:7]}")
        print(f"  Diff    : sample.diff ({SAMPLE_DIFF.count(chr(10))} lines)")
        print()

        print("  [1] DIFF FETCHED")
        print(f"       GET /repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}")
        print(f"       Diff size : {len(SAMPLE_DIFF)} chars")
        print(f"       Called    : {'✓' if diff_route.called else '✗'}")
        print()

        print("  [2] FILE CONTEXT FETCHED")
        print(f"       GET /repos/{OWNER}/{REPO}/contents/app/views.py")
        print(f"       Called    : {'✓' if file_route.called else '✗'}")
        print()

        print("  [3] AI SCAN")
        print(f"       POST {GITHUB_MODELS_URL}")
        print(f"       Called    : {'✓' if llm_route.called else '✗'}")
        if llm_route.called:
            llm_payload = json.loads(llm_route.calls.last.request.content)
            user_msg = llm_payload["messages"][1]["content"]
            print(f"       Model     : {llm_payload['model']}")
            print(f"       Diff sent : {'sample.diff content present' if 'subprocess' in user_msg else '?'}")
        print()

        verdict_data = json.loads(LLM_VERDICT_JSON)
        print("  [4] VERDICT")
        print(f"       Result    : {verdict_data['verdict']}")
        print(f"       Severity  : {verdict_data['severity']}")
        print(f"       CWE       : {verdict_data['cwe_id']}")
        print(f"       Confidence: {verdict_data['confidence']:.0%}")
        print(f"       Title     : {verdict_data['title']}")
        print(f"       Summary   : {verdict_data['summary'][:80]}...")
        print()

        print("  [5] PR COMMENT POSTED")
        print(f"       POST /repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments")
        print(f"       Called    : {'✓' if create_comment_route.called else '✗'}")
        if create_comment_route.called:
            comment_body = json.loads(
                create_comment_route.calls.last.request.content
            )["body"]
            first_line = comment_body.split("\n")[0]
            print(f"       Header    : {first_line}")
        print()

        print("  [6] COMMIT STATUS POSTED  (enables branch protection)")
        print(f"       POST /repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA[:7]}...")
        print(f"       Called    : {'✓' if status_route.called else '✗'}")
        if status_route.called:
            status_payload = json.loads(status_route.calls.last.request.content)
            print(f"       State     : {status_payload['state']}")
            print(f"       Desc      : {status_payload['description']}")
            print(f"       Context   : {status_payload['context']}")
        print()

        print("  [7] SARIF → GitHub Code Scanning")
        print(f"       POST /repos/{OWNER}/{REPO}/code-scanning/sarifs")
        print(f"       Called    : {'✓' if sarif_route.called else '✗'}")
        print()

        print("  [8] DASHBOARD INGEST")
        print(f"       POST {INGEST_URL}")
        print(f"       Called    : {'✓' if ingest_route.called else '✗'}")
        if ingest_route.called:
            ingest_body = json.loads(ingest_route.calls.last.request.content)
            # may be a list (chunked) or a single dict
            item = ingest_body[0] if isinstance(ingest_body, list) else ingest_body
            print(f"       Verdict   : {item['verdict']}")
            print(f"       Severity  : {item['severity']}")
            print(f"       CWE       : {item['cwe_id']}")
            print(f"       PR        : #{item['pr_number']}")
            print(f"       Commit    : {item['commit_sha'][:7]}")
        print()

        print(f"  [9] EXIT CODE : {exit_code}  (1 = high-confidence TP blocks merge)")
        print("=" * 70 + "\n")

        # ── Assertions ───────────────────────────────────────────────────────

        # Diff was fetched
        assert diff_route.called, "Expected PR diff to be fetched"

        # LLM was called
        assert llm_route.called, "Expected LLM to be called for analysis"

        # The diff was included in the LLM request
        llm_payload = json.loads(llm_route.calls.last.request.content)
        user_message = llm_payload["messages"][1]["content"]
        assert "subprocess" in user_message, "Expected diff content in LLM prompt"
        assert "shell=True" in user_message, "Expected vulnerable line in LLM prompt"

        # PR comment was posted
        assert create_comment_route.called, "Expected PR comment to be posted"
        comment_body = json.loads(
            create_comment_route.calls.last.request.content
        )["body"]
        assert "<!-- aegisdiff-report -->" in comment_body, "Expected AegisDiff marker in comment"
        # Comment should mention the vulnerability
        assert any(
            kw in comment_body
            for kw in ("TRUE_POSITIVE", "true_positive", "True Positive", "HIGH", ":x:", ":red_circle:")
        ), "Expected TRUE_POSITIVE indicator in PR comment"

        # Commit status posted with "failure" state (TRUE_POSITIVE blocks merge)
        assert status_route.called, "Expected commit status to be posted"
        status_payload = json.loads(status_route.calls.last.request.content)
        assert status_payload["state"] == "failure", (
            f"Expected 'failure' status for TRUE_POSITIVE, got '{status_payload['state']}'"
        )
        assert status_payload["context"] == "AegisDiff / security"

        # SARIF was uploaded
        assert sarif_route.called, "Expected SARIF to be uploaded to Code Scanning"

        # Dashboard received the metadata
        assert ingest_route.called, "Expected scan metadata to be sent to dashboard"
        ingest_body = json.loads(ingest_route.calls.last.request.content)
        item = ingest_body[0] if isinstance(ingest_body, list) else ingest_body
        assert item["verdict"] == "TRUE_POSITIVE"
        assert item["cwe_id"] == "CWE-78"
        assert item["pr_number"] == PR_NUMBER
        assert item["commit_sha"] == COMMIT_SHA
        assert item["pr_url"] == f"https://github.com/{OWNER}/{REPO}/pull/{PR_NUMBER}"

        # Authorization header was correct on GitHub API calls
        assert (
            status_route.calls.last.request.headers["Authorization"]
            == f"Bearer {FAKE_TOKEN}"
        )

        # High-confidence TRUE_POSITIVE → pipeline exits with code 1 (blocks merge)
        assert exit_code == 1, (
            "Expected exit code 1 for high-confidence TRUE_POSITIVE to block merge"
        )

    @respx.mock
    def test_full_pipeline_false_positive_exits_0(self, monkeypatch):
        """
        When the LLM returns FALSE_POSITIVE the pipeline must:
          - Post a "no issues" PR comment
          - Post a "success" commit status (allows merge)
          - Exit with code 0
        """
        for key, val in _env_vars().items():
            monkeypatch.setenv(key, val)

        false_positive_verdict = json.dumps(
            {
                "verdict": "FALSE_POSITIVE",
                "severity": "N/A",
                "cwe_id": "N/A",
                "confidence": 0.91,
                "title": "No exploitable vulnerability",
                "summary": "The subprocess call is guarded by an allowlist check above.",
                "evidence": "",
                "sanitizer_found": True,
                "sanitizer_description": "Allowlist validation before subprocess call",
                "attack_vector": None,
                "remediation": None,
                "false_positive_reason": (
                    "User input is validated against a hardcoded allowlist "
                    "before being passed to the shell."
                ),
            }
        )

        respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}"
        ).mock(return_value=httpx.Response(200, text=SAMPLE_DIFF))
        respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py"
        ).mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
        respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    **GITHUB_MODELS_RESPONSE,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": false_positive_verdict,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                },
            )
        )
        respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(200, json=[]))
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 43}))
        status_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}"
        ).mock(return_value=httpx.Response(201, json={}))
        respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs"
        ).mock(return_value=httpx.Response(202, json={"id": "sarif-fp"}))
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        from aegisdiff.github.app_client import GitHubAppClient

        with (
            patch.object(
                GitHubAppClient, "get_installation_token", return_value=FAKE_TOKEN
            ),
            patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None),
        ):
            from aegisdiff.app_entrypoint import main

            # FALSE_POSITIVE → sys.exit(0) → no SystemExit raised (or code 0)
            try:
                main()
                exited_with = 0
            except SystemExit as e:
                exited_with = e.code

        # Commit status must be "success"
        assert status_route.called
        status_payload = json.loads(status_route.calls.last.request.content)
        assert status_payload["state"] == "success", (
            f"Expected 'success' status for FALSE_POSITIVE, got '{status_payload['state']}'"
        )

        # Dashboard still receives the metadata
        assert ingest_route.called
        item_raw = json.loads(ingest_route.calls.last.request.content)
        item = item_raw[0] if isinstance(item_raw, list) else item_raw
        assert item["verdict"] == "FALSE_POSITIVE"

        # Pipeline exits cleanly
        assert exited_with == 0, (
            f"Expected exit code 0 for FALSE_POSITIVE, got {exited_with}"
        )

        print(f"\n  FALSE_POSITIVE → status=success, exit 0 ✓")
        print(f"  Dashboard received verdict=FALSE_POSITIVE ✓")
