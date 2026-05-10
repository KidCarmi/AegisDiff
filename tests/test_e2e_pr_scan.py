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

The ``TestE2ELargePRScan`` class at the bottom of this file exercises the
same pipeline against a synthetic 28-file diff that trips Large PR Risk
Triage Mode (>25 changed files), and asserts the Large PR coverage block,
banner, skip-reason buckets, LLM-call gating, and inline-post counter.
"""

from __future__ import annotations

import base64 as _b64
import json
import logging
import re
from pathlib import Path
from unittest.mock import patch

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
FAKE_TOKEN = "test_fake_installation_token"
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
        "evidence": ('subprocess.check_output(f"generate_report.sh {report_name}", shell=True)'),
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
        "GITHUB_TOKEN": "test_github_actions_token",
        "AEGISDIFF_INGEST_URL": INGEST_URL,
        "AEGISDIFF_INGEST_TOKEN": INGEST_TOKEN,
    }


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
        diff_route = respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}").mock(
            return_value=httpx.Response(200, text=SAMPLE_DIFF)
        )

        # [4] Fetch full file content for code-context extractor
        file_route = respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py").mock(
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
        respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews").mock(
            return_value=httpx.Response(200, json={"id": 1})
        )

        # [7] List existing PR comments (none exist)
        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments").mock(
            return_value=httpx.Response(200, json=[])
        )

        # [8] Create PR summary comment
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 42}))

        # [9] Post commit status
        status_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}").mock(
            return_value=httpx.Response(201, json={})
        )

        # [10] Upload SARIF to Code Scanning
        sarif_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs").mock(
            return_value=httpx.Response(202, json={"id": "sarif-abc"})
        )

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
            diff_state = "sample.diff content present" if "subprocess" in user_msg else "?"
            print(f"       Diff sent : {diff_state}")
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
            comment_body = json.loads(create_comment_route.calls.last.request.content)["body"]
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
        comment_body = json.loads(create_comment_route.calls.last.request.content)["body"]
        assert "<!-- aegisdiff-report -->" in comment_body, "Expected AegisDiff marker in comment"
        # Comment should mention the vulnerability
        tp_keywords = (
            "TRUE_POSITIVE",
            "true_positive",
            "True Positive",
            "HIGH",
            ":x:",
            ":red_circle:",
        )
        assert any(kw in comment_body for kw in tp_keywords), (
            "Expected TRUE_POSITIVE indicator in PR comment"
        )

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
        assert status_route.calls.last.request.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"

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

        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}").mock(
            return_value=httpx.Response(200, text=SAMPLE_DIFF)
        )
        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
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
        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments").mock(
            return_value=httpx.Response(200, json=[])
        )
        respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments").mock(
            return_value=httpx.Response(201, json={"id": 43})
        )
        status_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}").mock(
            return_value=httpx.Response(201, json={})
        )
        respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs").mock(
            return_value=httpx.Response(202, json={"id": "sarif-fp"})
        )
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        from aegisdiff.github.app_client import GitHubAppClient

        with (
            patch.object(GitHubAppClient, "get_installation_token", return_value=FAKE_TOKEN),
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
        assert exited_with == 0, f"Expected exit code 0 for FALSE_POSITIVE, got {exited_with}"

        print("\n  FALSE_POSITIVE → status=success, exit 0 ✓")
        print("  Dashboard received verdict=FALSE_POSITIVE ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Large PR Risk Triage Mode — E2E coverage
# ─────────────────────────────────────────────────────────────────────────────


def _diff_block(path: str, added_lines: list[str], context: str = "import os") -> str:
    """Build a single-file unified-diff block."""
    added = "\n".join(f"+{line}" for line in added_lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,1 +1,{len(added_lines) + 1} @@\n"
        f" {context}\n"
        f"{added}\n"
    )


# The single high-risk file in the Large PR fixture. Carries a CWE-78
# subprocess(shell=True) sink on an added line so the AST extractor can
# attach a line_number to the verdict and trigger an inline review.
LARGE_PR_AUTH_PATH = "src/auth/login.py"
LARGE_PR_AUTH_FILE_CONTENT = """\
import subprocess
from django.http import HttpResponse


def login(request):
    user = request.GET.get('user', '')
    result = subprocess.check_output(f'echo {user}', shell=True)
    return HttpResponse(result)
"""


def _build_large_pr_diff() -> str:
    """28-file synthetic diff that trips Large PR Risk Triage Mode.

    Composition:
      *  1 high-risk auth file with a real subprocess(shell=True) sink
      * 12 docs (skip → ``docs``)
      *  8 generated/build artefacts (skip → ``generated``)
      *  3 static assets (skip → ``static_asset``)
      *  1 lockfile (skip → ``dependency_only``)
      *  1 test file (deprioritize)
      *  2 neutral utility source files (analyze, low risk)
    """
    blocks: list[str] = []

    blocks.append(
        _diff_block(
            LARGE_PR_AUTH_PATH,
            [
                "import subprocess",
                "from django.http import HttpResponse",
                "def login(request):",
                "    user = request.GET.get('user', '')",
                "    result = subprocess.check_output(f'echo {user}', shell=True)",
                "    return HttpResponse(result)",
            ],
        )
    )
    for i in range(12):
        blocks.append(_diff_block(f"docs/page_{i}.md", [f"Updated section {i}."]))
    for i in range(8):
        blocks.append(_diff_block(f"dist/bundle_{i}.js", [f"console.log('built {i}');"]))
    for i in range(3):
        blocks.append(_diff_block(f"web/public/asset_{i}.svg", [f"<svg id='{i}'/>"]))
    blocks.append(_diff_block("package-lock.json", ['"version": "1.0.1",']))
    blocks.append(
        _diff_block(
            "tests/test_module.py",
            ["def test_smoke(): assert True"],
        )
    )
    for i in range(2):
        blocks.append(
            _diff_block(
                f"src/utils/helper_{i}.py",
                [f"def helper_{i}(): return {i}"],
            )
        )
    return "".join(blocks)


# LLM mock response — same TRUE_POSITIVE for every chunk in this E2E.
LARGE_PR_LLM_VERDICT_JSON = json.dumps(
    {
        "verdict": "TRUE_POSITIVE",
        "severity": "HIGH",
        "cwe_id": "CWE-78",
        "confidence": 0.92,
        "title": "OS Command Injection via shell=True",
        "summary": "User input flows into subprocess.check_output with shell=True.",
        "evidence": "subprocess.check_output(f'echo {user}', shell=True)",
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": "user query parameter",
        "remediation": "Use a list argv and validate user input.",
        "false_positive_reason": None,
    }
)


LARGE_PR_LLM_RESPONSE = {
    "id": "chatcmpl-large-pr-test",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": LARGE_PR_LLM_VERDICT_JSON},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 220, "completion_tokens": 110, "total_tokens": 330},
    "model": "Llama-3.3-70B-Instruct",
}


class TestE2ELargePRScan:
    """Full GitHub App pipeline E2E for Large PR Risk Triage Mode.

    Same respx pattern as ``TestE2EPRScan``: every external HTTP call is
    mocked, no network, no real GitHub or LLM. The synthetic diff has 28
    files so detection trips on changed_files > 25.
    """

    @respx.mock
    def test_full_pipeline_large_pr_mode(self, capsys, monkeypatch):
        for key, val in _env_vars().items():
            monkeypatch.setenv(key, val)

        large_pr_diff = _build_large_pr_diff()

        # Sanity: the synthetic diff really does trigger Large PR Mode.
        file_count = large_pr_diff.count("diff --git ")
        assert file_count == 28, f"fixture changed shape: {file_count} files"

        # ── PR diff ─────────────────────────────────────────────────────────
        diff_route = respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}").mock(
            return_value=httpx.Response(200, text=large_pr_diff)
        )

        # ── File contents — specific mock for the auth file (with sink),
        # catch-all 404 for everything else. The order matters: respx tries
        # routes in registration order and returns the first match.
        auth_content_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/{LARGE_PR_AUTH_PATH}"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": _b64_encode(LARGE_PR_AUTH_FILE_CONTENT),
                },
            )
        )
        contents_pattern = re.compile(rf"^{re.escape(GITHUB_API)}/repos/{OWNER}/{REPO}/contents/.*")
        catchall_content_route = respx.get(url__regex=contents_pattern).mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )

        # ── LLM ─────────────────────────────────────────────────────────────
        llm_route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=LARGE_PR_LLM_RESPONSE)
        )

        # ── Inline review (auth file is the only one with a known sink line)
        review_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        ).mock(return_value=httpx.Response(200, json={"id": 11}))

        # ── Summary comment upsert ──────────────────────────────────────────
        list_comments_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(200, json=[]))
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 99}))

        # ── Commit status, SARIF, dashboard ingest ─────────────────────────
        status_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}").mock(
            return_value=httpx.Response(201, json={})
        )
        sarif_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs").mock(
            return_value=httpx.Response(202, json={"id": "sarif-large"})
        )
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        from aegisdiff.github.app_client import GitHubAppClient

        with (
            patch.object(GitHubAppClient, "get_installation_token", return_value=FAKE_TOKEN),
            patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None),
        ):
            from aegisdiff.app_entrypoint import main

            try:
                main()
                exit_code = 0
            except SystemExit as e:
                exit_code = e.code

        # ── ASSERTIONS ──────────────────────────────────────────────────────

        # 1. Pipeline ran end to end.
        assert diff_route.called
        assert llm_route.called
        assert create_comment_route.called
        assert status_route.called
        assert sarif_route.called, "SARIF upload should still be attempted in Large PR Mode"
        assert ingest_route.called, "Dashboard ingest should still fire in Large PR Mode"

        # 2. Banner appears in summary PR comment.
        comment_body = json.loads(create_comment_route.calls.last.request.content)["body"]
        assert "AegisDiff ran in Large PR Risk Triage Mode" in comment_body, (
            "Large PR banner missing from summary comment"
        )
        assert "Large PR Risk Triage Mode coverage" in comment_body, (
            "Large PR coverage <details> block missing"
        )

        # 3. Coverage block reports the planned counts.
        assert "Files changed:" in comment_body
        assert "Files analyzed:" in comment_body
        assert "Files skipped:" in comment_body
        assert "LLM calls used:" in comment_body
        assert "Budget exhausted:" in comment_body

        # 4. Skip-reason buckets present for the categories in the fixture.
        assert "`docs`" in comment_body, "docs skip-reason missing"
        assert "`generated`" in comment_body, "generated skip-reason missing"
        assert "`static_asset`" in comment_body, "static_asset skip-reason missing"
        assert "`dependency_only`" in comment_body, "dependency_only skip-reason missing"

        # 5. The Large PR triggers note carries our threshold reason.
        assert "changed_files=28" in comment_body, "Large PR trigger reason missing"

        # 6. The full raw diff is NEVER sent as a single LLM prompt.
        assert llm_route.call_count >= 1
        for call in llm_route.calls:
            payload = json.loads(call.request.content)
            user_msg = payload["messages"][1]["content"]
            assert large_pr_diff not in user_msg, (
                "Large PR Mode must not send the full raw diff in one prompt"
            )
            # Each prompt must carry the Large PR addendum so the model
            # applies the change-only constraints.
            sys_msg = payload["messages"][0]["content"]
            assert "LARGE PR RISK TRIAGE MODE" in sys_msg, (
                "Large PR addendum missing from system prompt"
            )
            assert "UNTRUSTED INPUT" in sys_msg, (
                "Prompt-injection defense missing from system prompt"
            )

        # 7. LLM call count respects the budget. With our fixture the only
        # ANALYZE-eligible files are 1 auth + 2 utility helpers; the test
        # file is DEPRIORITIZED but still gets a call once the analyze
        # files are covered. Default max_llm_calls_per_pr is 40; the run
        # must stay well within that.
        assert llm_route.call_count <= 40, f"LLM call budget exceeded: {llm_route.call_count} > 40"
        assert llm_route.call_count >= 1, "Expected at least one LLM call"

        # 8. Inline-comment count reflects only successful create_review
        # returns. The auth file has a real sink line; helpers and the
        # test file have no sinks, so they don't trigger inline reviews.
        if review_route.called:
            posted = review_route.call_count
            assert f"Inline comments posted: **{posted}**" in comment_body, (
                f"Summary inline-post count out of sync with actual posts "
                f"(posted={posted}, comment={comment_body!r})"
            )
        else:
            # No inline reviews succeeded → summary should report zero or
            # omit the line entirely. Either is acceptable; the contract
            # is "don't overstate".
            assert (
                "Inline comments posted: **0**" in comment_body
                or "Inline comments posted:" not in comment_body
            )

        # 9. Dashboard ingest payload still reflects scan metadata
        # (no new schema, just the existing fields).
        ingest_body = json.loads(ingest_route.calls.last.request.content)
        item = ingest_body[0] if isinstance(ingest_body, list) else ingest_body
        assert item["verdict"] == "TRUE_POSITIVE"
        assert item["pr_number"] == PR_NUMBER
        assert item["commit_sha"] == COMMIT_SHA

        # 10. High-confidence TRUE_POSITIVE → exit 1 (blocks merge).
        assert exit_code == 1, (
            f"Expected exit 1 for high-confidence TRUE_POSITIVE in Large PR Mode, got {exit_code}"
        )

        # 11. Phase-1 prefetch gate: of the 28 changed files, only the
        # ANALYZE + DEPRIORITIZE buckets get a Contents API fetch
        # (1 auth + 2 utils + 1 test = 4). The 24 SKIP / DEPENDENCY_ONLY
        # files (12 docs + 8 generated + 3 assets + 1 lockfile) must NOT
        # trigger any Contents calls. Auth file is mocked specifically;
        # the other 3 land on the catch-all 404.
        total_content_fetches = auth_content_route.call_count + catchall_content_route.call_count
        assert total_content_fetches == 4, (
            f"Phase-1 prefetch gate broken: expected 4 fetches "
            f"(1 auth + 1 test + 2 utils), got {total_content_fetches} "
            f"(auth={auth_content_route.call_count}, "
            f"catchall={catchall_content_route.call_count})"
        )

        # ── Trace output for human inspection ──────────────────────────────
        print("\n" + "=" * 70)
        print("  AegisDiff Large PR Mode E2E — Pipeline Trace")
        print("=" * 70)
        print(f"  Files in diff      : {file_count} (Large PR threshold: >25)")
        print(f"  LLM calls          : {llm_route.call_count}")
        print(f"  Inline reviews     : {review_route.call_count}")
        print(f"  Summary posted     : {'✓' if create_comment_route.called else '✗'}")
        print(f"  SARIF uploaded     : {'✓' if sarif_route.called else '✗'}")
        print(f"  Ingest sent        : {'✓' if ingest_route.called else '✗'}")
        print(f"  Auth content fetch : {'✓' if auth_content_route.called else '✗'}")
        print(f"  Other content 404s : {catchall_content_route.call_count}")
        comments_state = "queried" if list_comments_route.called else "not queried"
        print(f"  Existing comments  : {comments_state}")
        print(f"  Exit code          : {exit_code}")
        print("=" * 70 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Manual GitHub Actions entrypoint — E2E coverage
# ─────────────────────────────────────────────────────────────────────────────
#
# ``aegisdiff/entrypoint.py`` is invoked by the workflow that runs on a
# checked-out repo (no GitHub App). It diverges from the App path in three
# meaningful ways:
#   * Diff comes from a local file at ``DIFF_PATH``, not a GitHub HTTP fetch.
#   * Auth uses ``GITHUB_TOKEN`` directly (no JWT / installation token).
#   * Ingest uses OIDC OR ``AEGISDIFF_REPO_TOKEN`` as the Bearer token.
#   * Step summary is appended to ``$GITHUB_STEP_SUMMARY``.
#
# These two tests exercise the full manual pipeline (small PR + Large PR Mode)
# through ``aegisdiff.entrypoint.main()`` with every external HTTP call
# intercepted by respx and the OIDC fetch patched to ``None``.


def _manual_env_vars(diff_path: str, step_summary_path: str = "") -> dict:
    """Env vars the GitHub Actions workflow injects for the manual path."""
    env = {
        "GITHUB_TOKEN": "test_github_actions_token",
        "REPO": f"{OWNER}/{REPO}",
        "PR_NUMBER": str(PR_NUMBER),
        "COMMIT_SHA": COMMIT_SHA,
        "DIFF_PATH": diff_path,
        "AEGISDIFF_INGEST_URL": INGEST_URL,
        "AEGISDIFF_REPO_TOKEN": INGEST_TOKEN,
    }
    if step_summary_path:
        env["GITHUB_STEP_SUMMARY"] = step_summary_path
    return env


# Provider-selection env keys we explicitly clear so each manual-path test
# has a deterministic provider list (only GitHubModelsProvider via
# GITHUB_TOKEN). Stale developer-environment keys would otherwise alter
# the orchestrator's failover order and produce flaky CI runs.
_PROVIDER_ENV_KEYS_TO_CLEAR = (
    "OPENROUTER_API_KEY",
    "OPENROUTER_API_KEY_2",
    "OPENROUTER_API_KEY_3",
    "GROQ_API_KEY",
    "GROQ_API_KEY_2",
    "GROQ_API_KEY_3",
)


class TestE2EManualEntrypoint:
    """Full pipeline integration tests for ``aegisdiff/entrypoint.py``.

    Every external HTTP call is mocked (no real GitHub or LLM). The OIDC
    fetch is patched to None so the platform-keys path is skipped and the
    ingest call falls back to the legacy ``AEGISDIFF_REPO_TOKEN`` Bearer.
    """

    @respx.mock
    def test_full_pipeline_manual_true_positive(self, capsys, monkeypatch, tmp_path):
        """Small PR (sample.diff) → TRUE_POSITIVE through the manual path."""
        diff_file = tmp_path / "pr.diff"
        diff_file.write_text(SAMPLE_DIFF)
        step_summary = tmp_path / "step_summary.md"
        step_summary.write_text("")

        for key in _PROVIDER_ENV_KEYS_TO_CLEAR:
            monkeypatch.delenv(key, raising=False)
        for key, val in _manual_env_vars(str(diff_file), str(step_summary)).items():
            monkeypatch.setenv(key, val)

        # ── Mocks ───────────────────────────────────────────────────────────
        # ``_fetch_file`` is the *fallback* the manual path uses when the
        # extractor can't read a path from disk. Specific 200 for the
        # vulnerable file, catch-all 404 for everything else.
        file_route = respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py").mock(
            return_value=httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": _b64_encode(FILE_CONTENT_PYTHON),
                },
            )
        )
        contents_pattern = re.compile(rf"^{re.escape(GITHUB_API)}/repos/{OWNER}/{REPO}/contents/.*")
        catchall_content_route = respx.get(url__regex=contents_pattern).mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )

        llm_route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=GITHUB_MODELS_RESPONSE)
        )

        review_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        ).mock(return_value=httpx.Response(200, json={"id": 51}))

        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments").mock(
            return_value=httpx.Response(200, json=[])
        )
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 81}))

        status_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}").mock(
            return_value=httpx.Response(201, json={})
        )
        sarif_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs").mock(
            return_value=httpx.Response(202, json={"id": "sarif-manual-tp"})
        )
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        with patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None):
            from aegisdiff.entrypoint import main

            try:
                main()
                exit_code = 0
            except SystemExit as e:
                exit_code = e.code

        # ── Assertions ──────────────────────────────────────────────────────

        assert llm_route.called, "Expected LLM to be called for analysis"
        # Confirms the local-file diff actually fed the engine.
        llm_payload = json.loads(llm_route.calls.last.request.content)
        user_message = llm_payload["messages"][1]["content"]
        assert "subprocess" in user_message
        assert "shell=True" in user_message

        # Manual path now mirrors the App path: ``build_manual_file_cache``
        # pre-populates the extractor's cache with the auth file content
        # for ANALYZE / DEPRIORITIZE files that aren't on disk under the
        # checked-out repo. The AST extractor then resolves a sink line
        # for the subprocess(shell=True) call deterministically, so the
        # inline review fires every time. Asserting it directly closes
        # the conditional gap PR #6 had to live with before F7 landed.
        assert review_route.called, (
            "Manual TP path must post an inline review now that file_cache "
            "is pre-populated for ANALYZE/DEPRIORITIZE files"
        )
        inline_payload = json.loads(review_route.calls.last.request.content)
        assert inline_payload["commit_id"] == COMMIT_SHA

        # Summary comment posted with AegisDiff marker + TP indicators.
        assert create_comment_route.called
        comment_body = json.loads(create_comment_route.calls.last.request.content)["body"]
        assert "<!-- aegisdiff-report -->" in comment_body
        assert "TRUE_POSITIVE" in comment_body or ":x:" in comment_body

        # Commit status = failure (high-confidence TP blocks merge).
        assert status_route.called
        status_payload = json.loads(status_route.calls.last.request.content)
        assert status_payload["state"] == "failure"
        assert status_payload["context"] == "AegisDiff / security"

        # SARIF upload attempted.
        assert sarif_route.called

        # Dashboard ingest called with the *repo-token* Bearer (OIDC patched
        # to None, so the fallback auth path engages — manual-path specific).
        assert ingest_route.called
        assert (
            ingest_route.calls.last.request.headers["Authorization"] == f"Bearer {INGEST_TOKEN}"
        ), "Manual path must fall back to AEGISDIFF_REPO_TOKEN when OIDC unavailable"

        ingest_body = json.loads(ingest_route.calls.last.request.content)
        item = ingest_body[0] if isinstance(ingest_body, list) else ingest_body
        assert item["verdict"] == "TRUE_POSITIVE"
        assert item["cwe_id"] == "CWE-78"
        assert item["pr_number"] == PR_NUMBER
        assert item["commit_sha"] == COMMIT_SHA
        assert item["pr_url"] == f"https://github.com/{OWNER}/{REPO}/pull/{PR_NUMBER}"

        # Step summary written (manual-path specific — App path doesn't do this).
        step_summary_text = step_summary.read_text()
        assert "TRUE_POSITIVE" in step_summary_text, (
            f"Expected TRUE_POSITIVE in $GITHUB_STEP_SUMMARY, got: {step_summary_text!r}"
        )

        # High-confidence TP → exit 1.
        assert exit_code == 1

        # ── Trace ──────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  AegisDiff Manual Entrypoint E2E (TRUE_POSITIVE) — Pipeline Trace")
        print("=" * 70)
        print(f"  Diff source       : {diff_file} ({SAMPLE_DIFF.count(chr(10))} lines)")
        print(f"  LLM calls         : {llm_route.call_count}")
        print(f"  Inline reviews    : {review_route.call_count}")
        print(f"  Summary posted    : {'✓' if create_comment_route.called else '✗'}")
        print(f"  Status state      : {status_payload['state']}")
        print(f"  SARIF uploaded    : {'✓' if sarif_route.called else '✗'}")
        print(f"  Ingest auth       : Bearer {INGEST_TOKEN[:8]}…")
        print(f"  Step summary line : {step_summary_text.strip().splitlines()[0]}")
        print(f"  Auth file fetched : {'✓' if file_route.called else '✗'}")
        print(f"  Catch-all 404s    : {catchall_content_route.call_count}")
        print(f"  Exit code         : {exit_code}")
        print("=" * 70 + "\n")

    @respx.mock
    def test_full_pipeline_manual_large_pr_mode(self, capsys, monkeypatch, tmp_path):
        """Large PR Mode through the manual path (28-file synthetic diff)."""
        large_pr_diff = _build_large_pr_diff()
        diff_file = tmp_path / "large_pr.diff"
        diff_file.write_text(large_pr_diff)
        step_summary = tmp_path / "step_summary.md"
        step_summary.write_text("")

        file_count = large_pr_diff.count("diff --git ")
        assert file_count == 28, f"fixture changed shape: {file_count} files"

        for key in _PROVIDER_ENV_KEYS_TO_CLEAR:
            monkeypatch.delenv(key, raising=False)
        for key, val in _manual_env_vars(str(diff_file), str(step_summary)).items():
            monkeypatch.setenv(key, val)

        # ── Mocks ───────────────────────────────────────────────────────────
        auth_content_route = respx.get(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/{LARGE_PR_AUTH_PATH}"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": _b64_encode(LARGE_PR_AUTH_FILE_CONTENT),
                },
            )
        )
        contents_pattern = re.compile(rf"^{re.escape(GITHUB_API)}/repos/{OWNER}/{REPO}/contents/.*")
        catchall_content_route = respx.get(url__regex=contents_pattern).mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )

        llm_route = respx.post(GITHUB_MODELS_URL).mock(
            return_value=httpx.Response(200, json=LARGE_PR_LLM_RESPONSE)
        )

        review_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/pulls/{PR_NUMBER}/reviews"
        ).mock(return_value=httpx.Response(200, json={"id": 91}))

        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments").mock(
            return_value=httpx.Response(200, json=[])
        )
        create_comment_route = respx.post(
            f"{GITHUB_API}/repos/{OWNER}/{REPO}/issues/{PR_NUMBER}/comments"
        ).mock(return_value=httpx.Response(201, json={"id": 71}))

        status_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/statuses/{COMMIT_SHA}").mock(
            return_value=httpx.Response(201, json={})
        )
        sarif_route = respx.post(f"{GITHUB_API}/repos/{OWNER}/{REPO}/code-scanning/sarifs").mock(
            return_value=httpx.Response(202, json={"id": "sarif-manual-large"})
        )
        ingest_route = respx.post(INGEST_URL).mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        with patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None):
            from aegisdiff.entrypoint import main

            try:
                main()
                exit_code = 0
            except SystemExit as e:
                exit_code = e.code

        # ── Assertions ──────────────────────────────────────────────────────

        assert llm_route.called
        assert llm_route.call_count >= 1
        assert llm_route.call_count <= 40, "LLM call budget should never be exceeded"

        # Banner + coverage block.
        assert create_comment_route.called
        comment_body = json.loads(create_comment_route.calls.last.request.content)["body"]
        assert "AegisDiff ran in Large PR Risk Triage Mode" in comment_body
        assert "Large PR Risk Triage Mode coverage" in comment_body
        assert "Files changed:" in comment_body
        assert "Files analyzed:" in comment_body
        assert "Files skipped:" in comment_body
        assert "LLM calls used:" in comment_body
        assert "Budget exhausted:" in comment_body

        # Skip-reason buckets.
        assert "`docs`" in comment_body
        assert "`generated`" in comment_body
        assert "`static_asset`" in comment_body
        assert "`dependency_only`" in comment_body

        # Trigger reason references our threshold breach.
        assert "changed_files=28" in comment_body

        # Full raw diff is NEVER sent in a single LLM prompt; every prompt
        # carries the addendum + injection defense.
        for call in llm_route.calls:
            payload = json.loads(call.request.content)
            user_msg = payload["messages"][1]["content"]
            assert large_pr_diff not in user_msg
            sys_msg = payload["messages"][0]["content"]
            assert "LARGE PR RISK TRIAGE MODE" in sys_msg
            assert "UNTRUSTED INPUT" in sys_msg

        # Inline-comments-posted count matches the actual successful review
        # responses (Codex P2 contract holds for the manual path too).
        if review_route.called:
            posted = review_route.call_count
            assert f"Inline comments posted: **{posted}**" in comment_body, (
                f"Manual-path inline-post count out of sync: posted={posted}"
            )
        else:
            assert (
                "Inline comments posted: **0**" in comment_body
                or "Inline comments posted:" not in comment_body
            )

        # Commit status, SARIF, ingest all still fire.
        assert status_route.called
        status_payload = json.loads(status_route.calls.last.request.content)
        assert status_payload["state"] == "failure"
        assert sarif_route.called

        assert ingest_route.called
        ingest_body = json.loads(ingest_route.calls.last.request.content)
        item = ingest_body[0] if isinstance(ingest_body, list) else ingest_body
        assert item["verdict"] == "TRUE_POSITIVE"
        assert item["pr_number"] == PR_NUMBER
        assert item["commit_sha"] == COMMIT_SHA

        assert exit_code == 1

        # ── Trace ──────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  AegisDiff Manual Entrypoint E2E (Large PR Mode) — Pipeline Trace")
        print("=" * 70)
        print(f"  Diff source     : {diff_file} ({file_count} files)")
        print(f"  LLM calls       : {llm_route.call_count}")
        print(f"  Inline reviews  : {review_route.call_count}")
        print(f"  Summary posted  : {'✓' if create_comment_route.called else '✗'}")
        print(f"  SARIF uploaded  : {'✓' if sarif_route.called else '✗'}")
        print(f"  Ingest sent     : {'✓' if ingest_route.called else '✗'}")
        print(f"  Auth content    : {'✓' if auth_content_route.called else '✗'}")
        print(f"  Catch-all 404s  : {catchall_content_route.call_count}")
        print(f"  Exit code       : {exit_code}")
        print("=" * 70 + "\n")

    # ── F12: fallback paths ──────────────────────────────────────────────

    @respx.mock
    def test_full_pipeline_manual_no_pr_context_prints_to_stdout(
        self, capsys, monkeypatch, tmp_path
    ):
        """No PR context → engine still runs end-to-end, but every PR-side
        GitHub API (inline review / summary comment / commit status /
        SARIF upload) is skipped and the verdict is printed to stdout
        instead. ``respx`` strict mode acts as the negative-space
        assertion: registering only the routes that *should* be called
        means any unexpected PR/status/SARIF call would raise.
        """
        diff_file = tmp_path / "pr.diff"
        diff_file.write_text(SAMPLE_DIFF)
        step_summary = tmp_path / "step_summary.md"
        step_summary.write_text("")

        for key in _PROVIDER_ENV_KEYS_TO_CLEAR:
            monkeypatch.delenv(key, raising=False)
        # Drop PR_NUMBER so cfg.pr_number is None → triggers the no-PR
        # branch (line 463 of entrypoint.py). Drop ingest URL/token too:
        # the "no PR context" contract is about GitHub APIs being silent;
        # ingest is a separate concern and is not part of this test.
        env = _manual_env_vars(str(diff_file), str(step_summary))
        env.pop("PR_NUMBER")
        env.pop("AEGISDIFF_INGEST_URL")
        env.pop("AEGISDIFF_REPO_TOKEN")
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        monkeypatch.delenv("PR_NUMBER", raising=False)
        monkeypatch.delenv("AEGISDIFF_INGEST_URL", raising=False)
        monkeypatch.delenv("AEGISDIFF_REPO_TOKEN", raising=False)

        # Mocks — only what the engine actually needs.
        # 1. Manual prefetch gate fetches /contents/app/views.py for
        #    the auth file; catch-all 404 absorbs anything else.
        respx.get(f"{GITHUB_API}/repos/{OWNER}/{REPO}/contents/app/views.py").mock(
            return_value=httpx.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": _b64_encode(FILE_CONTENT_PYTHON),
                },
            )
        )
        contents_pattern = re.compile(rf"^{re.escape(GITHUB_API)}/repos/{OWNER}/{REPO}/contents/.*")
        respx.get(url__regex=contents_pattern).mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        # 2. LLM call returns a FALSE_POSITIVE so the run exits 0 cleanly.
        false_positive_verdict = json.dumps(
            {
                "verdict": "FALSE_POSITIVE",
                "severity": "N/A",
                "cwe_id": "N/A",
                "confidence": 0.93,
                "title": "No exploitable vulnerability",
                "summary": "Allowlist guards the subprocess call.",
                "evidence": "",
                "sanitizer_found": True,
                "sanitizer_description": "Allowlist before subprocess",
                "attack_vector": None,
                "remediation": None,
                "false_positive_reason": "Validated against allowlist",
            }
        )
        llm_route = respx.post(GITHUB_MODELS_URL).mock(
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
        # No PR-side routes registered. Strict respx will raise if any
        # of /reviews, /issues/{n}/comments, /statuses/{sha}, or
        # /code-scanning/sarifs is hit — that's the assertion.

        with patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None):
            from aegisdiff.entrypoint import main

            try:
                main()
                exit_code = 0
            except SystemExit as e:
                exit_code = e.code

        # Engine ran (LLM was called).
        assert llm_route.called, "Expected LLM to be called for analysis"
        # Stdout carries the formatted verdict comment with stable markers.
        captured = capsys.readouterr()
        assert "<!-- aegisdiff-report -->" in captured.out, (
            "no-PR-context fallback must print the AegisDiff comment marker"
        )
        assert "AegisDiff Security Triage" in captured.out
        assert "FALSE_POSITIVE" in captured.out
        # FALSE_POSITIVE → exit 0.
        assert exit_code == 0

        print("\n" + "=" * 70)
        print("  AegisDiff Manual Entrypoint E2E (no-PR fallback) — Trace")
        print("=" * 70)
        print(f"  LLM calls       : {llm_route.call_count}")
        print("  PR APIs called  : (none — strict respx confirmed)")
        print("  Stdout markers  : aegisdiff-report ✓, FALSE_POSITIVE ✓")
        print(f"  Exit code       : {exit_code}")
        print("=" * 70 + "\n")

    @respx.mock
    def test_full_pipeline_manual_missing_diff_path_exits_1(self, monkeypatch, tmp_path, caplog):
        """``DIFF_PATH`` points at a nonexistent file → exit 1, no HTTP
        traffic. ``respx`` strict mode catches any accidental call."""
        missing_diff = tmp_path / "does_not_exist.diff"
        # Deliberately do NOT create the file.

        for key in _PROVIDER_ENV_KEYS_TO_CLEAR:
            monkeypatch.delenv(key, raising=False)
        env = _manual_env_vars(str(missing_diff))
        env.pop("AEGISDIFF_INGEST_URL")
        env.pop("AEGISDIFF_REPO_TOKEN")
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        monkeypatch.delenv("AEGISDIFF_INGEST_URL", raising=False)
        monkeypatch.delenv("AEGISDIFF_REPO_TOKEN", raising=False)

        # No HTTP routes registered. Strict respx asserts no calls happen.

        with patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None):
            from aegisdiff.entrypoint import main

            with caplog.at_level(logging.ERROR, logger="aegisdiff.entrypoint"):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1
        # Informative log assertion — the error message is a stable
        # contract for operators reading workflow logs.
        diff_not_found_records = [
            r
            for r in caplog.records
            if "Diff file not found" in r.getMessage() and r.levelno == logging.ERROR
        ]
        assert diff_not_found_records, "missing DIFF_PATH must log a 'Diff file not found' ERROR"

    @respx.mock
    def test_full_pipeline_manual_empty_diff_exits_0(self, capsys, monkeypatch, tmp_path):
        """Empty / whitespace-only diff → exit 0 with the friendly
        stdout message; no LLM call, no GitHub HTTP, no ingest."""
        empty_diff = tmp_path / "empty.diff"
        empty_diff.write_text("")

        for key in _PROVIDER_ENV_KEYS_TO_CLEAR:
            monkeypatch.delenv(key, raising=False)
        env = _manual_env_vars(str(empty_diff))
        env.pop("AEGISDIFF_INGEST_URL")
        env.pop("AEGISDIFF_REPO_TOKEN")
        for key, val in env.items():
            monkeypatch.setenv(key, val)
        monkeypatch.delenv("AEGISDIFF_INGEST_URL", raising=False)
        monkeypatch.delenv("AEGISDIFF_REPO_TOKEN", raising=False)

        # No HTTP routes registered. The empty-diff branch exits before
        # any LLM / GitHub call; strict respx catches regressions.

        with patch("aegisdiff.llm.platform_keys.get_oidc_token", return_value=None):
            from aegisdiff.entrypoint import main

            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "## AegisDiff" in out
        assert "No security-relevant code changes detected" in out
