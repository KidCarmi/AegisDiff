"""Integration tests for the TriageEngine — covers a diverse set of CWEs."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegisdiff.llm.orchestrator import LLMOrchestrator
from aegisdiff.llm.providers.base import LLMResponse
from aegisdiff.triage.engine import TriageEngine
from aegisdiff.triage.verdicts import Verdict, VerdictType


# ── Helpers ──────────────────────────────────────────────────────────────────

def _orch(content: str, provider: str = "gemini") -> LLMOrchestrator:
    """Return a mock orchestrator that always responds with *content*."""
    mock = MagicMock(spec=LLMOrchestrator)
    mock.complete.return_value = LLMResponse(
        content=content,
        provider=provider,
        model="gemini-1.5-pro",
        input_tokens=500,
        output_tokens=200,
        latency_ms=1200.0,
    )
    return mock


def _tp(cwe: str, title: str, confidence: float = 0.92, severity: str = "HIGH") -> str:
    """Build a TRUE_POSITIVE verdict JSON string."""
    return json.dumps({
        "verdict": "TRUE_POSITIVE",
        "severity": severity,
        "cwe_id": cwe,
        "confidence": confidence,
        "title": title,
        "summary": f"User-controlled input reaches {cwe} sink without sanitisation.",
        "evidence": "see diff",
        "sanitizer_found": False,
        "sanitizer_description": None,
        "attack_vector": "Craft malicious input for the vulnerable parameter",
        "remediation": "Sanitise and validate all user-supplied input before use.",
        "false_positive_reason": None,
    })


def _fp(title: str, reason: str) -> str:
    """Build a FALSE_POSITIVE verdict JSON string."""
    return json.dumps({
        "verdict": "FALSE_POSITIVE",
        "severity": "N/A",
        "cwe_id": "N/A",
        "confidence": 0.95,
        "title": title,
        "summary": "No exploitable path found.",
        "evidence": "",
        "sanitizer_found": True,
        "sanitizer_description": reason,
        "attack_vector": None,
        "remediation": None,
        "false_positive_reason": reason,
    })


# ── Canned verdicts ───────────────────────────────────────────────────────────

CMDI_VERDICT      = _tp("CWE-78",  "OS Command Injection via report_name")
PATH_TRAV_VERDICT = _tp("CWE-22",  "Path Traversal in download_file")
SSRF_VERDICT      = _tp("CWE-918", "SSRF via user-supplied URL", severity="HIGH")
SSTI_VERDICT      = _tp("CWE-94",  "Server-Side Template Injection in render_email", severity="CRITICAL")
SECRET_VERDICT    = _tp("CWE-798", "Hardcoded AWS credentials and API keys", severity="CRITICAL")
JWT_VERDICT       = _tp("CWE-327", "JWT accepts 'none' algorithm — authentication bypass", severity="CRITICAL")
DESER_VERDICT     = _tp("CWE-502", "Insecure deserialization via pickle.loads()", severity="CRITICAL")
XXE_VERDICT       = _tp("CWE-611", "XML External Entity injection via lxml parser", severity="HIGH")
XSS_VERDICT       = _tp("CWE-79",  "Stored XSS via dangerouslySetInnerHTML", severity="HIGH")
REDIRECT_VERDICT  = _tp("CWE-601", "Open redirect via unvalidated 'next' parameter", severity="MEDIUM")

FALSE_POS_VERDICT = _fp(
    "Django ORM filter is safe",
    "Django ORM parameterizes queries automatically",
)


# ── Fixture helpers: create minimal source files for AST extraction ───────────

def _django_app(tmp_path: Path) -> Path:
    d = tmp_path / "app"
    d.mkdir(exist_ok=True)
    return d


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestCWE78_CommandInjection:
    """sample.diff — subprocess shell=True with user input (CWE-78)."""

    def test_detects_command_injection(self, tmp_path, sample_diff):
        app = _django_app(tmp_path)
        (app / "views.py").write_text(
            "import subprocess\n"
            "def run_report(request):\n"
            "    report_name = request.GET.get('report')\n"
            "    subprocess.check_output(f'generate_report.sh {report_name}', shell=True)\n"
        )
        verdict = TriageEngine(_orch(CMDI_VERDICT), tmp_path).analyze_diff(sample_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-78"

    def test_also_detects_path_traversal_in_same_diff(self, tmp_path, sample_diff):
        """sample.diff contains both cmd injection AND path traversal — engine sees both."""
        _django_app(tmp_path)
        verdict = TriageEngine(_orch(PATH_TRAV_VERDICT), tmp_path).analyze_diff(sample_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert "22" in verdict.cwe_id  # CWE-22


class TestCWE918_SSRF:
    """ssrf.diff — requests.get() with user-supplied URL (CWE-918)."""

    def test_detects_ssrf(self, tmp_path, ssrf_diff):
        app = _django_app(tmp_path)
        (app / "webhooks.py").write_text(
            "import requests\n"
            "def webhook_test(request):\n"
            "    url = request.POST.get('url')\n"
            "    resp = requests.get(url)\n"
        )
        verdict = TriageEngine(_orch(SSRF_VERDICT), tmp_path).analyze_diff(ssrf_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-918"
        assert verdict.severity.value == "HIGH"


class TestCWE94_SSTI:
    """ssti.diff — Jinja2 Template(user_input).render() (CWE-94)."""

    def test_detects_ssti(self, tmp_path, ssti_diff):
        app = _django_app(tmp_path)
        (app / "templates_view.py").write_text(
            "from jinja2 import Template\n"
            "def render_email(request):\n"
            "    t = Template(request.POST.get('template'))\n"
            "    return t.render()\n"
        )
        verdict = TriageEngine(_orch(SSTI_VERDICT), tmp_path).analyze_diff(ssti_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-94"
        assert verdict.severity.value == "CRITICAL"


class TestCWE798_HardcodedSecret:
    """hardcoded_secret.diff — AWS keys + Stripe + GitHub tokens in source (CWE-798)."""

    def test_detects_hardcoded_credentials(self, tmp_path, hardcoded_secret_diff):
        app = _django_app(tmp_path)
        (app / "integrations.py").write_text(
            "AWS_SECRET='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "stripe_key='sk_live_AEGISDIFF_FAKE_TEST_FIXTURE_NOT_A_REAL_KEY'\n"
        )
        verdict = TriageEngine(_orch(SECRET_VERDICT), tmp_path).analyze_diff(hardcoded_secret_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-798"
        assert verdict.severity.value == "CRITICAL"


class TestCWE327_WeakJWT:
    """jwt_weak.diff — jwt.verify with 'none' algorithm allowed (CWE-327)."""

    def test_detects_jwt_none_algorithm(self, tmp_path, jwt_weak_diff):
        src = tmp_path / "src" / "auth"
        src.mkdir(parents=True, exist_ok=True)
        (src / "middleware.ts").write_text(
            "import jwt from 'jsonwebtoken';\n"
            "export function verify(t: string) {\n"
            "  return jwt.verify(t, secret, { algorithms: ['HS256', 'none'] });\n"
            "}\n"
        )
        verdict = TriageEngine(_orch(JWT_VERDICT), tmp_path).analyze_diff(jwt_weak_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-327"
        assert verdict.severity.value == "CRITICAL"


class TestCWE502_Deserialization:
    """deserialization.diff — pickle.loads() + yaml.load() on request body (CWE-502)."""

    def test_detects_insecure_deserialization(self, tmp_path, deserialization_diff):
        app = _django_app(tmp_path)
        (app / "api.py").write_text(
            "import pickle\n"
            "def restore_session(request):\n"
            "    return pickle.loads(request.body)\n"
        )
        verdict = TriageEngine(_orch(DESER_VERDICT), tmp_path).analyze_diff(deserialization_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-502"
        assert verdict.severity.value == "CRITICAL"


class TestCWE611_XXE:
    """xxe.diff — lxml with resolve_entities=True + stdlib ET on user XML (CWE-611)."""

    def test_detects_xxe(self, tmp_path, xxe_diff):
        app = _django_app(tmp_path)
        (app / "parsers.py").write_text(
            "from lxml import etree\n"
            "def parse_invoice(request):\n"
            "    parser = etree.XMLParser(resolve_entities=True)\n"
            "    etree.fromstring(request.body, parser)\n"
        )
        verdict = TriageEngine(_orch(XXE_VERDICT), tmp_path).analyze_diff(xxe_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-611"


class TestCWE79_XSS:
    """xss.diff — dangerouslySetInnerHTML with user content in React (CWE-79)."""

    def test_detects_xss(self, tmp_path, xss_diff):
        src = tmp_path / "src" / "components"
        src.mkdir(parents=True, exist_ok=True)
        (src / "UserComment.tsx").write_text(
            "export function UserComment({ comment }: any) {\n"
            "  return <div dangerouslySetInnerHTML={{ __html: comment }} />;\n"
            "}\n"
        )
        verdict = TriageEngine(_orch(XSS_VERDICT), tmp_path).analyze_diff(xss_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-79"


class TestCWE601_OpenRedirect:
    """open_redirect.diff — HttpResponseRedirect with unvalidated GET param (CWE-601)."""

    def test_detects_open_redirect(self, tmp_path, open_redirect_diff):
        app = _django_app(tmp_path)
        (app / "auth.py").write_text(
            "from django.http import HttpResponseRedirect\n"
            "def logout_view(request):\n"
            "    next_url = request.GET.get('next', '/')\n"
            "    return HttpResponseRedirect(next_url)\n"
        )
        verdict = TriageEngine(_orch(REDIRECT_VERDICT), tmp_path).analyze_diff(open_redirect_diff)
        assert verdict.verdict == VerdictType.TRUE_POSITIVE
        assert verdict.cwe_id == "CWE-601"


class TestFalsePositive:
    """safe.diff — Django ORM .filter() is parameterised and should be FALSE_POSITIVE."""

    def test_false_positive_on_safe_orm(self, tmp_path, safe_diff):
        app = _django_app(tmp_path)
        (app / "models.py").write_text(
            "from django.db import models\n"
            "class User(models.Model):\n"
            "    email = models.EmailField()\n"
            "    @classmethod\n"
            "    def get_by_email(cls, email):\n"
            "        return cls.objects.filter(email=email).first()\n"
        )
        verdict = TriageEngine(_orch(FALSE_POS_VERDICT), tmp_path).analyze_diff(safe_diff)
        assert verdict.verdict == VerdictType.FALSE_POSITIVE
        assert verdict.confidence >= 0.9


class TestEdgeCases:
    def test_empty_diff_short_circuits_llm(self, tmp_path):
        orch = MagicMock(spec=LLMOrchestrator)
        verdict = TriageEngine(orch, tmp_path).analyze_diff("")
        assert verdict.verdict == VerdictType.FALSE_POSITIVE
        assert "No security-relevant" in verdict.title
        orch.complete.assert_not_called()

    def test_all_providers_exhausted_returns_error_verdict(self, tmp_path, sample_diff):
        orch = MagicMock(spec=LLMOrchestrator)
        orch.complete.side_effect = RuntimeError("All providers exhausted")
        _django_app(tmp_path)
        verdict = TriageEngine(orch, tmp_path).analyze_diff(sample_diff)
        assert verdict.verdict == VerdictType.ERROR
        assert "All providers exhausted" in verdict.summary
        # New: error reason is now surfaced in the title (truncated to 80 chars)
        assert "All providers exhausted" in verdict.title

    def test_error_title_truncated_to_80_chars(self):
        long_reason = "x" * 200
        v = Verdict.error(long_reason)
        assert len(v.title) <= 80
        assert v.title == long_reason[:80]

    def test_error_empty_reason_uses_fallback(self):
        v = Verdict.error("")
        assert v.title == "Analysis engine error"

    def test_high_confidence_tp_not_downgraded(self):
        from aegisdiff.triage.verdicts import parse_verdict
        raw = _tp("CWE-78", "Cmd injection", confidence=0.95)
        v = parse_verdict(raw, provider="gemini")
        assert v.verdict == VerdictType.TRUE_POSITIVE
        assert v.confidence == 0.95

    def test_low_confidence_tp_downgraded_to_needs_review(self):
        from aegisdiff.triage.verdicts import parse_verdict
        raw = _tp("CWE-78", "Cmd injection", confidence=0.4)
        v = parse_verdict(raw, provider="gemini")
        assert v.verdict == VerdictType.NEEDS_REVIEW
