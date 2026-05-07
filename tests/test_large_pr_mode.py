"""
Phase 2 tests for Large PR Risk Triage Mode integration.

Covers the gated wiring of Large PR Mode into ``TriageEngine`` and the PR
summary comment formatter. LLM calls are mocked — no network, no GitHub.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegisdiff.github.pr_comment import (
    LARGE_PR_BANNER,
    format_large_pr_summary,
    format_summary_comment,
)
from aegisdiff.llm.orchestrator import LLMOrchestrator
from aegisdiff.llm.providers.base import LLMRequest, LLMResponse
from aegisdiff.triage.engine import LargePRRunResult, TriageEngine
from aegisdiff.triage.large_pr import LargePRBudgets, detect_large_pr
from aegisdiff.triage.prompts import APPSEC_SYSTEM_PROMPT, LARGE_PR_PROMPT_ADDENDUM
from aegisdiff.triage.verdicts import Severity, Verdict, VerdictType

# ── helpers ────────────────────────────────────────────────────────────────


def _llm_response(content: str) -> LLMResponse:
    return LLMResponse(
        content=content,
        provider="mock",
        model="mock-llama",
        input_tokens=200,
        output_tokens=80,
        latency_ms=300.0,
    )


def _fp_json() -> str:
    return json.dumps(
        {
            "verdict": "FALSE_POSITIVE",
            "severity": "N/A",
            "cwe_id": "N/A",
            "confidence": 0.95,
            "title": "Safe change",
            "summary": "Nothing exploitable.",
            "evidence": "",
            "sanitizer_found": True,
            "sanitizer_description": "Framework default",
            "attack_vector": None,
            "remediation": None,
            "false_positive_reason": "No tainted source reaches a sink",
        }
    )


def _make_engine_with_recording_orchestrator() -> tuple[TriageEngine, MagicMock]:
    """Build an engine whose orchestrator records every LLMRequest it sees."""
    orch = MagicMock(spec=LLMOrchestrator)
    orch.complete.side_effect = lambda req: _llm_response(_fp_json())
    engine = TriageEngine(orch, repo_root=Path("."))
    return engine, orch


def _build_diff(num_files: int, lines_per_file: int = 6, prefix: str = "src/svc") -> str:
    """Build a deterministic synthetic unified diff with N files."""
    parts: list[str] = []
    for i in range(num_files):
        path = f"{prefix}_{i}.py"
        added = "\n".join(f"+    line_{j} = compute({j})" for j in range(lines_per_file))
        parts.append(
            f"diff --git a/{path} b/{path}\n"
            f"index 1111111..2222222 100644\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -1,2 +1,{lines_per_file + 1} @@\n"
            f" import os\n"
            f"{added}\n"
        )
    return "".join(parts)


# ── 1. small PR path unchanged ─────────────────────────────────────────────


def test_small_pr_does_not_trigger_large_pr_mode():
    raw = _build_diff(num_files=2, lines_per_file=3)
    detection = detect_large_pr(
        changed_files=2,
        added_lines=raw.count("\n+") - 2,
        total_diff_bytes=len(raw.encode("utf-8")),
    )
    assert detection.is_large_pr is False


def test_small_pr_path_still_uses_existing_engine_methods_only():
    """The Phase 2 entrypoint logic must NOT call analyze_diff_large_pr_mode
    for small PRs. We assert this at the engine API level: the new method is
    only ever invoked when the caller explicitly opts in via detect_large_pr.
    """
    engine, _orch = _make_engine_with_recording_orchestrator()
    # Sanity: the new method exists and is opt-in.
    assert hasattr(engine, "analyze_diff_large_pr_mode")
    # Sanity: analyze_diff signature still accepts a single positional diff,
    # and large_pr_mode defaults to False (unchanged behaviour for old callers).
    import inspect

    sig = inspect.signature(engine.analyze_diff)
    assert "large_pr_mode" in sig.parameters
    assert sig.parameters["large_pr_mode"].default is False


# ── 2. Large PR Mode activates correctly ───────────────────────────────────


def test_large_pr_mode_activates_on_changed_file_count():
    raw = _build_diff(num_files=26, lines_per_file=2)
    engine, orch = _make_engine_with_recording_orchestrator()
    detection = detect_large_pr(
        changed_files=26,
        added_lines=26 * 2,
        total_diff_bytes=len(raw.encode("utf-8")),
    )
    assert detection.is_large_pr is True

    result = engine.analyze_diff_large_pr_mode(raw, detection)
    assert isinstance(result, LargePRRunResult)
    assert result.coverage is not None
    assert result.coverage.mode == "large_pr"
    # max_files_analyzed defaults to 20 — selection must respect the cap.
    assert result.coverage.files_analyzed <= detection.budgets.max_files_analyzed
    assert orch.complete.call_count >= 1


# ── 3. Full raw diff is never sent as one prompt ───────────────────────────


def test_large_pr_mode_never_sends_full_raw_diff_in_one_prompt():
    raw = _build_diff(num_files=30, lines_per_file=4)
    detection = detect_large_pr(
        changed_files=30, added_lines=120, total_diff_bytes=len(raw.encode("utf-8"))
    )
    engine, orch = _make_engine_with_recording_orchestrator()
    engine.analyze_diff_large_pr_mode(raw, detection)

    assert orch.complete.call_count >= 2, "expected multiple chunks, not one giant prompt"
    for call in orch.complete.call_args_list:
        req: LLMRequest = call.args[0]
        # No single LLM request may carry the full raw diff.
        assert raw not in req.user_message, "full raw diff must not be sent as a single prompt"
        # And every Large PR Mode prompt carries the addendum.
        assert LARGE_PR_PROMPT_ADDENDUM.strip().splitlines()[1] in req.system_prompt


# ── 4. Docs / generated / assets / lockfiles excluded from LLM calls ──────


def test_large_pr_mode_excludes_docs_assets_generated_and_lockfiles():
    raw = (
        _build_diff(num_files=1, prefix="docs/page")  # docs → skip
        + _build_diff(num_files=1, prefix="dist/bundle")  # generated → skip
        + _build_diff(num_files=1, prefix="web/public/logo")
        .replace("logo_0.py", "logo_0.png")
        .replace("compute(", "data(")  # asset → skip
        + _build_diff(num_files=1, prefix="package-lock").replace(
            "package-lock_0.py", "package-lock.json"
        )  # dep_only → no LLM
        + _build_diff(num_files=26, prefix="src/auth/handler")  # forces large mode
    )
    detection = detect_large_pr(
        changed_files=30, added_lines=200, total_diff_bytes=len(raw.encode("utf-8"))
    )
    assert detection.is_large_pr is True

    engine, orch = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)

    selected_paths = {c.path for c in result.selection.selected}
    # No skip / dependency_only file should have been selected for LLM.
    for forbidden in [
        "docs/page_0.py",
        "dist/bundle_0.py",
        "web/public/logo_0.png",
        "package-lock.json",
    ]:
        assert forbidden not in selected_paths, f"{forbidden} should not be analyzed"

    # And no LLM call carried any of those forbidden paths in its prompt.
    for call in orch.complete.call_args_list:
        body = call.args[0].user_message
        assert "docs/page_0.py" not in body
        assert "dist/bundle_0.py" not in body
        assert "package-lock.json" not in body


# ── 5. High-risk files are prioritized ─────────────────────────────────────


def test_large_pr_mode_prioritizes_high_risk_files():
    # Build 26 neutral files + 2 high-risk auth files. With max_files_analyzed=3
    # the selection should put both auth files in the selected set.
    high_risk = (
        "diff --git a/src/auth/login.py b/src/auth/login.py\n"
        "--- a/src/auth/login.py\n+++ b/src/auth/login.py\n"
        "@@ -1,1 +1,2 @@\n import os\n+def login(): pass\n"
        "diff --git a/src/auth/jwt_token.py b/src/auth/jwt_token.py\n"
        "--- a/src/auth/jwt_token.py\n+++ b/src/auth/jwt_token.py\n"
        "@@ -1,1 +1,2 @@\n import os\n+def verify(): pass\n"
    )
    raw = high_risk + _build_diff(num_files=26, prefix="src/utils/util")
    budgets = LargePRBudgets(max_files_analyzed=3)
    detection = detect_large_pr(
        changed_files=28,
        added_lines=30,
        total_diff_bytes=len(raw.encode("utf-8")),
        budgets=budgets,
    )
    engine, _ = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)

    selected_paths = [c.path for c in result.selection.selected]
    assert "src/auth/login.py" in selected_paths
    assert "src/auth/jwt_token.py" in selected_paths


# ── 6. max_llm_calls_per_pr enforced ───────────────────────────────────────


def test_large_pr_mode_enforces_max_llm_calls_per_pr():
    # Many files, each splitting into multiple sub-hunks, but the LLM-call
    # budget is tiny — orchestrator must be called at most that many times.
    raw = _build_diff(num_files=40, lines_per_file=5, prefix="src/auth/handler")
    budgets = LargePRBudgets(max_files_analyzed=40, max_llm_calls_per_pr=3)
    detection = detect_large_pr(
        changed_files=40,
        added_lines=40 * 5,
        total_diff_bytes=len(raw.encode("utf-8")),
        budgets=budgets,
    )
    engine, orch = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)

    assert orch.complete.call_count == 3
    assert result.llm_calls_budget_used == 3
    assert result.budget_exhausted is True
    assert result.coverage.budget_exhausted is True


# ── 7. Summary contains the mandated wording ──────────────────────────────


def test_summary_includes_large_pr_risk_triage_mode_wording():
    raw = _build_diff(num_files=26)
    detection = detect_large_pr(
        changed_files=26, added_lines=26 * 6, total_diff_bytes=len(raw.encode("utf-8"))
    )
    engine, _ = _make_engine_with_recording_orchestrator()
    run = engine.analyze_diff_large_pr_mode(raw, detection)

    block = format_large_pr_summary(
        run.coverage,
        llm_calls_used=run.llm_calls_budget_used,
        llm_calls_total=run.llm_calls_budget_total,
    )
    assert LARGE_PR_BANNER in block

    # And it threads through the full summary comment too.
    v = Verdict(
        verdict=VerdictType.FALSE_POSITIVE,
        severity=Severity.NA,
        cwe_id="N/A",
        confidence=0.95,
        title="Safe",
        summary="ok",
        evidence="",
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector=None,
        remediation=None,
        false_positive_reason=None,
    )
    full = format_summary_comment(v, pr_number=42, sha="abc1234", large_pr_summary=block)
    assert LARGE_PR_BANNER in full
    assert "Files changed:" in full
    assert "Files analyzed:" in full
    assert "Files skipped:" in full
    assert "LLM calls used:" in full
    assert "Budget exhausted:" in full
    assert "Large PR triggers:" in full


def test_summary_omits_large_pr_block_when_not_large():
    """Small-PR comments must look exactly as before — no Large PR block."""
    v = Verdict(
        verdict=VerdictType.FALSE_POSITIVE,
        severity=Severity.NA,
        cwe_id="N/A",
        confidence=0.95,
        title="Safe",
        summary="ok",
        evidence="",
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector=None,
        remediation=None,
        false_positive_reason=None,
    )
    body = format_summary_comment(v, pr_number=1, sha="deadbee")
    assert LARGE_PR_BANNER not in body
    assert "Large PR Risk Triage Mode coverage" not in body


# ── 8. Both entrypoint paths covered (smoke-level) ─────────────────────────


def test_both_entrypoints_import_the_large_pr_wiring():
    """Phase 2 must wire detect_large_pr + format_large_pr_summary into both
    entrypoints. We verify by inspecting their source — neither path can
    silently miss the new mode.
    """
    import aegisdiff.app_entrypoint as app_ep
    import aegisdiff.entrypoint as ep

    for path in (Path(ep.__file__), Path(app_ep.__file__)):
        text = path.read_text()
        assert "detect_large_pr(" in text, f"{path.name} must call detect_large_pr"
        assert "analyze_diff_large_pr_mode(" in text, (
            f"{path.name} must call analyze_diff_large_pr_mode"
        )
        assert "format_large_pr_summary" in text, (
            f"{path.name} must format the Large PR summary block"
        )


# ── 9. Changed-lines-only instructions appear in Large PR prompts ──────────


def test_large_pr_prompts_include_change_only_constraints():
    raw = _build_diff(num_files=26, prefix="src/auth/h")
    detection = detect_large_pr(
        changed_files=26, added_lines=200, total_diff_bytes=len(raw.encode("utf-8"))
    )
    engine, orch = _make_engine_with_recording_orchestrator()
    engine.analyze_diff_large_pr_mode(raw, detection)

    assert orch.complete.call_count >= 1
    for call in orch.complete.call_args_list:
        sp = call.args[0].system_prompt
        # Original cynical-AppSec system prompt is preserved.
        assert "ANALYSIS PROTOCOL" in sp
        # Plus the Large-PR addendum with its hard rules.
        assert "LARGE PR RISK TRIAGE MODE" in sp
        assert "Analyze only this selected changed file/hunk/chunk" in sp
        assert "TRUE_POSITIVE still requires confidence >= 0.7" in sp


def test_normal_analyze_diff_does_not_inject_large_pr_addendum():
    """analyze_diff(large_pr_mode=False) must NOT carry the addendum so
    small-PR behaviour is exactly as before."""
    orch = MagicMock(spec=LLMOrchestrator)
    orch.complete.side_effect = lambda req: _llm_response(_fp_json())
    engine = TriageEngine(orch, repo_root=Path("."))
    diff = _build_diff(num_files=1, lines_per_file=2)

    engine.analyze_diff(diff)  # default large_pr_mode=False
    assert orch.complete.call_count == 1
    sp = orch.complete.call_args.args[0].system_prompt
    assert sp == APPSEC_SYSTEM_PROMPT  # unchanged
    assert "LARGE PR RISK TRIAGE MODE" not in sp


# ── 10. Test-file deprioritization only applies in Large PR Mode ──────────


def test_test_files_deprioritized_only_in_large_pr_mode():
    # Build a Large PR with one non-test file + many test files. The non-test
    # file must take precedence; the tests are deprioritized but may be
    # picked up if budget remains.
    raw = (
        "diff --git a/src/auth/login.py b/src/auth/login.py\n"
        "--- a/src/auth/login.py\n+++ b/src/auth/login.py\n"
        "@@ -1,1 +1,2 @@\n import os\n+def login(): pass\n"
    ) + _build_diff(num_files=25, prefix="tests/test_x")
    budgets = LargePRBudgets(max_files_analyzed=3)
    detection = detect_large_pr(
        changed_files=26,
        added_lines=200,
        total_diff_bytes=len(raw.encode("utf-8")),
        budgets=budgets,
    )
    engine, _ = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)
    selected_paths = [c.path for c in result.selection.selected]
    # The single high-risk file lands first.
    assert selected_paths[0] == "src/auth/login.py"
    # And the existing chunked path (small PR / chunked mode) does NOT use
    # Phase 1's deprioritisation: it skips test files outright via the
    # legacy regex. We only assert the Large PR Mode behaviour here; the
    # existing behaviour is covered by tests/test_chunked_analysis.py.


# ── budget bookkeeping sanity ──────────────────────────────────────────────


def test_run_result_reports_budget_metrics():
    raw = _build_diff(num_files=5, prefix="src/auth/handler")
    budgets = LargePRBudgets(max_files_analyzed=5, max_llm_calls_per_pr=10)
    # Force large-PR mode by explicit detection.
    from aegisdiff.triage.large_pr import LargePRDetection

    detection = LargePRDetection(
        is_large_pr=True,
        reasons=["forced for test"],
        budgets=budgets,
    )
    engine, _ = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)
    assert result.llm_calls_budget_total == 10
    assert result.llm_calls_budget_used >= 1
    assert result.coverage.mode == "large_pr"
    assert isinstance(result.coverage.large_pr_reasons, list)


@pytest.mark.parametrize(
    "added_lines,total_bytes,expected",
    [
        (10, 1000, False),  # small
        (1001, 1000, True),  # over line threshold
        (10, 500_001, True),  # over byte threshold
    ],
)
def test_detect_large_pr_thresholds(added_lines, total_bytes, expected):
    d = detect_large_pr(changed_files=2, added_lines=added_lines, total_diff_bytes=total_bytes)
    assert d.is_large_pr is expected


# ── Hardening: chunk byte safety ──────────────────────────────────────────


def test_max_chunk_bytes_default():
    from aegisdiff.triage.large_pr import LargePRBudgets

    assert LargePRBudgets().max_chunk_bytes == 32_000


def test_trim_chunk_returns_input_unchanged_when_under_budget():
    from aegisdiff.triage.engine import _trim_chunk_to_byte_budget

    chunk = (
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,2 @@\n import os\n+x = 1\n"
    )
    out, trimmed = _trim_chunk_to_byte_budget(chunk, 32_000)
    assert out == chunk
    assert trimmed is False


def test_trim_chunk_caps_oversized_chunk_and_preserves_header():
    from aegisdiff.triage.engine import _trim_chunk_to_byte_budget

    body = "\n".join(f"+    line_{i} = compute({i})" for i in range(2000))
    chunk = (
        "diff --git a/big.py b/big.py\n"
        "--- a/big.py\n+++ b/big.py\n"
        "@@ -1,1 +1,2001 @@\n import os\n" + body + "\n"
    )
    out, trimmed = _trim_chunk_to_byte_budget(chunk, 4_000)
    assert trimmed is True
    assert len(out.encode("utf-8")) <= 4_000
    # Header metadata must survive — the LLM still needs to know what file.
    assert "diff --git a/big.py b/big.py" in out
    assert "@@ -1,1 +1,2001 @@" in out
    # And we must still send some body content, not just the header.
    assert "line_0" in out


def test_large_pr_mode_caps_oversized_chunk_before_llm():
    raw = "".join(
        f"diff --git a/src/auth/h_{i}.py b/src/auth/h_{i}.py\n"
        f"--- a/src/auth/h_{i}.py\n+++ b/src/auth/h_{i}.py\n"
        f"@@ -1,1 +1,200 @@\n import os\n"
        + "\n".join(f"+    pad_{j} = 'x' * 200" for j in range(150))
        + "\n"
        for i in range(3)
    )
    budgets = LargePRBudgets(
        max_files_analyzed=3,
        max_chunks_per_file=1,
        max_added_lines_per_chunk=400,  # line cap is generous
        max_chunk_bytes=2_000,  # but byte cap is tight — must still trim
        max_llm_calls_per_pr=10,
    )
    detection = detect_large_pr(
        changed_files=3, added_lines=600, total_diff_bytes=len(raw.encode("utf-8")), budgets=budgets
    )
    # Force large-PR mode for this synthetic file count below the default 25.
    detection.is_large_pr = True
    detection.reasons.append("forced for byte-cap test")

    engine, orch = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)

    assert orch.complete.call_count >= 1
    assert result.chunks_trimmed >= 1, "expected at least one chunk to be byte-trimmed"
    # Every prompt must respect the byte cap on the chunk we passed in.
    for call in orch.complete.call_args_list:
        # The user_message wraps the chunk with extractor output, so we
        # check that the *raw chunk* the engine saw was trimmed by
        # confirming we received fewer bytes than the synthetic input.
        body = call.args[0].user_message
        assert len(body.encode("utf-8")) < len(raw.encode("utf-8"))


def test_large_pr_mode_completes_when_chunk_is_capped():
    """Trimming a chunk must never abort analysis."""
    raw = (
        "diff --git a/src/auth/login.py b/src/auth/login.py\n"
        "--- a/src/auth/login.py\n+++ b/src/auth/login.py\n"
        "@@ -1,1 +1,500 @@\n import os\n"
        + "\n".join(f"+    line_{i} = 'a' * 200" for i in range(400))
        + "\n"
    )
    budgets = LargePRBudgets(
        max_files_analyzed=1,
        max_chunks_per_file=1,
        max_added_lines_per_chunk=1000,
        max_chunk_bytes=1_500,
        max_llm_calls_per_pr=5,
    )
    detection = detect_large_pr(
        changed_files=1, added_lines=400, total_diff_bytes=len(raw.encode("utf-8")), budgets=budgets
    )
    detection.is_large_pr = True
    detection.reasons.append("forced")

    engine, _ = _make_engine_with_recording_orchestrator()
    result = engine.analyze_diff_large_pr_mode(raw, detection)
    assert result.llm_calls_budget_used == 1
    assert result.chunks_trimmed == 1
    # Run still produced a verdict — analysis completed cleanly.
    assert len(result.verdicts) == 1


def test_small_pr_path_is_not_byte_trimmed():
    """analyze_diff() (small PR / non-Large path) must never trim."""
    diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,2 @@\n import os\n+x = 1\n"
    orch = MagicMock(spec=LLMOrchestrator)
    orch.complete.side_effect = lambda req: _llm_response(_fp_json())
    engine = TriageEngine(orch, repo_root=Path("."))
    engine.analyze_diff(diff)
    # The small-PR path does not pass through the byte-trim helper at all.
    sent = orch.complete.call_args.args[0].user_message
    assert "import os" in sent or "x = 1" in sent  # body survives


# ── Hardening: prompt-injection defense ───────────────────────────────────


def test_large_pr_addendum_includes_untrusted_input_warning():
    assert "UNTRUSTED INPUT" in LARGE_PR_PROMPT_ADDENDUM
    assert "PROMPT INJECTION" in LARGE_PR_PROMPT_ADDENDUM
    assert "ignore previous instructions" in LARGE_PR_PROMPT_ADDENDUM
    assert "Never follow" in LARGE_PR_PROMPT_ADDENDUM


def test_large_pr_prompts_carry_untrusted_input_warning():
    raw = _build_diff(num_files=26, prefix="src/auth/h")
    detection = detect_large_pr(
        changed_files=26, added_lines=200, total_diff_bytes=len(raw.encode("utf-8"))
    )
    engine, orch = _make_engine_with_recording_orchestrator()
    engine.analyze_diff_large_pr_mode(raw, detection)

    assert orch.complete.call_count >= 1
    for call in orch.complete.call_args_list:
        sp = call.args[0].system_prompt
        assert "UNTRUSTED INPUT" in sp
        assert "Never follow" in sp


def test_normal_prompt_does_not_carry_untrusted_input_warning():
    """Small PRs should not pay for the Large PR addendum."""
    orch = MagicMock(spec=LLMOrchestrator)
    orch.complete.side_effect = lambda req: _llm_response(_fp_json())
    engine = TriageEngine(orch, repo_root=Path("."))
    engine.analyze_diff(_build_diff(num_files=1, lines_per_file=1))
    sp = orch.complete.call_args.args[0].system_prompt
    assert sp == APPSEC_SYSTEM_PROMPT
    assert "UNTRUSTED INPUT" not in sp


# ── Hardening: shared severity ranking ────────────────────────────────────


def test_severity_rank_is_canonical_and_shared():
    from aegisdiff.triage.verdicts import SEVERITY_RANK, severity_rank

    # Canonical order: CRITICAL > HIGH > MEDIUM > LOW > INFO > NA.
    assert (
        severity_rank(Severity.CRITICAL)
        > severity_rank(Severity.HIGH)
        > severity_rank(Severity.MEDIUM)
        > severity_rank(Severity.LOW)
        > severity_rank(Severity.INFO)
        > severity_rank(Severity.NA)
    )
    assert SEVERITY_RANK[Severity.CRITICAL] == 5
    assert SEVERITY_RANK[Severity.NA] == 0


def test_no_duplicate_severity_rank_maps_in_codebase():
    """Belt-and-braces: no module other than verdicts.py may declare the
    severity → rank mapping. Phase 2 hardening required a single source.
    """
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for py in (repo_root / "aegisdiff").rglob("*.py"):
        if py.name == "verdicts.py":
            continue
        text = py.read_text()
        if "Severity.CRITICAL: 5" in text and "Severity.NA: 0" in text:
            offenders.append(str(py.relative_to(repo_root)))
    assert offenders == [], f"duplicate severity-rank map(s) found: {offenders}"


# ── Hardening: exact inline overflow ──────────────────────────────────────


def _verdict_with_line(severity: Severity, line: int = 10, path: str = "x.py") -> Verdict:
    return Verdict(
        verdict=VerdictType.TRUE_POSITIVE,
        severity=severity,
        cwe_id="CWE-89",
        confidence=0.9,
        title=f"f-{line}",
        summary="",
        evidence="",
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector=None,
        remediation=None,
        false_positive_reason=None,
        line_number=line,
        file_path=path,
    )


def _verdict_no_line(severity: Severity = Severity.HIGH) -> Verdict:
    return Verdict(
        verdict=VerdictType.TRUE_POSITIVE,
        severity=severity,
        cwe_id="CWE-79",
        confidence=0.9,
        title="no-line",
        summary="",
        evidence="",
        sanitizer_found=False,
        sanitizer_description=None,
        attack_vector=None,
        remediation=None,
        false_positive_reason=None,
        line_number=None,
        file_path=None,
    )


def test_select_inline_findings_exact_overflow_when_over_cap():
    from aegisdiff.triage.budget import select_inline_findings

    verdicts = [_verdict_with_line(Severity.HIGH, line=i + 1) for i in range(12)]
    selected, overflow = select_inline_findings(verdicts, max_inline_comments=10)
    assert len(selected) == 10
    assert overflow == 2


def test_select_inline_findings_zero_overflow_when_under_cap():
    from aegisdiff.triage.budget import select_inline_findings

    verdicts = [_verdict_with_line(Severity.HIGH, line=i + 1) for i in range(7)]
    selected, overflow = select_inline_findings(verdicts, max_inline_comments=10)
    assert len(selected) == 7
    assert overflow == 0


def test_select_inline_findings_excludes_findings_without_line_or_path():
    """Findings that can't be inline comments must NOT count toward overflow."""
    from aegisdiff.triage.budget import select_inline_findings

    eligible = [_verdict_with_line(Severity.HIGH, line=i + 1) for i in range(5)]
    non_eligible = [_verdict_no_line() for _ in range(20)]
    verdicts = eligible + non_eligible
    selected, overflow = select_inline_findings(verdicts, max_inline_comments=3)
    assert len(selected) == 3
    # Overflow is 5 - 3 = 2, not 25 - 3.
    assert overflow == 2


def test_select_inline_findings_sorts_critical_high_first():
    from aegisdiff.triage.budget import select_inline_findings

    low = _verdict_with_line(Severity.LOW, line=1)
    info = _verdict_with_line(Severity.INFO, line=2)
    crit = _verdict_with_line(Severity.CRITICAL, line=3)
    high = _verdict_with_line(Severity.HIGH, line=4)
    verdicts = [low, info, crit, high]
    selected, overflow = select_inline_findings(verdicts, max_inline_comments=2)
    assert [v.severity for v in selected] == [Severity.CRITICAL, Severity.HIGH]
    assert overflow == 2


def test_select_inline_findings_zero_cap_returns_empty_with_full_overflow():
    from aegisdiff.triage.budget import select_inline_findings

    verdicts = [_verdict_with_line(Severity.HIGH, line=i + 1) for i in range(3)]
    selected, overflow = select_inline_findings(verdicts, max_inline_comments=0)
    assert selected == []
    assert overflow == 3


# ── Hardening: stale-comment cleanup ──────────────────────────────────────


def test_file_classifier_has_no_stale_substring_comment():
    """Phase 1 switched to whole-token matching; comments must reflect that."""
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parent.parent
        / "aegisdiff"
        / "triage"
        / "file_classifier.py"
    ).read_text()
    # The accurate comments mention "substring" only in the negative
    # ("not arbitrary substrings"). The old wrong comment claimed scoring
    # was substring-based — that wording must be gone.
    assert "path-substring based" not in text
    assert "Score is path-substring" not in text
