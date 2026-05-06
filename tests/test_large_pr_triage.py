"""
Phase 1 tests for Large PR Risk Triage Mode.

Pure unit tests — no LLM, no GitHub, no network. Covers:
  - large PR detection thresholds
  - file classification (skip / deprioritize / dependency-only / analyze)
  - budget-aware selection
  - coverage metadata construction
"""

from __future__ import annotations

import pytest

from aegisdiff.triage.budget import (
    SKIP_REASON_BUDGET_EXHAUSTED,
    SKIP_REASON_DEPENDENCY_ONLY,
    SKIP_REASON_DOCS,
    SelectionResult,
    select_files_for_analysis,
)
from aegisdiff.triage.coverage import CoverageMetadata, build_coverage_metadata
from aegisdiff.triage.file_classifier import (
    Decision,
    classify_file,
    classify_files,
)
from aegisdiff.triage.large_pr import (
    LargePRBudgets,
    LargePRDetection,
    detect_large_pr,
)

# ── 1-4. Large PR detection ───────────────────────────────────────────────


def test_large_pr_detection_triggers_on_changed_file_count():
    d = detect_large_pr(changed_files=26, added_lines=10, total_diff_bytes=100)
    assert d.is_large_pr is True
    assert any("changed_files" in r for r in d.reasons)


def test_large_pr_detection_triggers_on_added_line_count():
    d = detect_large_pr(changed_files=2, added_lines=1001, total_diff_bytes=100)
    assert d.is_large_pr is True
    assert any("added_lines" in r for r in d.reasons)


def test_large_pr_detection_triggers_on_diff_byte_size():
    d = detect_large_pr(changed_files=2, added_lines=10, total_diff_bytes=500_001)
    assert d.is_large_pr is True
    assert any("total_diff_bytes" in r for r in d.reasons)


def test_small_pr_does_not_trigger_large_pr_mode():
    d = detect_large_pr(changed_files=5, added_lines=200, total_diff_bytes=20_000)
    assert d.is_large_pr is False
    assert d.reasons == []


def test_large_pr_detection_at_threshold_boundary_is_not_large():
    # Equal to threshold should not trip — only strictly greater.
    b = LargePRBudgets()
    d = detect_large_pr(
        changed_files=b.changed_files_threshold,
        added_lines=b.added_lines_threshold,
        total_diff_bytes=b.total_diff_bytes_threshold,
    )
    assert d.is_large_pr is False


def test_large_pr_detection_returns_budgets():
    d = detect_large_pr(changed_files=100, added_lines=0, total_diff_bytes=0)
    assert isinstance(d, LargePRDetection)
    assert isinstance(d.budgets, LargePRBudgets)
    assert d.budgets.max_files_analyzed == 20
    assert d.budgets.max_chunks_per_file == 5
    assert d.budgets.max_llm_calls_per_pr == 40
    assert d.budgets.max_inline_comments == 10
    assert d.budgets.max_added_lines_per_chunk == 120


def test_detection_to_dict_is_serialisable():
    d = detect_large_pr(changed_files=26, added_lines=0, total_diff_bytes=0)
    payload = d.to_dict()
    assert payload["is_large_pr"] is True
    assert isinstance(payload["reasons"], list)
    assert payload["budgets"]["changed_files_threshold"] == 25


# ── 5-10. File classifier — skip / dependency-only / deprioritize ────────


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "docs/architecture.md",
        "doc/intro.md",
        "CHANGELOG.md",
        "notes.txt",
        "guides/setup.rst",
    ],
)
def test_file_classifier_skips_docs(path):
    c = classify_file(path)
    assert c.decision == Decision.SKIP
    assert "docs" in c.reasons


@pytest.mark.parametrize(
    "path",
    [
        "dist/main.js",
        "build/output.bundle.js",
        "coverage/lcov-report/index.html",
        "node_modules/leftpad/index.js",
        "vendor/github.com/foo/bar.go",
        "target/debug/app",
    ],
)
def test_file_classifier_skips_generated_and_build_folders(path):
    c = classify_file(path)
    assert c.decision == Decision.SKIP
    assert "generated" in c.reasons


@pytest.mark.parametrize(
    "path",
    [
        "web/public/logo.png",
        "assets/photo.JPG",
        "icon.svg",
        "fonts/Inter.woff2",
        "src/img/avatar.gif",
        "favicon.ico",
    ],
)
def test_file_classifier_skips_static_assets(path):
    c = classify_file(path)
    assert c.decision == Decision.SKIP
    assert "static_asset" in c.reasons


@pytest.mark.parametrize(
    "path",
    [
        "web/public/jquery.min.js",
        "static/styles.min.css",
        "vendor/lib.MIN.JS",
    ],
)
def test_file_classifier_skips_minified_files(path):
    c = classify_file(path)
    assert c.decision == Decision.SKIP
    assert "minified" in c.reasons


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_engine.py",
        "src/foo/bar.test.ts",
        "src/foo/bar.spec.js",
        "test/integration.go",
        "__tests__/widget.tsx",
        "spec/models_spec.rb",
    ],
)
def test_file_classifier_deprioritizes_tests(path):
    c = classify_file(path)
    assert c.decision == Decision.DEPRIORITIZE
    assert "test_file" in c.reasons
    # Deprioritized files should still have a (low) score, lower than a
    # high-risk production file.
    assert 0 < c.risk_score < 50


@pytest.mark.parametrize(
    "path",
    [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
    ],
)
def test_file_classifier_marks_lockfiles_as_dependency_only(path):
    c = classify_file(path)
    assert c.decision == Decision.DEPENDENCY_ONLY
    assert "lockfile" in c.reasons


# ── 11-17. File classifier — high-risk path scoring ───────────────────────


def _neutral_baseline_score() -> int:
    return classify_file("src/utils/strings.py").risk_score


def test_classifier_prioritizes_auth_paths():
    base = _neutral_baseline_score()
    for path in [
        "web/lib/auth.ts",
        "src/login/handler.py",
        "internal/session/cookie.go",
        "api/jwt_token.py",
        "lib/permission.rb",
        "rbac/resolver.ts",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base, f"{path} should outrank a neutral file"


def test_classifier_prioritizes_api_route_controller_handler_paths():
    base = _neutral_baseline_score()
    for path in [
        "web/app/api/users/route.ts",
        "src/orders/order_controller.py",
        "internal/handler/admin.go",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_prioritizes_db_query_sql_paths():
    base = _neutral_baseline_score()
    for path in [
        "src/db/connection.py",
        "queries/orders.sql",
        "lib/sql_builder.ts",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_prioritizes_payment_billing_webhook_paths():
    base = _neutral_baseline_score()
    for path in [
        "src/payment/charge.py",
        "billing/invoice.ts",
        "web/app/api/webhooks/stripe/route.ts",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_prioritizes_upload_file_path_paths():
    base = _neutral_baseline_score()
    for path in [
        "src/upload/handler.py",
        "lib/file_system.go",
        "web/lib/path_resolver.ts",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_prioritizes_network_request_fetch_http_paths():
    base = _neutral_baseline_score()
    for path in [
        "src/network/socket.py",
        "lib/request_signer.ts",
        "internal/fetch/client.go",
        "src/http/proxy.py",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_prioritizes_config_secret_env_paths():
    base = _neutral_baseline_score()
    for path in [
        "src/config/loader.py",
        "lib/secret_manager.ts",
        "internal/env/parser.go",
    ]:
        c = classify_file(path)
        assert c.decision == Decision.ANALYZE
        assert c.risk_score > base


def test_classifier_neutral_application_files_still_analyze():
    c = classify_file("src/utils/strings.py")
    assert c.decision == Decision.ANALYZE
    assert 0 < c.risk_score < 100


def test_skip_wins_over_risk_keywords_for_obvious_assets():
    # "api-icon.svg" contains the "api" keyword but is still an asset.
    c = classify_file("web/public/api-icon.svg")
    assert c.decision == Decision.SKIP
    assert "static_asset" in c.reasons


def test_classify_files_helper_preserves_input_order():
    paths = ["README.md", "src/auth.py", "package-lock.json"]
    results = classify_files(paths)
    assert [r.path for r in results] == paths


# ── 18-22. Selection / budget ─────────────────────────────────────────────


def test_selection_respects_max_files_analyzed():
    budgets = LargePRBudgets(max_files_analyzed=3)
    classifications = classify_files([f"src/auth/handler_{i}.py" for i in range(10)])
    result = select_files_for_analysis(classifications, budgets)
    assert len(result.selected) == 3
    assert result.budget_exhausted is True


def test_selection_excludes_skipped_files():
    classifications = classify_files(
        [
            "README.md",
            "src/auth/login.py",
            "web/public/logo.png",
            "dist/bundle.js",
        ]
    )
    result = select_files_for_analysis(classifications, LargePRBudgets())
    selected_paths = {c.path for c in result.selected}
    assert "src/auth/login.py" in selected_paths
    assert "README.md" not in selected_paths
    assert "web/public/logo.png" not in selected_paths
    assert "dist/bundle.js" not in selected_paths


def test_selection_excludes_dependency_only_from_normal_analysis():
    classifications = classify_files(
        [
            "package-lock.json",
            "yarn.lock",
            "src/auth/login.py",
        ]
    )
    result = select_files_for_analysis(classifications, LargePRBudgets())
    selected_paths = {c.path for c in result.selected}
    assert "src/auth/login.py" in selected_paths
    assert "package-lock.json" not in selected_paths
    assert "yarn.lock" not in selected_paths
    assert result.skip_reason_counts.get(SKIP_REASON_DEPENDENCY_ONLY) == 2


def test_selection_reports_skip_reason_counts():
    classifications = classify_files(
        [
            "README.md",
            "docs/intro.md",
            "web/public/logo.png",
            "package-lock.json",
            "src/auth/login.py",
        ]
    )
    result = select_files_for_analysis(classifications, LargePRBudgets())
    counts = result.skip_reason_counts
    assert counts.get(SKIP_REASON_DOCS) == 2
    assert counts.get("static_asset") == 1
    assert counts.get(SKIP_REASON_DEPENDENCY_ONLY) == 1


def test_selection_reports_budget_exhaustion():
    # Below cap → not exhausted.
    budgets = LargePRBudgets(max_files_analyzed=20)
    small = classify_files([f"src/svc_{i}.py" for i in range(5)])
    assert select_files_for_analysis(small, budgets).budget_exhausted is False
    # Above cap → exhausted, overflow recorded with budget_exhausted reason.
    big = classify_files([f"src/svc_{i}.py" for i in range(25)])
    result = select_files_for_analysis(big, budgets)
    assert result.budget_exhausted is True
    assert len(result.selected) == 20
    assert result.skip_reason_counts.get(SKIP_REASON_BUDGET_EXHAUSTED) == 5


def test_selection_sorts_analyze_files_by_risk_score_descending():
    # auth path should outrank a neutral utils path.
    classifications = classify_files(
        [
            "src/utils/strings.py",
            "src/auth/login.py",
            "src/utils/format.py",
        ]
    )
    result = select_files_for_analysis(classifications, LargePRBudgets(max_files_analyzed=3))
    assert result.selected[0].path == "src/auth/login.py"


def test_selection_appends_deprioritized_after_analyze_within_budget():
    # All four fit in budget=4. Tests should land at the back of the list.
    classifications = classify_files(
        [
            "tests/test_auth.py",
            "src/utils/format.py",
            "src/auth/login.py",
        ]
    )
    result = select_files_for_analysis(classifications, LargePRBudgets(max_files_analyzed=4))
    assert len(result.selected) == 3
    assert result.selected[-1].decision == Decision.DEPRIORITIZE


# ── 23. Coverage metadata ─────────────────────────────────────────────────


def test_coverage_metadata_can_be_created_from_selection_results():
    classifications = classify_files(
        [
            "README.md",
            "src/auth/login.py",
            "src/utils/format.py",
            "package-lock.json",
            "tests/test_auth.py",
        ]
    )
    detection = detect_large_pr(
        changed_files=len(classifications),
        added_lines=50,
        total_diff_bytes=4_000,
    )
    selection = select_files_for_analysis(classifications, detection.budgets)
    coverage = build_coverage_metadata(detection, selection, files_changed=len(classifications))

    assert isinstance(coverage, CoverageMetadata)
    assert coverage.mode == "normal"  # well under thresholds
    assert coverage.files_changed == 5
    assert coverage.files_analyzed == len(selection.selected)
    assert coverage.files_skipped == len(selection.skipped)
    assert coverage.budget_exhausted is False
    # Skip-reason buckets propagate through.
    assert coverage.skip_reasons.get(SKIP_REASON_DOCS, 0) >= 1
    assert coverage.skip_reasons.get(SKIP_REASON_DEPENDENCY_ONLY, 0) >= 1

    payload = coverage.to_dict()
    assert payload["mode"] == "normal"
    assert payload["files_changed"] == 5
    assert isinstance(payload["skip_reasons"], dict)
    assert payload["large_pr_reasons"] == []


def test_coverage_metadata_marks_large_pr_mode():
    detection = detect_large_pr(changed_files=50, added_lines=2000, total_diff_bytes=600_000)
    classifications = classify_files([f"src/svc_{i}.py" for i in range(50)])
    selection = select_files_for_analysis(classifications, detection.budgets)
    coverage = build_coverage_metadata(detection, selection)

    assert coverage.mode == "large_pr"
    assert coverage.budget_exhausted is True
    assert coverage.large_pr_reasons  # non-empty
    assert coverage.files_analyzed == detection.budgets.max_files_analyzed


# ── Result / dataclass sanity ─────────────────────────────────────────────


def test_selection_result_to_dict_is_json_friendly():
    classifications = classify_files(["src/auth/login.py", "README.md", "package-lock.json"])
    result = select_files_for_analysis(classifications, LargePRBudgets())
    assert isinstance(result, SelectionResult)
    payload = result.to_dict()
    assert {"selected", "skipped", "skip_reason_counts", "budget_exhausted"} <= set(payload)


def test_file_classification_to_dict_round_trip():
    c = classify_file("src/auth/login.py")
    payload = c.to_dict()
    assert payload["path"] == "src/auth/login.py"
    assert payload["decision"] == "analyze"
    assert payload["risk_score"] > 0
    assert isinstance(payload["reasons"], list)


# ── Token-aware keyword matching — false-positive regressions ─────────────
# These paths previously got an undeserved risk boost from substring
# matching: "pathology" contains "path", "authors" contains "auth", etc.
# After tokenisation they should no longer match the listed keyword.


@pytest.mark.parametrize(
    "path, forbidden_keyword",
    [
        ("src/pathology/model.py", "path"),
        ("src/httparty_adapter.rb", "http"),
        ("src/filecoin/client.py", "file"),
        ("src/requested_feature/model.py", "request"),
        ("src/authors/service.py", "auth"),
    ],
)
def test_substring_lookalikes_do_not_match_keyword(path, forbidden_keyword):
    c = classify_file(path)
    # Still gets analyzed — these are normal application files.
    assert c.decision == Decision.ANALYZE
    # …but the false-positive keyword must not appear in the reasons list.
    assert f"keyword:{forbidden_keyword}" not in c.reasons, (
        f"{path} should not have been boosted by '{forbidden_keyword}'"
    )


def test_substring_lookalikes_do_not_inflate_risk_score():
    # All five lookalike paths should score at the neutral baseline — they
    # are application code with no real risk-keyword token.
    base = _neutral_baseline_score()
    for path in [
        "src/pathology/model.py",
        "src/httparty_adapter.rb",
        "src/filecoin/client.py",
        "src/requested_feature/model.py",
        "src/authors/service.py",
    ]:
        c = classify_file(path)
        assert c.risk_score == base, f"{path} should match the neutral baseline"


# ── Token-aware keyword matching — positive matches still work ───────────


def test_token_split_compound_user_file_matches_path_and_file():
    c = classify_file("src/path/user_file.py")
    assert c.decision == Decision.ANALYZE
    assert "keyword:path" in c.reasons
    assert "keyword:file" in c.reasons


def test_token_split_compound_orders_controller_matches_api_and_controller():
    c = classify_file("src/api/orders_controller.py")
    assert c.decision == Decision.ANALYZE
    assert "keyword:api" in c.reasons
    assert "keyword:controller" in c.reasons


def test_token_split_compound_env_loader_matches_config_and_env():
    c = classify_file("src/config/env_loader.py")
    assert c.decision == Decision.ANALYZE
    assert "keyword:config" in c.reasons
    assert "keyword:env" in c.reasons


def test_simple_segment_paths_still_match():
    # No compound names — just the keyword as a path segment.
    c_http = classify_file("src/http/client.py")
    assert "keyword:http" in c_http.reasons

    c_auth = classify_file("src/auth/login.py")
    assert "keyword:auth" in c_auth.reasons
    assert "keyword:login" in c_auth.reasons


def test_token_match_handles_dash_dot_and_mixed_case():
    # Tokeniser must split on '-' and '.' too, and be case-insensitive.
    c = classify_file("src/Auth-Service/Login.Handler.TS")
    assert "keyword:auth" in c.reasons
    assert "keyword:login" in c.reasons
    assert "keyword:handler" in c.reasons


def test_keyword_reasons_are_deduplicated():
    # "auth" appears in two path segments; it should be reported exactly once.
    c = classify_file("src/auth/auth_provider.py")
    assert c.reasons.count("keyword:auth") == 1
