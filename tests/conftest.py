"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_real_github_retry_sleep(monkeypatch):
    """Replace ``aegisdiff.github._retry._sleep`` with a no-op for every test.

    The retry helper waits 0.5s + 2.0s between attempts in production.
    Tests that exercise the wrapper's failure paths would otherwise sit
    in real sleeps for several seconds. Tests that *want* to inspect or
    count sleep calls can override ``aegisdiff.github._retry._sleep``
    again inside the test body.
    """
    import aegisdiff.github._retry as _retry

    monkeypatch.setattr(_retry, "_sleep", lambda _seconds: None)


def _load(name: str) -> str:
    return (FIXTURES_DIR / name).read_text()


@pytest.fixture
def sample_diff() -> str:
    return _load("sample.diff")


@pytest.fixture
def safe_diff() -> str:
    return _load("safe.diff")


@pytest.fixture
def empty_diff() -> str:
    return ""


@pytest.fixture
def ssrf_diff() -> str:
    return _load("ssrf.diff")


@pytest.fixture
def ssti_diff() -> str:
    return _load("ssti.diff")


@pytest.fixture
def hardcoded_secret_diff() -> str:
    return _load("hardcoded_secret.diff")


@pytest.fixture
def jwt_weak_diff() -> str:
    return _load("jwt_weak.diff")


@pytest.fixture
def deserialization_diff() -> str:
    return _load("deserialization.diff")


@pytest.fixture
def xxe_diff() -> str:
    return _load("xxe.diff")


@pytest.fixture
def xss_diff() -> str:
    return _load("xss.diff")


@pytest.fixture
def open_redirect_diff() -> str:
    return _load("open_redirect.diff")
