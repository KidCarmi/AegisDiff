"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


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
