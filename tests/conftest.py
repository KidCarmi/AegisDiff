"""Shared pytest fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_diff() -> str:
    return (FIXTURES_DIR / "sample.diff").read_text()


@pytest.fixture
def safe_diff() -> str:
    return (FIXTURES_DIR / "safe.diff").read_text()


@pytest.fixture
def empty_diff() -> str:
    return ""
