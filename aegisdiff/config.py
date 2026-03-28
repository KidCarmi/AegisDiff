"""Environment variable loading and configuration constants."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Config:
    openrouter_api_key: str
    openrouter_api_key_2: str
    openrouter_api_key_3: str
    github_token: str
    repo: str
    pr_number: Optional[int]
    commit_sha: str
    diff_path: str
    aegisdiff_ingest_url: Optional[str]
    aegisdiff_repo_token: Optional[str]
    aegisdiff_gist_id: Optional[str]


def load_config() -> Config:
    """Load configuration from environment variables."""
    pr_str = os.environ.get("PR_NUMBER", "")
    pr_number = int(pr_str) if pr_str.isdigit() else None

    return Config(
        openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
        openrouter_api_key_2=os.environ.get("OPENROUTER_API_KEY_2", ""),
        openrouter_api_key_3=os.environ.get("OPENROUTER_API_KEY_3", ""),
        github_token=os.environ.get("GITHUB_TOKEN", ""),
        repo=os.environ.get("REPO", ""),
        pr_number=pr_number,
        commit_sha=os.environ.get("COMMIT_SHA", "unknown"),
        diff_path=os.environ.get("DIFF_PATH", "/tmp/aegisdiff_pr.diff"),
        aegisdiff_ingest_url=os.environ.get("AEGISDIFF_INGEST_URL"),
        aegisdiff_repo_token=os.environ.get("AEGISDIFF_REPO_TOKEN"),
        aegisdiff_gist_id=os.environ.get("AEGISDIFF_GIST_ID"),
    )
