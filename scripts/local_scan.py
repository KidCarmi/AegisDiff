#!/usr/bin/env python3
"""
Local developer CLI for running AegisDiff against a diff file.

Usage:
    python scripts/local_scan.py --diff path/to/file.diff [--lang python]

Reads GEMINI_API_KEY / GROQ_API_KEY from environment variables or a .env file.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path so we can import aegisdiff without installing
sys.path.insert(0, str(Path(__file__).parent.parent))


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency required)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> None:
    load_dotenv(Path(__file__).parent.parent / ".env")

    parser = argparse.ArgumentParser(description="AegisDiff local scan")
    parser.add_argument("--diff", required=True, help="Path to a unified diff file")
    parser.add_argument("--lang", default="python", help="Language hint (default: python)")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Path to the repository root (default: current directory)",
    )
    args = parser.parse_args()

    diff_path = Path(args.diff)
    if not diff_path.exists():
        print(f"Error: diff file not found: {diff_path}", file=sys.stderr)
        sys.exit(1)

    raw_diff = diff_path.read_text(errors="replace")

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    groq_key = os.environ.get("GROQ_API_KEY", "")

    if not gemini_key and not groq_key:
        print(
            "Error: No API keys found.\n"
            "Set GEMINI_API_KEY and/or GROQ_API_KEY as environment variables "
            "or in a .env file in the project root.",
            file=sys.stderr,
        )
        sys.exit(1)

    from aegisdiff.llm.orchestrator import LLMOrchestrator
    from aegisdiff.llm.providers.gemini import GeminiProvider
    from aegisdiff.llm.providers.groq import GroqProvider
    from aegisdiff.triage.engine import TriageEngine
    from aegisdiff.github.pr_comment import format_verdict_comment

    providers = []
    if gemini_key:
        providers.append(GeminiProvider(gemini_key))
        print("✓ Gemini 1.5 Pro (primary)")
    if groq_key:
        providers.append(GroqProvider(groq_key))
        print("✓ Groq Llama-3-70b (fallback)")

    orchestrator = LLMOrchestrator(providers)
    engine = TriageEngine(orchestrator, repo_root=Path(args.repo_root), language=args.lang)

    print(f"\nAnalyzing: {diff_path}")
    print("─" * 60)

    verdict = engine.analyze_diff(raw_diff)
    comment = format_verdict_comment(verdict, pr_number=0, sha="local")

    print(comment)

    # Exit 1 on high-confidence true positive (mirrors CI behavior)
    from aegisdiff.triage.verdicts import VerdictType
    if verdict.verdict == VerdictType.TRUE_POSITIVE and verdict.confidence >= 0.8:
        sys.exit(1)


if __name__ == "__main__":
    main()
