#!/usr/bin/env python3
"""
Seed the dashboard with synthetic scan records for testing.

Usage:
    AEGISDIFF_INGEST_URL=https://your-app.vercel.app/api/ingest \
    AEGISDIFF_REPO_TOKEN=<token-from-repos-page> \
    python scripts/seed_dashboard.py

The token is shown in the dashboard under Repos → CI secrets setup → AEGISDIFF_REPO_TOKEN.
"""
from __future__ import annotations

import os
import sys
import time

import httpx

INGEST_URL = os.environ.get("AEGISDIFF_INGEST_URL", "")
REPO_TOKEN = os.environ.get("AEGISDIFF_REPO_TOKEN", "")

if not INGEST_URL or not REPO_TOKEN:
    print("ERROR: set AEGISDIFF_INGEST_URL and AEGISDIFF_REPO_TOKEN env vars")
    print(__doc__)
    sys.exit(1)

SEED_SCANS = [
    {
        "verdict": "TRUE_POSITIVE",
        "severity": "HIGH",
        "cwe_id": "CWE-89",
        "confidence": 0.92,
        "title": "SQL Injection via unsanitized request.GET parameter",
        "provider": "seed",
        "pr_number": 1,
        "commit_sha": "deadbeef00000000000000000000000000000001",
        "pr_url": None,
        "scan_ms": 1823,
    },
    {
        "verdict": "FALSE_POSITIVE",
        "severity": "N/A",
        "cwe_id": "N/A",
        "confidence": 0.95,
        "title": "Django ORM .filter() — parameterized, not injectable",
        "provider": "seed",
        "pr_number": 2,
        "commit_sha": "deadbeef00000000000000000000000000000002",
        "pr_url": None,
        "scan_ms": 1102,
    },
    {
        "verdict": "NEEDS_REVIEW",
        "severity": "MEDIUM",
        "cwe_id": "CWE-78",
        "confidence": 0.45,
        "title": "Possible command injection — subprocess call with user input",
        "provider": "seed",
        "pr_number": 3,
        "commit_sha": "deadbeef00000000000000000000000000000003",
        "pr_url": None,
        "scan_ms": 2401,
    },
]

headers = {"Authorization": f"Bearer {REPO_TOKEN}", "Content-Type": "application/json"}

print(f"Seeding {len(SEED_SCANS)} scans → {INGEST_URL}\n")
for i, scan in enumerate(SEED_SCANS, 1):
    try:
        resp = httpx.post(INGEST_URL, json=scan, headers=headers, timeout=10.0)
        if resp.status_code == 201:
            print(f"  [{i}/{len(SEED_SCANS)}] OK  {scan['verdict']}  {scan['title'][:60]}")
        else:
            print(f"  [{i}/{len(SEED_SCANS)}] FAIL {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"  [{i}/{len(SEED_SCANS)}] ERROR: {e}")
    time.sleep(0.2)

print("\nDone. Refresh your dashboard.")
