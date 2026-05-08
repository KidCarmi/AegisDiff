"""
SARIF 2.1.0 builder for GitHub Code Scanning integration.

Converts AegisDiff Verdicts into a valid SARIF document that can be
uploaded to the GitHub Code Scanning API so findings appear in the
repository's Security tab alongside Dependabot and CodeQL alerts.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
from typing import List

from .verdicts import Verdict, VerdictType

# Maps AegisDiff severity to SARIF level
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
    "N/A": "none",
}

# Human-readable names for common CWEs
_CWE_NAMES: dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection / SSTI",
    "CWE-95": "Eval Injection",
    "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-327": "Use of Broken Cryptographic Algorithm",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def _cwe_help_uri(cwe_id: str) -> str:
    num = "".join(c for c in cwe_id if c.isdigit())
    return f"https://cwe.mitre.org/data/definitions/{num}.html" if num else ""


def _rule_for_cwe(cwe_id: str, level: str) -> dict:
    name = _CWE_NAMES.get(cwe_id, cwe_id)
    help_uri = _cwe_help_uri(cwe_id)
    rule: dict = {
        "id": cwe_id,
        "name": name.replace(" ", "").replace("/", "").replace("(", "").replace(")", ""),
        "shortDescription": {"text": f"{name} ({cwe_id})"},
        "fullDescription": {
            "text": (
                f"AegisDiff detected a potential {name} vulnerability. "
                f"Review the flagged code and the inline PR comment for details."
            )
        },
        "defaultConfiguration": {"level": level},
        "properties": {"tags": ["security", cwe_id]},
    }
    if help_uri:
        rule["helpUri"] = help_uri
        rule["help"] = {
            "text": f"See {help_uri} for more information about {name}.",
            "markdown": f"See [{cwe_id}]({help_uri}) for more information about {name}.",
        }
    return rule


def build_sarif(verdicts: List[Verdict], repo: str, commit_sha: str) -> dict:
    """
    Build a SARIF 2.1.0 document from a list of Verdicts.

    Only TRUE_POSITIVE and NEEDS_REVIEW findings are included.
    FALSE_POSITIVE and ERROR verdicts are excluded.

    Result-level deduplication: chunked / Large PR Mode runs may produce
    multiple actionable verdicts that point at the same finding location
    (same CWE, same file, same line). Without dedup those would surface
    as duplicate alerts in the GitHub Security tab. We collapse such
    groups to a single result, keeping the highest-confidence verdict
    (ties broken by first-occurrence order so output is deterministic).
    Rule-level dedup (one rule per unique CWE) is preserved as before.

    Args:
        verdicts:    List of Verdict objects from the triage engine.
        repo:        Repository in "owner/name" format.
        commit_sha:  Full 40-char commit SHA being scanned.
    """
    actionable = [
        v for v in verdicts if v.verdict in (VerdictType.TRUE_POSITIVE, VerdictType.NEEDS_REVIEW)
    ]

    # ── Result-level dedup ────────────────────────────────────────────────
    # Key: (normalised cwe_id, file_path, line_number). ``line_number=0``
    # and ``line_number=None`` both mean "no specific line" and are
    # normalised to ``None`` so they collapse together. Different CWEs at
    # the same location stay separate; missing-location verdicts with
    # different CWEs also stay separate.
    groups: dict[tuple, Verdict] = {}
    for v in actionable:
        cwe_id = v.cwe_id if v.cwe_id and v.cwe_id != "N/A" else "AegisDiff/Finding"
        line_key = v.line_number if (v.line_number and v.line_number > 0) else None
        key = (cwe_id, v.file_path, line_key)
        existing = groups.get(key)
        if existing is None or v.confidence > existing.confidence:
            groups[key] = v

    # Iteration order is insertion order (CPython 3.7+ guarantee), which
    # gives deterministic SARIF output for the same inputs.
    deduped = list(groups.values())

    # Build deduplicated rules (one per unique CWE)
    seen_rules: dict[str, dict] = {}
    results: list[dict] = []

    for v in deduped:
        cwe_id = v.cwe_id if v.cwe_id and v.cwe_id != "N/A" else "AegisDiff/Finding"
        level = _SEVERITY_TO_LEVEL.get(v.severity.value, "warning")

        if cwe_id not in seen_rules:
            seen_rules[cwe_id] = _rule_for_cwe(cwe_id, level)

        # Build location — use file_path/line_number when available
        if v.file_path:
            physical = {
                "artifactLocation": {
                    "uri": v.file_path.lstrip("/"),
                    "uriBaseId": "%SRCROOT%",
                },
            }
            if v.line_number and v.line_number > 0:
                physical["region"] = {"startLine": v.line_number}
        else:
            # Fallback: point at repo root (finding still shows in Security tab)
            physical = {
                "artifactLocation": {
                    "uri": ".",
                    "uriBaseId": "%SRCROOT%",
                },
            }

        result: dict = {
            "ruleId": cwe_id,
            "level": level,
            "message": {
                "text": (
                    f"{v.title}. "
                    f"Confidence: {int(v.confidence * 100)}%. "
                    f"See the PR comment for evidence and remediation."
                )
            },
            "locations": [{"physicalLocation": physical}],
            "properties": {
                "confidence": v.confidence,
                "verdict": v.verdict.value,
                "severity": v.severity.value,
                "provider": v.provider or "unknown",
            },
        }
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisDiff",
                        "version": "1.0.0",
                        "informationUri": os.environ.get(
                            "AEGISDIFF_BASE_URL", "https://aegis-diff.vercel.app"
                        ),
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"aegisdiff/{repo}/{commit_sha[:7]}",
                },
            }
        ],
    }


def encode_sarif(sarif: dict) -> str:
    """
    Gzip-compress and base64-encode a SARIF dict for the GitHub Code Scanning API.

    GitHub requires: Content-Encoding: gzip + base64 encoded body.
    """
    raw = json.dumps(sarif, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw, compresslevel=9)
    return base64.b64encode(compressed).decode("ascii")
