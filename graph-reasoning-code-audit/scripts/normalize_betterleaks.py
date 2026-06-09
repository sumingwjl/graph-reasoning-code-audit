#!/usr/bin/env python3
"""Normalize Betterleaks JSON output into secret_findings.json."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    return json.loads(text)


def normalize_path(path: str, repo_root: Path | None) -> str:
    text = str(path or "").replace("\\", "/")
    if repo_root:
        root = str(repo_root.resolve()).replace("\\", "/")
        if text.startswith(root + "/"):
            return text[len(root) + 1 :]
    return text.lstrip("./")


def get_any(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def iter_findings(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(payload, dict):
        for key in ("findings", "Findings", "leaks", "Leaks", "results", "Results"):
            values = payload.get(key)
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict):
                        yield item


def redact(value: Any, keep: int = 4) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}...{text[-keep:]}"


def line_number(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def validation_status(item: dict[str, Any]) -> str:
    raw = get_any(item, "Validation", "validation", "ValidationStatus", "validation_status", "validated")
    if isinstance(raw, dict):
        raw = get_any(raw, "result", "status", "valid")
    text = str(raw or "unknown").lower()
    if text in {"valid", "active", "true", "verified"}:
        return "valid"
    if text in {"invalid", "inactive", "false", "revoked"}:
        return "invalid"
    return "unknown"


def risk_for(rule_id: str, description: str, validation: str) -> str:
    text = f"{rule_id} {description}".lower()
    if validation == "valid":
        return "critical"
    if any(token in text for token in ("private-key", "rsa", "ssh", "jwt", "github", "aws", "azure", "gcp")):
        return "high"
    if any(token in text for token in ("password", "secret", "token", "apikey", "api-key", "connection")):
        return "high"
    return "medium"


def confidence_for(validation: str, secret: str, entropy: Any) -> float:
    if validation == "valid":
        return 0.95
    if validation == "invalid":
        return 0.2
    try:
        entropy_value = float(entropy)
    except (TypeError, ValueError):
        entropy_value = 0.0
    if secret and entropy_value >= 4.0:
        return 0.75
    if secret:
        return 0.65
    return 0.5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--betterleaks-results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--source-kind", default="betterleaks", help="betterleaks-git, betterleaks-dir, etc.")
    parser.add_argument("--start-index", type=int, default=1)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve() if args.repo_root else None
    payload = load_json(args.betterleaks_results)
    findings: list[dict[str, Any]] = []

    for index, item in enumerate(iter_findings(payload), start=args.start_index):
        rule_id = str(get_any(item, "RuleID", "rule_id", "RuleId", "rule", "ruleID") or "unknown-rule")
        description = str(get_any(item, "Description", "description", "Message", "message") or rule_id)
        path = normalize_path(str(get_any(item, "File", "file", "Path", "path", "Source", "source") or ""), repo_root)
        start_line = line_number(get_any(item, "StartLine", "start_line", "Line", "line"))
        end_line = line_number(get_any(item, "EndLine", "end_line"))
        secret = str(get_any(item, "Secret", "secret") or "")
        match = str(get_any(item, "Match", "match") or "")
        entropy = get_any(item, "Entropy", "entropy")
        validation = validation_status(item)
        fingerprint = str(get_any(item, "Fingerprint", "fingerprint", "ID", "id") or "")
        commit = str(get_any(item, "Commit", "commit", "CommitHash", "commit_hash") or "")
        tags = get_any(item, "Tags", "tags") or []
        if isinstance(tags, str):
            tags = [tags]

        finding = {
            "id": f"S-{index:03d}",
            "class": "F",
            "type": "hardcoded_secret",
            "tool": args.source_kind,
            "rule_id": rule_id,
            "description": description,
            "risk": risk_for(rule_id, description, validation),
            "confidence": confidence_for(validation, secret, entropy),
            "validation": {
                "status": validation,
                "raw": get_any(item, "Validation", "validation", "ValidationStatus", "validation_status", "validated"),
            },
            "locations": [
                {
                    "path": path,
                    "line": start_line,
                    "end_line": end_line,
                    "note": f"{args.source_kind} matched {rule_id}",
                }
            ],
            "secret": {
                "redacted": redact(secret or match),
                "match_redacted": redact(match),
                "entropy": entropy,
            },
            "git_context": {
                "commit": commit,
                "author": get_any(item, "Author", "author"),
                "email": get_any(item, "Email", "email"),
                "date": get_any(item, "Date", "date"),
                "message": get_any(item, "Message", "message"),
            },
            "tags": tags,
            "fingerprint": fingerprint,
            "status": "needs_review",
            "reasoning": (
                "Secret scanner match. Source validation must decide whether this is a real, "
                "effective secret, test fixture, placeholder, or false positive."
            ),
            "fix_suggestion": "Rotate if effective, remove from source/history, and load via a secret manager or deployment environment.",
            "raw_keys": sorted(item.keys()),
        }
        findings.append(finding)

    output = {
        "schema": "graph-reasoning-code-audit/secret-findings-v1",
        "source": {
            "tool": "betterleaks",
            "input": str(args.betterleaks_results),
            "source_kind": args.source_kind,
        },
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "valid": sum(1 for item in findings if item["validation"]["status"] == "valid"),
            "invalid": sum(1 for item in findings if item["validation"]["status"] == "invalid"),
            "unknown": sum(1 for item in findings if item["validation"]["status"] == "unknown"),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
