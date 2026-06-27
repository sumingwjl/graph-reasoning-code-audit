#!/usr/bin/env python3
"""Merge normalized secret_findings JSON files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def finding_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    locations = item.get("locations") or [{}]
    location = locations[0] if locations and isinstance(locations[0], dict) else {}
    fingerprint = str(item.get("fingerprint") or "")
    semantic_key = (
        str(location.get("path") or ""),
        str(location.get("line") or ""),
        str(item.get("rule_id") or ""),
        str((item.get("secret") or {}).get("redacted") or ""),
    )
    if any(semantic_key):
        return semantic_key
    return ("fingerprint", fingerprint, "", "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    merged: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []

    for input_path in args.inputs:
        payload = load_json(input_path)
        source = payload.get("source")
        if isinstance(source, dict):
            sources.append(source)
        for item in payload.get("findings", []):
            key = finding_key(item)
            existing = seen.get(key)
            if existing:
                existing_git = existing.get("git_context") or {}
                item_git = item.get("git_context") or {}
                if item_git.get("commit") and not existing_git.get("commit"):
                    existing["git_context"] = item_git
                existing["tool"] = ",".join(sorted(set(str(existing.get("tool", "")).split(",") + [str(item.get("tool", ""))]) - {""}))
                continue
            item = dict(item)
            item["id"] = f"S-{len(merged) + 1:03d}"
            seen[key] = item
            merged.append(item)

    output = {
        "schema": "graph-reasoning-code-audit/secret-findings-v1",
        "source": {
            "tool": "merged-secret-scanners",
            "inputs": [str(path) for path in args.inputs],
            "sources": sources,
        },
        "findings": merged,
        "summary": {
            "findings": len(merged),
            "valid": sum(1 for item in merged if (item.get("validation") or {}).get("status") == "valid"),
            "invalid": sum(1 for item in merged if (item.get("validation") or {}).get("status") == "invalid"),
            "unknown": sum(1 for item in merged if (item.get("validation") or {}).get("status") == "unknown"),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
