#!/usr/bin/env python3
"""Normalize CodeQL SARIF into graph-reasoning-code-audit tool evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_rule_map(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        return {str(key): str(value) for key, value in data.items()}
    return {}


def first_location(result: dict[str, Any]) -> dict[str, Any] | None:
    locations = result.get("locations") or []
    if not locations:
        return None
    physical = ((locations[0] or {}).get("physicalLocation") or {})
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    path = artifact.get("uri")
    if not path:
        return None
    return {
        "path": str(path).replace("\\", "/"),
        "line": region.get("startLine"),
        "symbol": None,
    }


def path_steps(result: dict[str, Any]) -> list[list[str]]:
    output: list[list[str]] = []
    for flow in result.get("codeFlows") or []:
        for thread in flow.get("threadFlows") or []:
            steps: list[str] = []
            for loc in thread.get("locations") or []:
                physical = (((loc.get("location") or {}).get("physicalLocation") or {}))
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}
                uri = artifact.get("uri")
                if uri:
                    line = region.get("startLine")
                    steps.append(f"{str(uri).replace('\\', '/')}:{line or '?'}")
            if steps:
                output.append(steps)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--hypothesis-id", help="Attach all SARIF results to one hypothesis.")
    parser.add_argument("--rule-map", type=Path, help="JSON map of SARIF ruleId to hypothesis id.")
    args = parser.parse_args()

    sarif = json.loads(args.sarif.read_text(encoding="utf-8-sig"))
    rule_map = load_rule_map(args.rule_map)
    normalized: list[dict[str, Any]] = []

    for run in sarif.get("runs") or []:
        rules = {}
        for extension in ((run.get("tool") or {}).get("extensions") or []):
            for rule in extension.get("rules") or []:
                rules[rule.get("id")] = rule
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            rules[rule.get("id")] = rule

        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "")
            hypothesis_id = args.hypothesis_id or rule_map.get(rule_id)
            location = first_location(result)
            rule = rules.get(rule_id) or {}
            message = (result.get("message") or {}).get("text") or ""
            item = {
                "tool": "codeql",
                "hypothesis_id": hypothesis_id,
                "task": "codeql",
                "status": "hit",
                "locations": [location] if location else [],
                "paths": path_steps(result),
                "details": {
                    "evidence_kind": "suspicious_pattern",
                    "rule_id": rule_id,
                    "rule_name": rule.get("name"),
                    "message": message,
                    "severity": ((result.get("properties") or {}).get("security-severity")
                                 or (result.get("properties") or {}).get("problem.severity")),
                },
            }
            if not hypothesis_id:
                item["metadata"] = {"unmapped": True}
            normalized.append(item)

    payload = {
        "tool": "codeql",
        "status": "ok",
        "results": normalized,
        "raw_summary": {"runs": len(sarif.get("runs") or []), "results": len(normalized)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
