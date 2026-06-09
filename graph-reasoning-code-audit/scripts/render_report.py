#!/usr/bin/env python3
"""Render evidence.json to final_report.md."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CLASS_LABEL = {
    "A": "A. Identity and Access Control",
    "B": "B. Workflow and State Machine",
    "C": "C. Business Logic and Abuse",
    "D": "D. Injection and Unsafe Interpretation",
    "E": "E. Data Exposure and Privacy",
    "F": "F. Secrets, Crypto, and Session Security",
    "G": "G. External Boundaries, Files, and Network",
    "H": "H. Concurrency, Consistency, and Resource Exhaustion",
    "SCA": "SCA. Dependency and Configuration Advisory",
}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def format_locations(locations: list[dict[str, Any]]) -> str:
    values = []
    for loc in locations:
        path = loc.get("path")
        line = loc.get("line")
        if path and line:
            values.append(f"`{path}:{line}`")
        elif path:
            values.append(f"`{path}`")
    return ", ".join(values) if values else "No concrete source location yet"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    evidence = load(args.evidence)
    stats = evidence.get("stats") or {}
    findings = [item for item in evidence.get("findings", []) if isinstance(item, dict)]
    lines = [
        "# Graph Reasoning Code Audit Report",
        "",
        "## Summary",
        "",
        f"- Hypotheses: {stats.get('hypotheses', len(findings))}",
        f"- Confirmed: {stats.get('confirmed', 0)}",
        f"- Needs review: {stats.get('needs_review', 0)}",
        f"- False positives: {stats.get('false_positive', 0)}",
        "",
    ]

    for status in ("confirmed", "needs_review", "false_positive"):
        group = [item for item in findings if item.get("status") == status]
        if not group:
            continue
        lines.extend([f"## {status.replace('_', ' ').title()}", ""])
        for item in group:
            class_name = CLASS_LABEL.get(str(item.get("class")), str(item.get("class") or "Unknown"))
            lines.extend(
                [
                    f"### {item.get('id')} - {item.get('title')}",
                    "",
                    f"- Class: {class_name}",
                    f"- Type: `{item.get('type')}`",
                    f"- Risk: `{item.get('risk')}`",
                    f"- Confidence: `{item.get('confidence')}`",
                    f"- Locations: {format_locations(item.get('locations') or [])}",
                    f"- Summary: {item.get('reasoning_summary') or 'No summary yet'}",
                    "",
                ]
            )
            tool_evidence = item.get("tool_evidence") or {}
            lines.extend(
                [
                    "Tool evidence:",
                    f"- Semgrep: {len(tool_evidence.get('semgrep') or [])}",
                    f"- Joern: {len(tool_evidence.get('joern') or [])}",
                    f"- CodeQL: {len(tool_evidence.get('codeql') or [])}",
                    "",
                ]
            )
            if item.get("fix_suggestion"):
                lines.extend(["Fix suggestion:", "", str(item["fix_suggestion"]), ""])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
