#!/usr/bin/env python3
"""Render secret_findings.json as a concise Markdown report."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def risk_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}.get(str(value).lower(), 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-findings", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-items", type=int, default=120)
    args = parser.parse_args()

    payload = load_json(args.secret_findings)
    findings = payload.get("findings", [])
    risk_counts = Counter(str(item.get("risk") or "unknown") for item in findings)
    validation_counts = Counter((item.get("validation") or {}).get("status") or "unknown" for item in findings)
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            -risk_rank(item.get("risk") or "unknown"),
            str((item.get("validation") or {}).get("status") or "unknown"),
            str((item.get("locations") or [{}])[0].get("path") or ""),
            int((item.get("locations") or [{}])[0].get("line") or 0),
        ),
    )

    lines = [
        "# Secret Scan Report",
        "",
        "## Summary",
        "",
        f"- Findings: {len(findings)}",
        f"- Critical: {risk_counts.get('critical', 0)}",
        f"- High: {risk_counts.get('high', 0)}",
        f"- Medium: {risk_counts.get('medium', 0)}",
        f"- Low: {risk_counts.get('low', 0)}",
        f"- Validation valid: {validation_counts.get('valid', 0)}",
        f"- Validation invalid: {validation_counts.get('invalid', 0)}",
        f"- Validation unknown: {validation_counts.get('unknown', 0)}",
        "",
        "Scanner matches are secret-exposure signals. Count them as confirmed vulnerabilities only after source/context validation shows an effective secret or concrete security impact.",
        "",
        "## Findings",
        "",
    ]

    for item in sorted_findings[: args.max_items]:
        location = (item.get("locations") or [{}])[0]
        secret = item.get("secret") or {}
        git_context = item.get("git_context") or {}
        line_text = f":{location.get('line')}" if location.get("line") else ""
        commit_text = f"`{git_context.get('commit')}`" if git_context.get("commit") else "`not recorded`"
        lines.extend(
            [
                f"### {item.get('id')} - {item.get('rule_id', 'unknown-rule')}",
                "",
                f"- Risk: `{item.get('risk', 'unknown')}`",
                f"- Validation: `{(item.get('validation') or {}).get('status', 'unknown')}`",
                f"- Confidence: `{item.get('confidence', 0.0)}`",
                f"- Location: `{location.get('path', 'unknown')}{line_text}`",
                f"- Secret: `{secret.get('redacted', '')}`",
                f"- Commit: {commit_text}",
                f"- Status: `{item.get('status', 'needs_review')}`",
                f"- Note: {item.get('reasoning', '')}",
                "",
            ]
        )

    if len(sorted_findings) > args.max_items:
        lines.append(f"_Truncated: {len(sorted_findings) - args.max_items} additional findings omitted._")
        lines.append("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
