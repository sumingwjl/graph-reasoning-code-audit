#!/usr/bin/env python3
"""Render dependency_findings.json as a concise SCA Markdown report."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def severity_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}.get(value.lower(), 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependency-findings", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-items", type=int, default=80)
    args = parser.parse_args()

    payload = load_json(args.dependency_findings)
    findings = payload.get("findings", [])
    counts = Counter((item.get("advisory") or {}).get("severity") or "unknown" for item in findings)
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            -severity_rank((item.get("advisory") or {}).get("severity") or "unknown"),
            str(item.get("package") or ""),
            str((item.get("advisory") or {}).get("id") or ""),
        ),
    )

    lines = [
        "# SCA Report",
        "",
        "## Summary",
        "",
        f"- Findings: {len(findings)}",
        f"- Critical: {counts.get('critical', 0)}",
        f"- High: {counts.get('high', 0)}",
        f"- Medium: {counts.get('medium', 0)}",
        f"- Low: {counts.get('low', 0)}",
        f"- Unknown: {counts.get('unknown', 0)}",
        "",
        "Version matches are SCA signals. Treat exploitability as a follow-up question unless a finding is explicitly deep-dived.",
        "",
        "## Findings",
        "",
    ]

    for item in sorted_findings[: args.max_items]:
        advisory = item.get("advisory") or {}
        aliases = advisory.get("aliases") or []
        alias_text = f" ({', '.join(aliases[:3])})" if aliases else ""
        fixed = advisory.get("fixed_versions") or []
        fixed_text = ", ".join(fixed[:5]) if fixed else "unknown"
        evidence = (item.get("config_evidence") or item.get("usage_evidence") or [{}])[0]
        lines.extend(
            [
                f"### {item.get('id')} - {item.get('package')}@{item.get('version')}",
                "",
                f"- Severity: `{advisory.get('severity', 'unknown')}`",
                f"- Advisory: `{advisory.get('id', 'unknown')}`{alias_text}",
                f"- Ecosystem: `{item.get('ecosystem', 'unknown')}`",
                f"- Affected range: `{advisory.get('affected_range') or 'unknown'}`",
                f"- Fixed versions: `{fixed_text}`",
                f"- Evidence: `{evidence.get('path', 'unknown')}` {evidence.get('note', '')}".rstrip(),
                f"- Status: `{item.get('status', 'needs_review')}`",
                f"- Fix: {item.get('fix_suggestion', 'Upgrade or apply documented mitigation.')}",
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
