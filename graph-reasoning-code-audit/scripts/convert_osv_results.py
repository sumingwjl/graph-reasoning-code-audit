#!/usr/bin/env python3
"""Convert OSV-Scanner JSON output into dependency_findings.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def normalize_path(path: str, repo_root: Path | None) -> str:
    text = path.replace("\\", "/")
    if repo_root:
        root = str(repo_root.resolve()).replace("\\", "/")
        if text.startswith(root + "/"):
            return text[len(root) + 1 :]
    return text


def affected_ranges(vulnerability: dict[str, Any]) -> tuple[str, list[str]]:
    ranges: list[str] = []
    fixed: list[str] = []
    for affected in vulnerability.get("affected", []):
        for range_item in affected.get("ranges", []):
            events = []
            for event in range_item.get("events", []):
                if "introduced" in event:
                    events.append(f">={event['introduced']}")
                if "fixed" in event:
                    fixed.append(str(event["fixed"]))
                    events.append(f"<{event['fixed']}")
                if "last_affected" in event:
                    events.append(f"<= {event['last_affected']}")
            if events:
                ranges.append(" ".join(events))
    return "; ".join(ranges), sorted(set(fixed))


def severity_of(package_item: dict[str, Any], vulnerability: dict[str, Any]) -> str:
    raw = ((vulnerability.get("database_specific") or {}).get("severity") or "").upper()
    if raw in SEVERITY_MAP:
        return SEVERITY_MAP[raw]
    groups = package_item.get("groups") or []
    for group in groups:
        max_severity = group.get("max_severity")
        if isinstance(max_severity, str):
            try:
                score = float(max_severity)
            except ValueError:
                continue
            if score >= 9:
                return "critical"
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            return "low"
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osv-results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--max-details-chars", type=int, default=900)
    args = parser.parse_args()

    payload = load_json(args.osv_results)
    repo_root = args.repo_root.resolve() if args.repo_root else None
    findings: list[dict[str, Any]] = []
    counter = 1

    for result in payload.get("results", []):
        source = result.get("source") or {}
        source_path = normalize_path(str(source.get("path") or ""), repo_root)
        for package_item in result.get("packages", []):
            package = package_item.get("package") or {}
            package_name = package.get("name")
            version = package.get("version")
            ecosystem = package.get("ecosystem") or "unknown"
            for vulnerability in package_item.get("vulnerabilities", []):
                affected, fixed_versions = affected_ranges(vulnerability)
                aliases = vulnerability.get("aliases") or []
                advisory_id = vulnerability.get("id") or (aliases[0] if aliases else "unknown")
                severity = severity_of(package_item, vulnerability)
                details = str(vulnerability.get("details") or "")
                references = vulnerability.get("references") or []
                finding = {
                    "id": f"D-{counter:03d}",
                    "class": "SCA",
                    "type": "known_vulnerable_dependency",
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "advisory": {
                        "id": advisory_id,
                        "aliases": aliases,
                        "source": "osv",
                        "severity": severity,
                        "affected_range": affected,
                        "fixed_versions": fixed_versions,
                        "references": references[:8],
                    },
                    "trigger_conditions": [
                        "Version is present in lockfile and matches an OSV advisory.",
                        "Project-specific exploitability requires checking vulnerable API/config/feature usage.",
                    ],
                    "usage_evidence": [],
                    "config_evidence": [
                        {
                            "path": source_path,
                            "line": None,
                            "note": f"OSV-Scanner found {package_name}@{version} in {source.get('type', 'source')}",
                        }
                    ],
                    "status": "needs_review",
                    "confidence": 0.4,
                    "reasoning": details[: args.max_details_chars],
                    "fix_suggestion": (
                        f"Upgrade {package_name} to a non-affected version"
                        + (f" such as {', '.join(fixed_versions[:3])}" if fixed_versions else "")
                        + "; verify advisory trigger conditions before prioritizing as exploitable."
                    ),
                }
                findings.append(finding)
                counter += 1

    output = {
        "schema": "graph-reasoning-code-audit/dependency-findings-v1",
        "source": {
            "tool": "osv-scanner",
            "input": str(args.osv_results),
        },
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "confirmed": 0,
            "needs_review": len(findings),
            "false_positive": 0,
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
