#!/usr/bin/env python3
"""Apply guard coverage conclusions to evidence findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--guard-coverage", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    evidence = load_json(args.evidence)
    coverage = load_json(args.guard_coverage)
    coverage_by_hypothesis = {item["hypothesis_id"]: item for item in coverage.get("coverage", [])}

    for finding in evidence.get("findings", []):
        hypothesis_ids = finding.get("hypothesis_ids") or []
        matched = [coverage_by_hypothesis[hid] for hid in hypothesis_ids if hid in coverage_by_hypothesis]
        if not matched:
            continue
        if all(item.get("coverage") == "covered" for item in matched):
            finding["status"] = "false_positive"
            finding["risk"] = "info"
            finding["confidence"] = min(float(finding.get("confidence") or 0), 0.2)
            coverage_summary = "; ".join(f"{item['hypothesis_id']}: {item['reason']}" for item in matched)
            finding["reasoning_summary"] = (
                f"{finding.get('reasoning_summary', '')} Guard coverage assessment marks this hypothesis as covered. "
                f"{coverage_summary}"
            ).strip()
            finding["fix_suggestion"] = "No fix recommended from current evidence; keep regression tests around the documented guard chain."
            finding.setdefault("coverage", {})
            finding["coverage"]["status"] = "covered_by_guard"
            finding["coverage"]["hypotheses"] = [item["hypothesis_id"] for item in matched]

    findings = evidence.get("findings", [])
    evidence["stats"] = {
        "hypotheses": len(findings),
        "confirmed": sum(1 for item in findings if item.get("status") == "confirmed"),
        "needs_review": sum(1 for item in findings if item.get("status") == "needs_review"),
        "false_positive": sum(1 for item in findings if item.get("status") == "false_positive"),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
