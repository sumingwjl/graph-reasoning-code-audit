#!/usr/bin/env python3
"""Fuse hypotheses and tool outputs into evidence.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


RISK_BY_CLASS = {
    "ARCH": "high",
    "A": "high",
    "B": "medium",
    "C": "medium",
    "D": "high",
    "E": "medium",
    "F": "high",
    "G": "medium",
    "H": "medium",
}
RISK_VALUES = {"critical", "high", "medium", "low", "info"}


def risk_for(hypothesis: dict[str, Any]) -> tuple[str, str]:
    priority = str(hypothesis.get("priority") or "").lower()
    if priority in RISK_VALUES:
        return priority, "hypothesis.priority"
    severity = str(hypothesis.get("severity") or "").lower()
    if severity in RISK_VALUES:
        return severity, "hypothesis.severity"
    return RISK_BY_CLASS.get(str(hypothesis.get("class")), "medium"), "class_default"


def load_json(path: Path | None, default: Any) -> Any:
    if not path or not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    data = load_json(path, {"hypotheses": []})
    if isinstance(data, dict):
        return [item for item in data.get("hypotheses", []) if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def index_tool_results(payload: Any) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(payload, dict):
        return index
    items = payload.get("results")
    if items is None:
        items = payload.get("findings", [])
    for item in items or []:
        if not isinstance(item, dict):
            continue
        hid = item.get("hypothesis_id")
        if not hid:
            metadata = item.get("metadata") or {}
            hid = metadata.get("hypothesis_id")
        if hid:
            index.setdefault(str(hid), []).append(item)
    return index


def score(semgrep_hits: list[dict[str, Any]], joern_hits: list[dict[str, Any]], prior: str) -> float:
    value = {"high": 0.45, "medium": 0.3, "low": 0.2}.get(prior, 0.25)
    suspicious_semgrep = [
        item
        for item in semgrep_hits
        if (item.get("metadata") or {}).get("evidence_kind") not in {"guard_present", "sanitizer_present"}
    ]
    guard_evidence = [
        item
        for item in semgrep_hits
        if (item.get("metadata") or {}).get("evidence_kind") in {"guard_present", "sanitizer_present"}
    ]
    value += 0.25 if any(item.get("status") == "hit" for item in suspicious_semgrep) else 0
    value -= 0.1 if guard_evidence and not suspicious_semgrep else 0
    suspicious_joern = [
        item
        for item in joern_hits
        if (item.get("metadata") or item.get("details") or {}).get("evidence_kind")
        in {"missing_guard", "vuln_path", "taint_path", "route_param_sink", "mutation_sink"}
    ]
    value += 0.2 if any(item.get("status") == "hit" for item in suspicious_joern) else 0
    return round(min(value, 0.95), 2)


def status_for(confidence: float, semgrep_hits: list[dict[str, Any]], joern_hits: list[dict[str, Any]]) -> str:
    confirmed_kinds = {"missing_guard", "vuln_path", "confirmed_taint_path"}
    if any(
        item.get("status") in {"confirmed", "hit"}
        and (item.get("metadata") or item.get("details") or {}).get("evidence_kind") in confirmed_kinds
        for item in semgrep_hits + joern_hits
    ):
        return "confirmed"
    if confidence >= 0.5:
        return "needs_review"
    return "needs_review"


def locations(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    for group in groups:
        for item in group:
            if "locations" in item and isinstance(item["locations"], list):
                for loc in item["locations"]:
                    if not isinstance(loc, dict):
                        continue
                    path = str(loc.get("path") or "")
                    line = str(loc.get("line") or "")
                    key = (path, line)
                    if path and key not in seen:
                        seen.add(key)
                        output.append(loc)
            else:
                path = item.get("path")
                line = item.get("line")
                if path:
                    key = (str(path), str(line or ""))
                    if key not in seen:
                        seen.add(key)
                        output.append({"path": path, "line": line})
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--joern", type=Path)
    parser.add_argument("--codeql", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    hypotheses = load_hypotheses(args.hypotheses)
    semgrep_index = index_tool_results(load_json(args.semgrep, {}))
    joern_index = index_tool_results(load_json(args.joern, {}))
    codeql_index = index_tool_results(load_json(args.codeql, {}))

    findings = []
    for index, hypothesis in enumerate(hypotheses, 1):
        hid = str(hypothesis.get("id") or f"H-{index:03d}")
        semgrep_hits = semgrep_index.get(hid, [])
        joern_hits = joern_index.get(hid, [])
        codeql_hits = codeql_index.get(hid, [])
        confidence = score(semgrep_hits, joern_hits + codeql_hits, str(hypothesis.get("confidence_prior") or "medium"))
        risk, risk_source = risk_for(hypothesis)
        finding = {
            "id": f"F-{index:03d}",
            "hypothesis_ids": [hid],
            "class": hypothesis.get("class"),
            "type": hypothesis.get("type"),
            "title": hypothesis.get("title") or hypothesis.get("suspected_gap") or hid,
            "status": status_for(confidence, semgrep_hits, joern_hits + codeql_hits),
            "risk": risk,
            "risk_source": risk_source,
            "confidence": confidence,
            "locations": locations(semgrep_hits, joern_hits, codeql_hits),
            "call_paths": [
                path
                for item in joern_hits + codeql_hits
                for path in item.get("paths", [])
                if isinstance(path, list)
            ],
            "tool_evidence": {
                "semgrep": semgrep_hits,
                "joern": joern_hits,
                "codeql": codeql_hits,
            },
            "reasoning_summary": hypothesis.get("suspected_gap") or "",
            "fix_suggestion": "",
        }
        findings.append(finding)

    stats = {
        "hypotheses": len(hypotheses),
        "confirmed": sum(1 for item in findings if item["status"] == "confirmed"),
        "needs_review": sum(1 for item in findings if item["status"] == "needs_review"),
        "false_positive": sum(1 for item in findings if item["status"] == "false_positive"),
    }
    payload = {"findings": findings, "stats": stats}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
