#!/usr/bin/env python3
"""Create a Phase 3 semantic verifier depth plan from triaged hypotheses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_hypotheses(path: Path) -> dict[str, dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, dict):
        items = data.get("hypotheses", [])
    elif isinstance(data, list):
        items = data
    else:
        items = []
    return {str(item.get("id")): item for item in items if isinstance(item, dict) and item.get("id")}


def symbols(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    output: list[str] = []
    for item in value:
        if isinstance(item, str):
            output.append(item)
        elif isinstance(item, dict):
            text = item.get("name") or item.get("id") or item.get("location") or item.get("path")
            if text:
                output.append(str(text))
    return output


def query_kind(verifier: str, hypothesis: dict[str, Any]) -> str:
    htype = str(hypothesis.get("type") or "")
    if verifier == "codeql":
        if htype in {"sql_injection", "nosql_injection", "command_injection", "template_injection", "xss", "path_traversal", "ssrf"}:
            return "codeql_custom"
        return "codeql_standard_mapped"
    if htype in {"idor", "auth_bypass", "vertical_privilege", "tenant_isolation_bypass", "state_skip", "approval_bypass"}:
        return "joern_structural"
    if htype in {"sql_injection", "nosql_injection", "command_injection", "path_traversal", "ssrf", "unsafe_file_upload"}:
        return "joern_dataflow"
    return "joern_slice"


def task_for(verifier: str, hypothesis: dict[str, Any], work_root: str) -> dict[str, Any]:
    hid = str(hypothesis.get("id"))
    entrypoints = symbols(hypothesis.get("entrypoints"))
    sinks = symbols(hypothesis.get("sensitive_actions"))
    guards = symbols(hypothesis.get("expected_guards"))
    qkind = query_kind(verifier, hypothesis)
    suffix = "ql" if verifier == "codeql" else "sc"
    result_suffix = "sarif" if verifier == "codeql" else "json"
    return {
        "hypothesis_id": hid,
        "query_intent": hypothesis.get("suspected_gap") or hypothesis.get("title") or f"Depth-check {hid}",
        "query_kind": qkind,
        "source_symbols": entrypoints,
        "sink_symbols": sinks,
        "guard_symbols": guards,
        "expected_query_file": f"{work_root}/queries/{hid}.{suffix}",
        "expected_result_path": f"{work_root}/results/{hid}.{result_suffix}",
        "status": "planned",
    }


def breadth_coverage_for(verifier: str, work_root: str) -> dict[str, Any]:
    if verifier == "joern":
        return {
            "enabled": True,
            "mode": "full_cpg_first",
            "commands": [
                f"joern-parse <repo-root> --output {work_root}/cpg.bin",
                f"joern --script {work_root}/queries/breadth-inventory.sc --nocolors",
                "run Joern querydb/prebuilt rules when available for this Joern installation",
            ],
            "result_paths": [
                f"{work_root}/results/breadth-inventory.json",
                f"{work_root}/results/querydb.json",
            ],
            "fallback_policy": (
                "Use focused CPGs only if full CPG generation, loading, or narrow "
                "per-hypothesis queries fail or become impractical."
            ),
        }
    return {
        "enabled": True,
        "mode": "standard_packs_first",
        "commands": [
            "codeql database analyze <db> <standard-query-pack> --format=sarifv2.1.0 --output=<sarif>",
            "map standard-pack or custom-query results back to semantic_review_ids where applicable",
        ],
        "result_paths": [
            f"{work_root}/results/breadth-standard-packs.sarif",
            f"{work_root}/results/breadth-standard-packs.json",
        ],
        "fallback_policy": "If standard packs run but targeted hypothesis-depth queries do not, record semantic verifier depth as degraded.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--triage", required=True, type=Path)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    hypotheses = load_hypotheses(args.hypotheses)
    triage = load_json(args.triage)
    selection = load_json(args.selection)
    verifier = str(selection.get("chosen") or "")
    if verifier not in {"codeql", "joern"}:
        raise SystemExit(f"semantic verifier must be codeql or joern, got: {verifier}")
    semantic_ids = [str(item) for item in triage.get("semantic_review_ids") or []]
    work_root = f".audit/tool-work/{verifier}"
    tasks = [task_for(verifier, hypotheses[hid], work_root) for hid in semantic_ids if hid in hypotheses]
    missing = [hid for hid in semantic_ids if hid not in hypotheses]
    payload = {
        "schema": "graph-reasoning-code-audit/semantic-verifier-depth-plan-v1",
        "selected_verifier": verifier,
        "breadth_coverage": breadth_coverage_for(verifier, work_root),
        "semantic_review_ids": semantic_ids,
        "tasks": tasks,
        "missing_hypotheses": missing,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
