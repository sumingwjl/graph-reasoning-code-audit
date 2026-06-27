#!/usr/bin/env python3
"""Small state machine for running graph-reasoning-code-audit in phases.

This helper keeps long audit runs out of chat memory. It writes a durable
state file and one focused task file for the next AI CLI session to execute.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "graph-reasoning-code-audit/flow-state-v1"
STATE_FILE = "audit_state.json"

TOOL_SPECS = {
    "python": {
        "command": [sys.executable, "--version"],
        "required": True,
        "purpose": "Run audit helper scripts.",
    },
    "graphify": {
        "command": ["graphify", "--help"],
        "required": False,
        "purpose": "Optional CLI fallback when the official graphify skill/slash command is unavailable.",
    },
    "osv-scanner": {
        "command": ["osv-scanner", "--version"],
        "required": False,
        "purpose": "Collect dependency vulnerability context.",
    },
    "betterleaks": {
        "command": ["betterleaks", "--help"],
        "required": False,
        "purpose": "Scan committed and working-tree hardcoded secrets.",
    },
    "semgrep": {
        "command": ["semgrep", "--version"],
        "required": False,
        "purpose": "Run generated evidence rules.",
    },
    "joern-parse": {
        "command": ["joern-parse", "--help"],
        "required": False,
        "purpose": "Create Joern CPGs for source verification.",
    },
    "joern": {
        "command": ["joern", "--help"],
        "required": False,
        "purpose": "Run Joern CLI queries.",
    },
    "codeql": {
        "command": ["codeql", "version"],
        "required": False,
        "purpose": "Optional semantic/data-flow verification.",
    },
}

SOURCE_VALIDATION_BATCH_THRESHOLD = 5
SOURCE_VALIDATION_DEFAULT_BATCH_SIZE = 3
SOURCE_VALIDATION_MAX_BATCH_SIZE = 3
SOURCE_VALIDATION_PARTS_DIR = "source-validation-parts"
SOURCE_VALIDATION_WORK_DIR = "source-validation-work"
TOOL_WORK_DIR = "tool-work"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def python_cmd() -> str:
    return '"' + sys.executable.replace("\\", "/") + '"'


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ensure_dirs(audit_dir: Path) -> None:
    for name in ("tasks", "summaries", "skips", SOURCE_VALIDATION_PARTS_DIR, SOURCE_VALIDATION_WORK_DIR, TOOL_WORK_DIR):
        (audit_dir / name).mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    messages: list[str]


@dataclass(frozen=True)
class Phase:
    id: str
    title: str
    kind: str
    dispatch: str
    required_outputs: tuple[str, ...]
    check: Callable[[Path], CheckResult]
    summary_hint: str


def ok(messages: list[str] | None = None) -> CheckResult:
    return CheckResult(True, messages or [])


def fail(messages: list[str]) -> CheckResult:
    return CheckResult(False, messages)


def file_exists(audit_dir: Path, rel: str) -> bool:
    return (audit_dir / rel).exists()


def json_exists(audit_dir: Path, rel: str, messages: list[str]) -> bool:
    path = audit_dir / rel
    if not path.exists():
        messages.append(f"missing {rel}")
        return False
    try:
        load_json(path)
    except Exception as exc:  # noqa: BLE001 - validation should report any parse issue.
        messages.append(f"{rel} is not valid JSON: {exc}")
        return False
    return True


def skip_exists(audit_dir: Path, name: str) -> bool:
    return (audit_dir / "skips" / f"{name}.json").exists()


def tool_cache_path(audit_dir: Path) -> Path:
    return audit_dir / "tool_status.json"


def approval_path(audit_dir: Path) -> Path:
    return audit_dir / "preflight_approval.json"


def graphify_mode_path(audit_dir: Path) -> Path:
    return audit_dir / "graphify_mode.json"


def semantic_verifier_path(audit_dir: Path) -> Path:
    return audit_dir / "semantic_verifier_selection.json"


def semgrep_triage_path(audit_dir: Path) -> Path:
    return audit_dir / "semgrep_triage.json"


def semantic_depth_plan_path(audit_dir: Path) -> Path:
    return audit_dir / "semantic_verifier_depth_plan.json"


def semantic_depth_results_path(audit_dir: Path) -> Path:
    return audit_dir / "semantic_verifier_depth_results.json"


def semantic_depth_approval_path(audit_dir: Path) -> Path:
    return audit_dir / "semantic_verifier_depth_approval.json"


def source_validation_dispatch_path(audit_dir: Path) -> Path:
    return audit_dir / "source_validation_dispatch.json"


def verification_checkpoint_path(audit_dir: Path) -> Path:
    return audit_dir / "verification_checkpoint.json"


CODEQL_LANGUAGE_SUFFIXES = {
    "csharp": {".cs"},
    "javascript-typescript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "python": {".py"},
    "go": {".go"},
    "java-kotlin": {".java", ".kt", ".kts"},
    "ruby": {".rb"},
    "c-cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"},
    "swift": {".swift"},
}
CODEQL_SUFFIXES = {suffix for suffixes in CODEQL_LANGUAGE_SUFFIXES.values() for suffix in suffixes}
JOERN_SUFFIXES = {
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".hxx",
    ".cs",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
}


def detect_repo_suffixes(repo: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    ignored = {".git", ".audit", "node_modules", "dist", "build", "venv", ".venv", "__pycache__"}
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if any(part in ignored for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if not suffix:
            continue
        counts[suffix] = counts.get(suffix, 0) + 1
    return counts


def matching_languages(suffixes: dict[str, int], language_suffixes: dict[str, set[str]]) -> dict[str, int]:
    matches: dict[str, int] = {}
    for language, known_suffixes in language_suffixes.items():
        count = sum(suffixes.get(suffix, 0) for suffix in known_suffixes)
        if count:
            matches[language] = count
    return matches


def select_semantic_verifier(repo: Path, tool_status: dict[str, Any], requested: str = "auto") -> dict[str, Any]:
    tools = tool_status.get("tools", {})
    codeql_available = tools.get("codeql", {}).get("status") == "available"
    joern_available = tools.get("joern", {}).get("status") == "available" and tools.get("joern-parse", {}).get("status") == "available"
    suffixes = detect_repo_suffixes(repo)
    codeql_languages = matching_languages(suffixes, CODEQL_LANGUAGE_SUFFIXES)
    codeql_supported = sum(codeql_languages.values())
    joern_supported = sum(count for suffix, count in suffixes.items() if suffix in JOERN_SUFFIXES)
    limitations: list[str] = []
    confidence = "medium"
    if not codeql_available:
        limitations.append("CodeQL is unavailable in the preflight tool status.")
    if not joern_available:
        limitations.append("Joern is unavailable unless both joern and joern-parse are available.")
    if codeql_available and codeql_supported == 0:
        limitations.append("CodeQL is available but no strong CodeQL-supported suffixes were detected.")
    if joern_available and joern_supported == 0:
        limitations.append("Joern is available but no strong Joern-supported suffixes were detected.")

    if requested != "auto":
        chosen = requested
        confidence = "medium"
        reason = f"User or operator explicitly selected {requested}."
        if requested == "codeql" and not codeql_available:
            limitations.append("Explicitly selected CodeQL, but CodeQL is unavailable in preflight.")
            confidence = "low"
        if requested == "joern" and not joern_available:
            limitations.append("Explicitly selected Joern, but joern and joern-parse are not both available in preflight.")
            confidence = "low"
        if requested == "unavailable":
            confidence = "low"
            reason = "User or operator explicitly marked semantic verification unavailable."
    elif codeql_available and codeql_supported > 0 and (not joern_available or codeql_supported >= joern_supported):
        chosen = "codeql"
        confidence = "high" if codeql_supported >= 10 else "medium"
        reason = "CodeQL is available and the repository contains languages with mature extractor/query-pack support."
    elif joern_available and joern_supported > 0:
        chosen = "joern"
        confidence = "high" if joern_supported >= 10 else "medium"
        reason = "Joern is available and currently has the better detected source-language coverage for this repository."
    elif joern_available:
        chosen = "joern"
        reason = "Joern is available; CodeQL support is unavailable or not detected from repository suffixes."
    elif codeql_available:
        chosen = "codeql"
        reason = "CodeQL is available; Joern is unavailable or not detected from repository suffixes."
    else:
        chosen = "unavailable"
        confidence = "low"
        reason = "Neither primary semantic verifier is fully available; use the best fallback and record the gap."
    return {
        "schema": "graph-reasoning-code-audit/semantic-verifier-selection-v1",
        "created_at": utc_now(),
        "repo_root": str(repo.resolve()),
        "repo_suffixes": dict(sorted(suffixes.items(), key=lambda item: item[0])),
        "codeql_detected_languages": codeql_languages,
        "joern_supported_file_count": joern_supported,
        "chosen": chosen,
        "confidence": confidence,
        "reason": reason,
        "limitations": limitations,
        "available": {
            "codeql": codeql_available,
            "joern": joern_available,
        },
        "selection_mode": requested,
        "unselected": [name for name in ("joern", "codeql") if name != chosen],
        "policy": "Run Semgrep first, write semgrep_triage.json, then run exactly one primary semantic verifier for triaged targets by default.",
    }


def detect_tool(tool: str, spec: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "tool": tool,
        "required": bool(spec.get("required")),
        "purpose": spec.get("purpose", ""),
        "status": "missing",
        "command": spec.get("command", []),
        "details": "",
    }
    if not spec.get("command"):
        return entry
    executable = shutil.which(str(spec["command"][0]))
    if not executable:
        entry["details"] = "not in PATH"
        return entry
    entry["path"] = executable
    try:
        completed = subprocess.run(
            list(spec["command"]),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - report any execution failure explicitly.
        entry["status"] = "error"
        entry["details"] = str(exc)
        return entry

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    output = stdout or stderr
    if completed.returncode == 0:
        entry["status"] = "available"
        entry["details"] = output.splitlines()[0] if output else "available"
    else:
        entry["status"] = "error"
        entry["details"] = output.splitlines()[0] if output else f"exit {completed.returncode}"
    return entry


def preflight_tools() -> dict[str, Any]:
    tools = {name: detect_tool(name, spec) for name, spec in TOOL_SPECS.items()}
    required_missing = [name for name, item in tools.items() if item["required"] and item["status"] != "available"]
    optional_missing = [name for name, item in tools.items() if not item["required"] and item["status"] != "available"]
    return {
        "schema": "graph-reasoning-code-audit/tool-status-v1",
        "created_at": utc_now(),
        "tools": tools,
        "summary": {
            "required_total": sum(1 for item in TOOL_SPECS.values() if item["required"]),
            "required_available": sum(1 for item in tools.values() if item["required"] and item["status"] == "available"),
            "optional_total": sum(1 for item in TOOL_SPECS.values() if not item["required"]),
            "optional_available": sum(1 for item in tools.values() if not item["required"] and item["status"] == "available"),
            "required_missing": required_missing,
            "optional_missing": optional_missing,
        },
    }


def md_cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def write_preflight_report(repo: Path, tool_status: dict[str, Any]) -> Path:
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    summary = tool_status.get("summary", {})
    lines = [
        "# Phase 0A Summary: Tool Preflight",
        "",
        f"- Required tools available: {summary.get('required_available', 0)}/{summary.get('required_total', 0)}",
        f"- Optional tools available: {summary.get('optional_available', 0)}/{summary.get('optional_total', 0)}",
        "",
        "## Tools",
        "",
        "Graphify CLI is optional when the installed official graphify skill or slash command is available.",
        "Recommended Graphify mode for code audit: AST/code graph. Deep mode is optional for security-relevant docs, diagrams, OpenAPI specs, threat models, or deployment notes.",
        "Ask the user which Graphify mode to use before approving Phase 0A, then record it with approve-preflight.",
        "",
        "| Tool | Required | Status | Details | Purpose |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, item in tool_status["tools"].items():
        lines.append(
            f"| `{name}` | {'yes' if item['required'] else 'no'} | {item['status']} | "
            f"{md_cell(item.get('details'))} | {md_cell(item.get('purpose'))} |"
        )
    if summary.get("required_missing"):
        lines.extend(["", "## Required Missing", ""])
        for name in summary["required_missing"]:
            lines.append(f"- `{name}`")
    if summary.get("optional_missing"):
        lines.extend(["", "## Optional Missing", ""])
        for name in summary["optional_missing"]:
            lines.append(f"- `{name}`")
    path = audit_dir / "summaries" / "phase-0a-tool-preflight.md"
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def check_phase0(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    if not json_exists(audit_dir, "tool_status.json", messages):
        return fail(messages)
    data = load_json(audit_dir / "tool_status.json")
    required_missing = (data.get("summary") or {}).get("required_missing") or []
    if required_missing:
        messages.append("required tools missing: " + ", ".join(required_missing))
    if not approval_path(audit_dir).exists():
        messages.append("missing preflight_approval.json; report tool status and Graphify mode choices to the user, then run approve-preflight after approval")
    else:
        try:
            approval = load_json(approval_path(audit_dir))
            if approval.get("status") != "approved":
                messages.append("preflight approval status is not approved")
            if approval.get("graphify_mode") not in {"ast", "deep", "existing"}:
                messages.append("preflight_approval.json missing graphify_mode: ast|deep|existing")
        except Exception as exc:  # noqa: BLE001
            messages.append(f"preflight_approval.json is not valid JSON: {exc}")
    return CheckResult(not messages, messages)


def check_graph_context(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    if not json_exists(audit_dir, "graph_context.json", messages):
        return fail(messages)
    data = load_json(audit_dir / "graph_context.json")
    warnings = data.get("graphify_input_warnings") or []
    quality = data.get("graphify_quality") or {}
    code_quality = data.get("graphify_code_quality") or {}
    if warnings:
        messages.append("graph_context.json has graphify_input_warnings; clean graphify input before continuing")
    has_code_graph = bool(code_quality.get("has_code_graph") or quality.get("has_code_graph"))
    has_code_edges = bool(code_quality.get("has_code_edges") or quality.get("has_code_edges"))
    has_structural_edges = bool(code_quality.get("has_structural_code_edges") or quality.get("has_structural_code_edges"))
    if not has_code_graph:
        messages.append("graph_context.json has no code graph nodes; rerun graphify on the source tree or narrow the audit scope")
    if has_code_graph and not has_code_edges:
        messages.append("graph_context.json has code nodes but no code edges; rerun graphify or inspect graphify output before Phase 2")
    if has_code_edges and not has_structural_edges:
        messages.append("graph_context.json has code edges but no obvious import/call/reference structure; inspect graphify output before Phase 2")
    return CheckResult(not messages, messages)


def check_phase1(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    json_exists(audit_dir, "dependency_context.json", messages)
    if not file_exists(audit_dir, "dependency_findings.json") and not skip_exists(audit_dir, "sca"):
        messages.append("missing dependency_findings.json or skips/sca.json")
    elif file_exists(audit_dir, "dependency_findings.json"):
        json_exists(audit_dir, "dependency_findings.json", messages)
    if not file_exists(audit_dir, "secret_findings.json") and not skip_exists(audit_dir, "secret_scan"):
        messages.append("missing secret_findings.json or skips/secret_scan.json")
    elif file_exists(audit_dir, "secret_findings.json"):
        json_exists(audit_dir, "secret_findings.json", messages)
    return CheckResult(not messages, messages)


def check_semantic_model(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    if json_exists(audit_dir, "semantic_model.json", messages):
        data = load_json(audit_dir / "semantic_model.json")
        for key in ("roles", "resources", "guards", "entrypoints", "sensitive_actions", "uncertainties"):
            if key not in data:
                messages.append(f"semantic_model.json missing key: {key}")
    return CheckResult(not messages, messages)


def check_hypotheses(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    backlog_ok = json_exists(audit_dir, "hypothesis_backlog.json", messages)
    shortlist_ok = json_exists(audit_dir, "hypotheses.json", messages)
    if backlog_ok:
        backlog = load_json(audit_dir / "hypothesis_backlog.json")
        for item in backlog.get("hypotheses", []):
            if item.get("validation_status") == "confirmed":
                messages.append(f"backlog item {item.get('id')} is confirmed before source validation")
            if item.get("backlog_status") not in {"candidate", "selected", "deferred", "rejected", "merged", "validated"}:
                messages.append(f"backlog item {item.get('id')} has unexpected backlog_status")
    if shortlist_ok:
        shortlist = load_json(audit_dir / "hypotheses.json")
        hypotheses = shortlist.get("hypotheses", [])
        if not hypotheses:
            messages.append("hypotheses.json has no hypotheses")
        for item in hypotheses:
            if not item.get("backlog_ids"):
                messages.append(f"hypothesis {item.get('id')} missing backlog_ids")
    return CheckResult(not messages, messages)


def check_verification_checkpoint(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    if not json_exists(audit_dir, "verification_checkpoint.json", messages):
        messages.append(
            "report Phase 0-2 progress to the user, ask whether to use parallel subagents for Phase 3 tool verification and Phase 4 source validation, then run the current Python interpreter with -m orchestrator.audit_flow approve-verification --repo <repo> --tool-mode <parallel|sequential> --source-mode <parallel|sequential> --by \"user\" --progress-summary \"...\" --next-steps \"...\""
        )
        return fail(messages)
    data = load_json(verification_checkpoint_path(audit_dir))
    if data.get("status") != "approved":
        messages.append("verification_checkpoint.json status must be approved")
    tool_mode = data.get("tool_verification_mode", data.get("verification_mode"))
    if tool_mode not in {"parallel", "sequential"}:
        messages.append("verification_checkpoint.json tool_verification_mode must be parallel or sequential")
    source_mode = data.get("source_validation_mode")
    if source_mode not in {"parallel", "sequential"}:
        messages.append("verification_checkpoint.json source_validation_mode must be parallel or sequential")
    if not data.get("reported_to_user"):
        messages.append("verification_checkpoint.json must set reported_to_user=true")
    if not data.get("user_choice_recorded"):
        messages.append("verification_checkpoint.json must set user_choice_recorded=true")
    if not data.get("progress_summary"):
        messages.append("verification_checkpoint.json missing progress_summary")
    if not data.get("next_steps"):
        messages.append("verification_checkpoint.json missing next_steps")
    return CheckResult(not messages, messages)


def check_evidence(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    checkpoint = check_verification_checkpoint(audit_dir)
    if not checkpoint.ok:
        messages.extend("verification checkpoint incomplete: " + message for message in checkpoint.messages)
    semantic_review_ids: list[str] = []
    if json_exists(audit_dir, "semgrep_triage.json", messages):
        triage = load_json(semgrep_triage_path(audit_dir))
        if triage.get("schema") != "graph-reasoning-code-audit/semgrep-triage-v1":
            messages.append("semgrep_triage.json has unexpected schema")
        if not isinstance(triage.get("items"), list):
            messages.append("semgrep_triage.json must contain an items array")
        if "semantic_review_ids" not in triage:
            messages.append("semgrep_triage.json missing semantic_review_ids")
        else:
            semantic_review_ids = [str(item) for item in triage.get("semantic_review_ids") or []]
    if json_exists(audit_dir, "semantic_verifier_selection.json", messages):
        selection = load_json(semantic_verifier_path(audit_dir))
        chosen = str(selection.get("chosen") or "")
        if chosen in {"joern", "codeql"} and semantic_review_ids:
            check_semantic_depth(audit_dir, chosen, semantic_review_ids, messages)
    json_exists(audit_dir, "evidence.json", messages)
    if file_exists(audit_dir, "evidence-final.json"):
        json_exists(audit_dir, "evidence-final.json", messages)
    return CheckResult(not messages, messages)


def check_semantic_depth(audit_dir: Path, chosen: str, semantic_review_ids: list[str], messages: list[str]) -> None:
    degraded_path = audit_dir / "skips" / "semantic_verifier_depth.json"
    degraded_uncovered: set[str] = set()
    if degraded_path.exists():
        try:
            degraded = load_json(degraded_path)
        except Exception as exc:  # noqa: BLE001 - report malformed degradation records.
            messages.append(f"skips/semantic_verifier_depth.json is not valid JSON: {exc}")
            return
        if degraded.get("status") not in {"degraded", "skipped"}:
            messages.append("skips/semantic_verifier_depth.json status must be degraded or skipped")
        if not degraded.get("reason"):
            messages.append("skips/semantic_verifier_depth.json missing reason")
        degraded_uncovered = {str(item) for item in degraded.get("uncovered") or []}
        approval_path = semantic_depth_approval_path(audit_dir)
        if not approval_path.exists():
            messages.append(
                "semantic verifier depth is degraded; stop now, report the verifier, uncovered ids, and choices to the user, then run approve-semantic-depth-degradation before evidence fusion"
            )
        else:
            try:
                approval = load_json(approval_path)
                if approval.get("status") != "approved":
                    messages.append("semantic_verifier_depth_approval.json status must be approved")
                if approval.get("decision") not in {"continue", "retry", "switch", "narrow"}:
                    messages.append("semantic_verifier_depth_approval.json decision must be continue, retry, switch, or narrow")
                elif approval.get("decision") != "continue":
                    messages.append(
                        "semantic_verifier_depth_approval.json decision is not continue; complete the approved retry/switch/narrow action before evidence fusion"
                    )
                if not approval.get("reported_to_user"):
                    messages.append("semantic_verifier_depth_approval.json must set reported_to_user=true")
            except Exception as exc:  # noqa: BLE001 - report malformed approval records.
                messages.append(f"semantic_verifier_depth_approval.json is not valid JSON: {exc}")

    required = set(semantic_review_ids) - degraded_uncovered

    plan_path = semantic_depth_plan_path(audit_dir)
    results_path = semantic_depth_results_path(audit_dir)
    if not plan_path.exists():
        if not required:
            return
        messages.append(
            "missing semantic_verifier_depth_plan.json; selected CodeQL/Joern must plan one task per semantic_review_id, or write skips/semantic_verifier_depth.json with uncovered ids if targeted depth is not feasible"
        )
        return
    try:
        plan = load_json(plan_path)
    except Exception as exc:  # noqa: BLE001 - validation should report any parse issue.
        messages.append(f"semantic_verifier_depth_plan.json is not valid JSON: {exc}")
        return
    if not results_path.exists():
        messages.append(
            "missing semantic_verifier_depth_results.json; standard CodeQL packs or Joern querydb breadth results do not satisfy hypothesis-depth validation. Write depth results for covered ids and skips/semantic_verifier_depth.json for uncovered ids."
        )
        return
    try:
        results = load_json(results_path)
    except Exception as exc:  # noqa: BLE001 - validation should report any parse issue.
        messages.append(f"semantic_verifier_depth_results.json is not valid JSON: {exc}")
        return
    if plan.get("schema") != "graph-reasoning-code-audit/semantic-verifier-depth-plan-v1":
        messages.append("semantic_verifier_depth_plan.json has unexpected schema")
    if results.get("schema") != "graph-reasoning-code-audit/semantic-verifier-depth-results-v1":
        messages.append("semantic_verifier_depth_results.json has unexpected schema")
    if plan.get("selected_verifier") != chosen:
        messages.append(f"semantic_verifier_depth_plan.json selected_verifier must be {chosen}")
    if results.get("selected_verifier") != chosen:
        messages.append(f"semantic_verifier_depth_results.json selected_verifier must be {chosen}")
    breadth_plan = plan.get("breadth_coverage") or {}
    if breadth_plan.get("enabled") is not True:
        messages.append(
            "semantic_verifier_depth_plan.json must enable breadth_coverage for the selected verifier. Breadth coverage is separate from hypothesis-depth validation; if it cannot run, record the limitation in results or skips."
        )
    if not breadth_plan.get("commands"):
        messages.append("semantic_verifier_depth_plan.json breadth_coverage.commands must list the planned standard/querydb or inventory commands")
    breadth_results = results.get("breadth_coverage") or {}
    if breadth_results.get("status") not in {"completed", "degraded", "skipped"}:
        messages.append(
            "semantic_verifier_depth_results.json must include breadth_coverage.status as completed, degraded, or skipped so broad CodeQL/Joern coverage is not silently omitted"
        )

    planned_ids = {str(item.get("hypothesis_id")) for item in plan.get("tasks", []) if isinstance(item, dict) and item.get("hypothesis_id")}
    result_items = [item for item in results.get("results", []) if isinstance(item, dict)]
    result_ids = {str(item.get("hypothesis_id")) for item in result_items if item.get("hypothesis_id")}
    if degraded_uncovered and results.get("coverage_status") == "depth_complete":
        messages.append(
            "semantic depth state is contradictory: skips/semantic_verifier_depth.json exists while semantic_verifier_depth_results.json reports depth_complete. Use coverage_status=partial when any id is uncovered/degraded."
        )
    overlap = sorted(degraded_uncovered & result_ids)
    if overlap:
        messages.append(
            "semantic depth state is contradictory: ids appear in both degraded skip and depth results: "
            + ", ".join(overlap)
            + ". Put covered ids only in semantic_verifier_depth_results.json; put uncovered ids only in skips/semantic_verifier_depth.json."
        )
    missing_plan = sorted(required - planned_ids)
    missing_results = sorted(required - result_ids)
    if missing_plan:
        messages.append(
            "semantic depth plan misses semantic_review_ids: "
            + ", ".join(missing_plan)
            + ". Add one task per id to semantic_verifier_depth_plan.json, or mark those ids uncovered in skips/semantic_verifier_depth.json."
        )
    if missing_results:
        messages.append(
            "semantic depth results miss semantic_review_ids: "
            + ", ".join(missing_results)
            + ". Add one result per covered id, or mark uncovered ids in skips/semantic_verifier_depth.json and request user approval."
        )
    for item in result_items:
        hid = str(item.get("hypothesis_id") or "")
        if hid not in required:
            continue
        status = item.get("status")
        if status not in {"hit", "miss", "error", "skipped"}:
            messages.append(f"semantic depth result {hid} status must be hit, miss, error, or skipped")
        if item.get("coverage_mode") != "depth":
            messages.append(f"semantic depth result {hid} must set coverage_mode=depth")
        if not item.get("query_intent"):
            messages.append(f"semantic depth result {hid} missing query_intent")
        if status in {"error", "skipped"} and not item.get("limitations"):
            messages.append(f"semantic depth result {hid} with status {status} must include limitations")
    if results.get("coverage_status") == "breadth_only":
        messages.append(
            "semantic_verifier_depth_results.json reports breadth_only; write skips/semantic_verifier_depth.json with every uncovered semantic_review_id, report the degradation to the user, and record approve-semantic-depth-degradation before continuing"
        )


def check_source_packet(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    json_exists(audit_dir, "source_validation_packet.json", messages)
    if not file_exists(audit_dir, "source_validation_prompt.md"):
        messages.append("missing source_validation_prompt.md")
    return CheckResult(not messages, messages)


def load_hypothesis_ids(audit_dir: Path, messages: list[str]) -> list[str]:
    path = audit_dir / "hypotheses.json"
    if not path.exists():
        messages.append("missing hypotheses.json")
        return []
    try:
        data = load_json(path)
    except Exception as exc:  # noqa: BLE001
        messages.append(f"hypotheses.json is not valid JSON: {exc}")
        return []
    hypotheses = data.get("hypotheses") or []
    ids: list[str] = []
    for index, item in enumerate(hypotheses, start=1):
        hypothesis_id = str(item.get("id") or f"H-{index:03d}")
        if hypothesis_id in ids:
            messages.append(f"duplicate hypothesis id in hypotheses.json: {hypothesis_id}")
        ids.append(hypothesis_id)
    return ids


def plan_source_validation(repo: Path, batch_size: int) -> dict[str, Any]:
    audit_dir = repo / ".audit"
    messages: list[str] = []
    ids = load_hypothesis_ids(audit_dir, messages)
    if messages:
        raise SystemExit("; ".join(messages))
    if not ids:
        raise SystemExit("hypotheses.json has no hypotheses to dispatch.")
    if batch_size < 1 or batch_size > SOURCE_VALIDATION_MAX_BATCH_SIZE:
        raise SystemExit(
            f"source validation batch size must be 1-{SOURCE_VALIDATION_MAX_BATCH_SIZE}; use one to three hypotheses per worker"
        )
    batches = []
    for offset in range(0, len(ids), batch_size):
        batch_ids = ids[offset : offset + batch_size]
        batch_number = len(batches) + 1
        batches.append(
            {
                "batch_id": f"batch-{batch_number:03d}",
                "hypothesis_ids": batch_ids,
                "worker_output": f".audit/{SOURCE_VALIDATION_PARTS_DIR}/batch-{batch_number:03d}.md",
                "worker_work_dir": f".audit/{SOURCE_VALIDATION_WORK_DIR}/batch-{batch_number:03d}/",
                "status": "pending",
            }
        )
    return {
        "schema": "graph-reasoning-code-audit/source-validation-dispatch-v1",
        "created_at": utc_now(),
        "repo_root": str(repo.resolve()),
        "hypothesis_count": len(ids),
        "batch_size": batch_size,
        "parallel_requested": True,
        "parallel_required": True,
        "write_policy": {
            "aggregate_owner": "main-agent",
            "aggregate_output": ".audit/source_validation.md",
            "worker_outputs_dir": f".audit/{SOURCE_VALIDATION_PARTS_DIR}/",
            "worker_work_dir_root": f".audit/{SOURCE_VALIDATION_WORK_DIR}/",
            "worker_may_write_aggregate": False,
        },
        "batches": batches,
    }


def validate_source_validation_dispatch(audit_dir: Path, expected_ids: list[str], messages: list[str]) -> None:
    if skip_exists(audit_dir, "source_validation_subagents"):
        try:
            skip = load_json(audit_dir / "skips" / "source_validation_subagents.json")
        except Exception as exc:  # noqa: BLE001
            messages.append(f"skips/source_validation_subagents.json is not valid JSON: {exc}")
            return
        if skip.get("status") == "skipped":
            return
        messages.append("skips/source_validation_subagents.json must have status skipped")
        return
    path = source_validation_dispatch_path(audit_dir)
    if not path.exists():
        messages.append(
            "missing source_validation_dispatch.json; run plan-source-validation and assign workers to part files before merging"
        )
        return
    try:
        data = load_json(path)
    except Exception as exc:  # noqa: BLE001
        messages.append(f"source_validation_dispatch.json is not valid JSON: {exc}")
        return
    if data.get("parallel_requested") is not True:
        messages.append("source_validation_dispatch.json must set parallel_requested=true when source_validation_mode=parallel")
    if data.get("parallel_required") is not True:
        messages.append(
            "source_validation_dispatch.json must set parallel_required=true when the user selected parallel source validation; use skips/source_validation_subagents.json before any main-agent fallback"
        )
    policy = data.get("write_policy") or {}
    if policy.get("aggregate_owner") != "main-agent":
        messages.append(
            "source_validation_dispatch.json must set write_policy.aggregate_owner to main-agent; expected write_policy: {\"aggregate_owner\":\"main-agent\",\"aggregate_output\":\".audit/source_validation.md\",\"worker_outputs_dir\":\".audit/source-validation-parts/\",\"worker_work_dir_root\":\".audit/source-validation-work/\",\"worker_may_write_aggregate\":false}"
        )
    if policy.get("worker_may_write_aggregate") is not False:
        messages.append(
            "source_validation_dispatch.json must set write_policy.worker_may_write_aggregate to false; workers write only .audit/source-validation-parts/<batch>.md"
        )
    if policy.get("worker_work_dir_root") != f".audit/{SOURCE_VALIDATION_WORK_DIR}/":
        messages.append(
            f"source_validation_dispatch.json must set write_policy.worker_work_dir_root to .audit/{SOURCE_VALIDATION_WORK_DIR}/"
        )
    batches = data.get("batches") or []
    if not batches:
        messages.append("source_validation_dispatch.json has no batches")
        return
    seen: list[str] = []
    for batch in batches:
        batch_id = str(batch.get("batch_id") or "")
        worker_output = str(batch.get("worker_output") or "")
        worker_work_dir = str(batch.get("worker_work_dir") or "")
        batch_ids = [str(item) for item in (batch.get("hypothesis_ids") or [])]
        if not batch_id:
            messages.append(
                "source validation batch missing batch_id; expected item shape: {\"batch_id\":\"batch-001\",\"hypothesis_ids\":[\"H-001\",\"H-002\"],\"worker_output\":\".audit/source-validation-parts/batch-001.md\",\"worker_work_dir\":\".audit/source-validation-work/batch-001/\",\"status\":\"pending\"}"
            )
        if not batch_ids:
            messages.append(f"source validation batch {batch_id or '<unknown>'} has no hypothesis_ids")
        if len(batch_ids) > SOURCE_VALIDATION_MAX_BATCH_SIZE:
            messages.append(
                f"source validation batch {batch_id or '<unknown>'} has {len(batch_ids)} hypotheses; split workers to 1-{SOURCE_VALIDATION_MAX_BATCH_SIZE} hypotheses each"
            )
        overlap = sorted(set(seen).intersection(batch_ids))
        if overlap:
            messages.append(f"source validation batch {batch_id} overlaps ids: {', '.join(overlap)}")
        seen.extend(batch_ids)
        if not worker_output.startswith(f".audit/{SOURCE_VALIDATION_PARTS_DIR}/") or not worker_output.endswith(".md"):
            messages.append(
                f"source validation batch {batch_id} has invalid worker_output: {worker_output}; expected .audit/source-validation-parts/{batch_id or 'batch-001'}.md"
            )
            continue
        expected_work_dir = f".audit/{SOURCE_VALIDATION_WORK_DIR}/{batch_id or 'batch-001'}/"
        if worker_work_dir != expected_work_dir:
            messages.append(
                f"source validation batch {batch_id} has invalid worker_work_dir: {worker_work_dir}; expected {expected_work_dir}"
            )
        else:
            work_rel = worker_work_dir.removeprefix(".audit/").rstrip("/")
            work_path = audit_dir / work_rel
            if not work_path.is_dir():
                messages.append(f"missing source validation worker work dir: {worker_work_dir}")
        if batch.get("status") != "completed":
            messages.append(f"source validation batch {batch_id or '<unknown>'} status must be completed before merging")
        part_rel = worker_output.removeprefix(".audit/")
        part_path = audit_dir / part_rel
        if not part_path.exists():
            messages.append(f"missing source validation part: {worker_output}")
            continue
        text = part_path.read_text(encoding="utf-8", errors="replace").strip()
        if len(text) < 80:
            messages.append(f"{worker_output} is too short to be a useful source-validation part")
        if "## Worker Metadata" not in text:
            messages.append(
                f"{worker_output} missing '## Worker Metadata'; each parallel worker part must record executor, assigned ids, files checked, and worker_work_dir"
            )
        if batch_id and batch_id not in text:
            messages.append(f"{worker_output} must mention its batch id {batch_id}")
    missing = sorted(set(expected_ids).difference(seen))
    extra = sorted(set(seen).difference(expected_ids))
    if missing:
        messages.append("source validation dispatch misses hypothesis ids: " + ", ".join(missing))
    if extra:
        messages.append("source validation dispatch contains unknown hypothesis ids: " + ", ".join(extra))


def check_source_validation(audit_dir: Path) -> CheckResult:
    messages: list[str] = []
    checkpoint = check_verification_checkpoint(audit_dir)
    if not checkpoint.ok:
        messages.extend("verification checkpoint incomplete: " + message for message in checkpoint.messages)
    markdown_result = check_markdown("source_validation.md")(audit_dir)
    messages.extend(markdown_result.messages)
    hypothesis_ids = load_hypothesis_ids(audit_dir, messages)
    checkpoint_data: dict[str, Any] = {}
    checkpoint_file = verification_checkpoint_path(audit_dir)
    if checkpoint_file.exists():
        try:
            checkpoint_data = load_json(checkpoint_file)
        except Exception:  # noqa: BLE001 - checkpoint errors are reported above.
            checkpoint_data = {}
    source_mode = checkpoint_data.get("source_validation_mode")
    if source_mode == "parallel" and hypothesis_ids:
        validate_source_validation_dispatch(audit_dir, hypothesis_ids, messages)
    return CheckResult(not messages, messages)


def check_markdown(rel: str) -> Callable[[Path], CheckResult]:
    def _check(audit_dir: Path) -> CheckResult:
        path = audit_dir / rel
        if not path.exists():
            return fail([f"missing {rel}"])
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if len(text) < 80:
            return fail([f"{rel} is too short to be a useful audit artifact"])
        return ok()

    return _check


PHASES: tuple[Phase, ...] = (
    Phase(
        "phase-0a-tool-preflight",
        "Phase 0A: Tool Preflight and User Approval",
        "deterministic-with-user-approval",
        "main-agent only; run preflight, report to user, wait for approval",
        ("tool_status.json", "preflight_approval.json"),
        check_phase0,
        "Summarize required and optional tool availability, limitations, and the user's approval decision.",
    ),
    Phase(
        "phase-0b-graph-context",
        "Phase 0B: Setup and Graphify Context",
        "ai-or-deterministic",
        "main-agent, optional explorer for graphify interpretation",
        ("graph_context.json",),
        check_graph_context,
        "Summarize graphify quality, graph inputs, important entrypoints, sensitive candidates, and limitations.",
    ),
    Phase(
        "phase-1-sca-secret",
        "Phase 1: SCA and Secret Context",
        "deterministic",
        "main-agent runs deterministic setup; optional parallel workers for SCA and secret scan",
        ("dependency_context.json", "dependency_findings.json|skips/sca.json", "secret_findings.json|skips/secret_scan.json"),
        check_phase1,
        "Summarize dependency scanner coverage, secret scanner coverage, skipped tools, and high-signal context.",
    ),
    Phase(
        "phase-2-semantic-model",
        "Phase 2A: Security Semantic Model",
        "ai",
        "main-agent owns final model; optional explorer workers for bounded subsystem summaries",
        ("semantic_model.json",),
        check_semantic_model,
        "Summarize roles, resources, guards, invariants, entrypoints, sensitive actions, and uncertainty.",
    ),
    Phase(
        "phase-2-hypotheses",
        "Phase 2B: Hypothesis Backlog and Current Batch",
        "ai",
        "main-agent owns backlog and shortlist; optional reviewer checks coverage and forbidden verdict wording",
        ("hypothesis_backlog.json", "hypotheses.json"),
        check_hypotheses,
        "Summarize backlog coverage by A-H class, selected batch, unvalidated areas, and prioritization rationale.",
    ),
    Phase(
        "phase-2c-verification-checkpoint",
        "Phase 2C: Verification Checkpoint and User Approval",
        "user-checkpoint",
        "main-agent only; report progress and ask user to choose parallel or sequential execution for Phase 3 and Phase 4 validation",
        ("verification_checkpoint.json",),
        check_verification_checkpoint,
        "Summarize the user-facing progress report, chosen Phase 3 tool-verification mode, chosen Phase 4 source-validation mode, rationale, and any scope changes requested by the user.",
    ),
    Phase(
        "phase-3-verification",
        "Phase 3: Tool Verification and Evidence Fusion",
        "deterministic",
        "run Semgrep first, write semgrep_triage.json as a barrier, then run exactly one semantic verifier with explicit breadth/depth accounting",
        ("semgrep-results.json", "semgrep_triage.json", "semantic_verifier_selection.json", "semantic_verifier_depth_plan.json or skips/semantic_verifier_depth.json when triaged ids exist", "semantic_verifier_depth_results.json or skips/semantic_verifier_depth.json when triaged ids exist", "evidence.json"),
        check_evidence,
        "Summarize Semgrep, semgrep_triage barrier decisions, selected semantic verifier, breadth coverage, per-hypothesis depth coverage or degradation, guard coverage, and evidence stats.",
    ),
    Phase(
        "phase-4-source-packet",
        "Phase 4A: Source Validation Packet",
        "deterministic",
        "main-agent only; no subagent needed",
        ("source_validation_packet.json", "source_validation_prompt.md"),
        check_source_packet,
        "Summarize packet size, unresolved locations, auxiliary context included, and hypotheses to validate.",
    ),
    Phase(
        "phase-4-source-validation",
        "Phase 4B: Source Validation",
        "ai",
        "main-agent integrates; use batch workers only when the checkpoint selected parallel source validation",
        ("source_validation_dispatch.json when checkpoint selected parallel source validation", "source-validation-parts/*.md when checkpoint selected parallel source validation", "source_validation.md"),
        check_source_validation,
        "Summarize confirmed, needs-review, false-positive, derived candidates, worker part files, and source-grounded reasons.",
    ),
    Phase(
        "phase-5-final-report",
        "Phase 5: Final User-Facing Report",
        "ai",
        "main-agent writes final report; optional read-only reviewer before delivery",
        ("audit_report.md",),
        check_markdown("audit_report.md"),
        "Summarize final counts, tool coverage, skipped tools, limitations, and deferred backlog.",
    ),
)

PHASE_BY_ID = {phase.id: phase for phase in PHASES}


def state_path(repo: Path) -> Path:
    return repo / ".audit" / STATE_FILE


def load_state(repo: Path) -> dict[str, Any]:
    path = state_path(repo)
    if not path.exists():
        raise SystemExit(f"No audit state at {path}. Run init first.")
    return load_json(path)


def save_state(repo: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    write_json(state_path(repo), state)


def default_skill_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def rel_to_repo(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def create_state(repo: Path, skill_dir: Path, force: bool = False) -> dict[str, Any]:
    audit_dir = repo / ".audit"
    state_file = audit_dir / STATE_FILE
    if state_file.exists() and not force:
        raise SystemExit(f"State already exists at {state_file}. Use --force to reinitialize.")
    ensure_dirs(audit_dir)
    now = utc_now()
    state = {
        "schema": SCHEMA,
        "repo_root": str(repo.resolve()),
        "skill_dir": str(skill_dir.resolve()),
        "audit_dir": str(audit_dir.resolve()),
        "current_phase": PHASES[0].id,
        "created_at": now,
        "updated_at": now,
        "phases": {
            phase.id: {
                "title": phase.title,
                "kind": phase.kind,
                "dispatch": phase.dispatch,
                "status": "pending",
                "required_outputs": list(phase.required_outputs),
                "task_file": f".audit/tasks/{phase.id}.task.md",
                "summary_file": f".audit/summaries/{phase.id}.md",
                "dispatch_file": ".audit/tasks/dispatch_plan.json",
            }
            for phase in PHASES
        },
        "history": [],
    }
    state["phases"][PHASES[0].id]["status"] = "current"
    save_state(repo, state)
    write_task(repo, state, PHASES[0])
    return state


def phase_index(phase_id: str) -> int:
    for index, phase in enumerate(PHASES):
        if phase.id == phase_id:
            return index
    raise KeyError(phase_id)


def current_phase(state: dict[str, Any]) -> Phase:
    phase_id = state.get("current_phase")
    if phase_id not in PHASE_BY_ID:
        raise SystemExit(f"Unknown current phase in state: {phase_id}")
    return PHASE_BY_ID[phase_id]


def phase_paths(repo: Path, phase: Phase) -> tuple[Path, Path]:
    return repo / ".audit" / "tasks" / f"{phase.id}.task.md", repo / ".audit" / "summaries" / f"{phase.id}.md"


def reference_list(phase: Phase) -> list[str]:
    base = [
        "SKILL.md",
        "references/schemas.md",
        "references/orchestration-protocol.md",
    ]
    mapping = {
        "phase-0a-tool-preflight": ["references/phase-0-setup-and-graphify.md"],
        "phase-0b-graph-context": ["references/phase-0-setup-and-graphify.md"],
        "phase-1-sca-secret": ["references/phase-1-sca.md", "references/phase-1b-secret-scan.md"],
        "phase-2-semantic-model": ["references/phase-2-semantics-and-hypotheses.md", "references/hypothesis_types.md"],
        "phase-2-hypotheses": ["references/phase-2-semantics-and-hypotheses.md", "references/hypothesis_types.md"],
        "phase-2c-verification-checkpoint": ["references/phase-2-semantics-and-hypotheses.md"],
        "phase-3-verification": ["references/phase-3-verification.md", "references/semgrep_templates.md", "references/joern_queries.md", "references/codeql_queries.md"],
        "phase-4-source-packet": ["references/phase-4-source-validation-and-reporting.md", "references/source_validation_playbooks.md"],
        "phase-4-source-validation": ["references/phase-4-source-validation-and-reporting.md", "references/source_validation_playbooks.md"],
        "phase-5-final-report": ["references/phase-4-source-validation-and-reporting.md", "templates/audit_report_template.md"],
    }
    return base + mapping.get(phase.id, [])


def prior_summaries(repo: Path, phase: Phase) -> list[str]:
    output: list[str] = []
    for prior in PHASES[: phase_index(phase.id)]:
        summary = repo / ".audit" / "summaries" / f"{prior.id}.md"
        if summary.exists():
            output.append(f".audit/summaries/{prior.id}.md")
    return output


def task_body(repo: Path, state: dict[str, Any], phase: Phase) -> str:
    skill_dir = Path(state["skill_dir"])
    refs = "\n".join(f"- `{rel}`" for rel in reference_list(phase))
    summaries = prior_summaries(repo, phase)
    summary_lines = "\n".join(f"- `{rel}`" for rel in summaries) if summaries else "- none yet"
    outputs = "\n".join(f"- `.audit/{rel}`" for rel in phase.required_outputs)
    summary_path = f".audit/summaries/{phase.id}.md"
    current_task = f".audit/tasks/{phase.id}.task.md"

    commands = command_hints(phase, skill_dir)
    dispatch = dispatch_hints(phase)
    py = python_cmd()
    return f"""# {phase.title}

You are executing one phase of `graph-reasoning-code-audit`.

Do not rely on prior chat memory. Treat files on disk as the source of truth.
Keep graphify output read-only after generation. Write generated audit artifacts
only under `.audit/`.

## Repository

- repo root: `{repo.resolve()}`
- skill dir: `{skill_dir.resolve()}`
- state file: `.audit/{STATE_FILE}`
- current task: `{current_task}`
- dispatch plan: `.audit/tasks/dispatch_plan.json`

## Orchestrator Mode

The main agent is the orchestrator for this phase. It may use subagents only as
described here and in `references/orchestration-protocol.md`.

- phase kind: `{phase.kind}`
- dispatch policy: {phase.dispatch}

{dispatch}

## Read First

{refs}

## Prior Phase Summaries

{summary_lines}

## Required Outputs

{outputs}

## Suggested Commands / Actions

{commands}

## Phase Contract

- Complete only this phase.
- Use the schemas in `references/schemas.md`.
- Do not mark vulnerabilities confirmed before source validation.
- Keep SCA, secret exposure, and source-code vulnerability conclusions separate.
- If a tool is unavailable, write a skip record under `.audit/skips/` with:

```json
{{"tool":"tool-name","status":"skipped","reason":"short reason","uncovered":[]}}
```

## Required Summary

Write `{summary_path}` after producing the phase artifacts.

Summary requirements:
- {phase.summary_hint}
- List exact artifacts created or intentionally skipped.
- List limitations that the next phase must know.
- Keep it short enough for the next AI session to read quickly.

## Finish

After this phase is complete, run:

```bash
{py} -m orchestrator.audit_flow validate --repo "{repo.resolve()}"
{py} -m orchestrator.audit_flow next --repo "{repo.resolve()}"
```
"""


def command_hints(phase: Phase, skill_dir: Path) -> str:
    s = skill_dir.as_posix()
    py = python_cmd()
    if phase.id == "phase-0a-tool-preflight":
        return f"""Run the tool preflight first:

```bash
{py} -m orchestrator.audit_flow preflight --repo <repo>
```

Then report `.audit/summaries/phase-0a-tool-preflight.md` to the user. Explain
which required tools are available/missing, which optional verifiers are
available/missing, and what the limitations mean.

Also ask which Graphify mode to use in Phase 0B:
- `ast` (recommended): code-only AST/code graph extraction for source audit.
- `deep`: include Graphify semantic extraction for security-relevant docs,
  diagrams, OpenAPI specs, threat models, or deployment notes.
- `existing`: reuse an existing graphify output after normalization and quality
  checks.

Stop and wait for user approval and a Graphify mode choice.
After the user approves, record it:

```bash
{py} -m orchestrator.audit_flow approve-preflight --repo <repo> --by "<user or agent>" --graphify-mode ast
```"""
    if phase.id == "phase-0b-graph-context":
        return f"""1. Read `.audit/preflight_approval.json` and use its `graphify_mode`.
   Default/recommended mode is `ast`: run Graphify for code structure, AST, call/import/reference graph, clustering, and report. Do not require Graphify semantic extraction for code-only audits.
   Use `deep` only when the user selected it because security-relevant non-code files should be included.
   Use `existing` only when an existing `graph.json` and `GRAPH_REPORT.md` are available.
2. Create or update `<repo>/.graphifyignore` for audit-irrelevant files. Use gitignore syntax. Typical exclusions:

```gitignore
.audit/
graphify-out/
**/logo*/
**/logos/**
**/brand/**
**/branding/**
**/assets/**/*.png
**/assets/**/*.jpg
**/assets/**/*.jpeg
**/assets/**/*.gif
**/assets/**/*.webp
**/assets/**/*.svg
```

Keep screenshots, diagrams, API docs, architecture images, threat models, deployment docs, and OpenAPI specs only when they help security reasoning and the user selected `deep`.
3. Run Graphify according to the approved mode:
   - `ast`: use `/graphify <repo> --no-viz` or the equivalent code/AST graph path supported by the installed Graphify. If Graphify detects a code-only corpus and skips semantic extraction, that is expected.
   - `deep`: use `/graphify <repo> --mode deep --no-viz` or equivalent.
   - `existing`: inspect the existing graphify output and normalize it.
4. Normalize it:

```bash
{py} "{s}/scripts/normalize_graphify.py" --graph-json <graph.json> --graph-report <GRAPH_REPORT.md> --repo-root <repo> --output <repo>/.audit/graph_context.json
```

5. Stop if `graphify_input_warnings` is non-empty, code graph nodes are missing, code edges are missing, or structural code edges are missing. Do not stop merely because Graphify semantic artifacts, inferred edges, or hyperedges are absent in `ast` mode."""
    if phase.id == "phase-1-sca-secret":
        return f"""Run deterministic context collection and scanners when available:

```bash
{py} "{s}/scripts/collect_dependency_context.py" --repo-root <repo> --output <repo>/.audit/dependency_context.json
# Read <repo>/.audit/dependency_context.json suggested_scanners. Prefer its manifest_or_lockfile OSV command.
osv-scanner scan --lockfile=<manifest-or-lockfile-from-dependency_context> --format json --output <repo>/.audit/osv-results.json
{py} "{s}/scripts/convert_osv_results.py" --osv-results <repo>/.audit/osv-results.json --repo-root <repo> --output <repo>/.audit/dependency_findings.json
{py} "{s}/scripts/render_sca_report.py" --dependency-findings <repo>/.audit/dependency_findings.json --output <repo>/.audit/sca_report.md
```

For Betterleaks:
- If `<repo>/.git` exists, run `betterleaks git <repo> --report-path <repo>/.audit/betterleaks-git.json --report-format json --exit-code 0`.
- Always run `betterleaks dir <repo> --report-path <repo>/.audit/betterleaks-dir.json --report-format json --exit-code 0`.
- If there is no `.git`, skip the Git-history scan and run only `betterleaks dir`.

```bash
{py} "{s}/scripts/normalize_betterleaks.py" --betterleaks-results <repo>/.audit/betterleaks-dir.json --repo-root <repo> --source-kind betterleaks-dir --output <repo>/.audit/secret_findings.dir.json
{py} "{s}/scripts/merge_secret_findings.py" --inputs <repo>/.audit/secret_findings.dir.json --output <repo>/.audit/secret_findings.json
{py} "{s}/scripts/render_secret_report.py" --secret-findings <repo>/.audit/secret_findings.json --output <repo>/.audit/secret_report.md
```

If OSV or Betterleaks is unavailable, write `.audit/skips/sca.json` or `.audit/skips/secret_scan.json`."""
    if phase.id == "phase-2-semantic-model":
        return "Create `.audit/semantic_model.json` from graph context, summaries, key source files, dependency context, and secret context. Do not create vulnerability findings here."
    if phase.id == "phase-2-hypotheses":
        return "Create `.audit/hypothesis_backlog.json` and `.audit/hypotheses.json`. Treat the shortlist as one verification batch, not full coverage."
    if phase.id == "phase-2c-verification-checkpoint":
        return f"""This is a hard user checkpoint. Do not run Phase 3 tools yet.

Report to the user:
- what has been completed in Phase 0-2;
- graph/context quality and any degraded or skipped areas;
- dependency and secret scan status;
- how many backlog candidates and shortlisted hypotheses were produced;
- the rough themes/classes in the shortlist;
- what Phase 3 will do next: Semgrep first, then a triage barrier, then exactly
  one selected semantic verifier only for triaged targets;
- what Phase 4 source validation will do after tool evidence is fused.

Ask the user to choose both execution modes:
- Phase 3 tool verification mode:
  - `parallel`: use subagents inside each funnel stage, but keep the Semgrep
    stage, triage barrier, semantic-verifier stage, and fusion stage ordered;
  - `sequential`: keep Phase 3 tool verification in the main agent/session.
- Phase 4 source validation mode:
  - `parallel`: after the source-validation packet is prepared, split hypotheses
    into disjoint batches of one to three hypotheses per worker;
  - `sequential`: keep source validation in the main agent/session.

Do not choose silently for the user. After the user answers, record the decision:

```bash
{py} -m orchestrator.audit_flow approve-verification --repo <repo> --tool-mode <parallel|sequential> --source-mode <parallel|sequential> --by "user" --progress-summary "<one sentence summary shown to user>" --next-steps "<one sentence next-step plan>"
```"""
    if phase.id == "phase-3-verification":
        return f"""Read `.audit/verification_checkpoint.json` first and follow `tool_verification_mode`.
Phase 3 is a funnel, not a flat parallel fan-out:

1. Run Semgrep first.
2. Write `.audit/semgrep_triage.json`.
3. Select exactly one primary semantic verifier: Joern or CodeQL.
4. Run the selected verifier only after reading `.audit/semgrep_triage.json`.
5. Fuse evidence.

Do not start Joern or CodeQL before `.audit/semgrep-results.json` and
`.audit/semgrep_triage.json` exist.

Select the primary semantic verifier after Semgrep triage:

```bash
{py} -m orchestrator.audit_flow select-verifier --repo <repo>
```

If `tool_verification_mode` is `parallel` and subagents are available, use a
Semgrep worker for the first stage. Wait for it to finish, then the main agent
runs triage and may start one selected semantic-verifier worker for the second
stage. If `tool_verification_mode` is `sequential`, do not spawn verification
workers; run the same funnel stages in the main agent/session.

Parallel worker write scopes:
- Semgrep worker: `.audit/semgrep-rules.yml`, `.audit/semgrep-results.json`,
  and `.audit/{TOOL_WORK_DIR}/semgrep/` only.
- Joern worker: `.audit/joern-results.json`,
  `.audit/semantic_verifier_depth_plan.json`,
  `.audit/semantic_verifier_depth_results.json`, and
  `.audit/{TOOL_WORK_DIR}/joern/` only.
- CodeQL worker: `.audit/codeql-results.json` and
  `.audit/semantic_verifier_depth_plan.json`,
  `.audit/semantic_verifier_depth_results.json`, and
  `.audit/{TOOL_WORK_DIR}/codeql/` only.
- Workers must not write `.audit/semantic_verifier_selection.json`,
  `.audit/evidence.json`, summaries, or any other aggregate artifact.

Semgrep worker:

```bash
{py} "{s}/scripts/generate_semgrep_rules.py" --hypotheses <repo>/.audit/hypotheses.json --output <repo>/.audit/semgrep-rules.yml
{py} "{s}/scripts/run_semgrep.py" --repo-root <repo> --config <repo>/.audit/semgrep-rules.yml --hypotheses <repo>/.audit/hypotheses.json --output <repo>/.audit/semgrep-results.json
{py} "{s}/scripts/triage_semgrep.py" --hypotheses <repo>/.audit/hypotheses.json --semgrep <repo>/.audit/semgrep-results.json --output <repo>/.audit/semgrep_triage.json
```

- If the repo is best served by Joern, run `run_joern_queries.py` and write
  `.audit/joern-results.json`.
- If the repo is better served by CodeQL, run CodeQL analysis and normalize the
  SARIF to `.audit/codeql-results.json`.
- Do not run both by default. Pick the one with the best current language/build
  support and record the choice in `.audit/semantic_verifier_selection.json`.
- The selected verifier must read `.audit/semgrep_triage.json` and focus on
  `semantic_review_ids`. It may skip low-signal items from semantic verification,
  but P4 source validation still receives the full current shortlist.
- Standard CodeQL packs and Joern querydb/prebuilt rules are breadth coverage.
  They do not satisfy depth validation by themselves.
- If `semantic_review_ids` is non-empty, write
  `.audit/semantic_verifier_depth_plan.json` before the selected verifier runs
  targeted checks, then write `.audit/semantic_verifier_depth_results.json`.
  Each triaged id must have one `coverage_mode: "depth"` result with status
  `hit`, `miss`, `error`, or `skipped`.

```bash
{py} "{s}/scripts/plan_semantic_depth.py" --hypotheses <repo>/.audit/hypotheses.json --triage <repo>/.audit/semgrep_triage.json --selection <repo>/.audit/semantic_verifier_selection.json --output <repo>/.audit/semantic_verifier_depth_plan.json
```

- If the selected verifier only completed breadth coverage, write
  `.audit/skips/semantic_verifier_depth.json` with `status: "degraded"`,
  a reason, and every uncovered `semantic_review_id`. This is a hard user
  checkpoint: immediately report the degradation, the attempted verifier, the
  uncovered ids, and the choices to continue, retry, switch verifier, or narrow
  scope. Stop until the user decides, then record the decision:

```bash
{py} -m orchestrator.audit_flow approve-semantic-depth-degradation --repo <repo> --decision <continue|retry|switch|narrow> --by "user" --summary "<degradation summary shown to user>" --next-steps "<approved next steps>"
```

Do not run evidence fusion or advance to Phase 4 until
`.audit/semantic_verifier_depth_approval.json` exists when depth is degraded.

```bash
{py} "{s}/scripts/fuse_evidence.py" --hypotheses <repo>/.audit/hypotheses.json --semgrep <repo>/.audit/semgrep-results.json --joern <repo>/.audit/joern-results.json --codeql <repo>/.audit/codeql-results.json --output <repo>/.audit/evidence.json
```

Run guard coverage only when appropriate, and record partial coverage explicitly."""
    if phase.id == "phase-4-source-packet":
        return f"""Prepare the packet:

```bash
{py} "{s}/scripts/source_validate.py" --repo-root <repo> --hypotheses <repo>/.audit/hypotheses.json --evidence <repo>/.audit/evidence.json --dependency-findings <repo>/.audit/dependency_findings.json --secret-findings <repo>/.audit/secret_findings.json --output <repo>/.audit/source_validation_packet.json --prompt-output <repo>/.audit/source_validation_prompt.md
```"""
    if phase.id == "phase-4-source-validation":
        return f"""Read `.audit/verification_checkpoint.json` first and follow `source_validation_mode`.
Use `.audit/source_validation_packet.json`, `.audit/source_validation_prompt.md`, playbooks, raw evidence, and source windows.

If `source_validation_mode` is `parallel`, create a disjoint worker plan before
launching subagents:

```bash
{py} -m orchestrator.audit_flow plan-source-validation --repo <repo> --batch-size 3
```

Rules:
- Source-validation workers may write only `.audit/{SOURCE_VALIDATION_PARTS_DIR}/<batch>.md`.
- Source-validation workers may write scratch files only under their assigned
  `.audit/{SOURCE_VALIDATION_WORK_DIR}/<batch>/`.
- Assign one to three hypotheses per worker; never more than three.
- Workers must not write `.audit/source_validation.md`.
- Main agent alone merges all part files into `.audit/source_validation.md`.
- If `source_validation_mode` is `sequential`, do not spawn source-validation workers.
- If the user selected `parallel` but no subagent tool is available, main agent may write the final file directly,
  but must first write `.audit/skips/source_validation_subagents.json` with
  `skip --name source_validation_subagents`, then record the fallback in the
  phase summary."""
    if phase.id == "phase-5-final-report":
        return "Read `templates/audit_report_template.md`, then write `.audit/audit_report.md` directly from source validation, evidence, scanner reports, summaries, and checked source files. Preserve the template section order unless adding a clearly needed section."
    return "Follow the phase references."


def dispatch_hints(phase: Phase) -> str:
    if phase.id == "phase-0a-tool-preflight":
        return """Main agent only:
- Run `preflight`.
- Present the generated summary to the user.
- Do not advance until the user explicitly approves continuing with the known
  tool availability and limitations.
- Record approval with `approve-preflight`."""
    if phase.id == "phase-1-sca-secret":
        return """Recommended when subagents are available:
- Start one SCA worker for `.audit/dependency_findings.json` and `.audit/sca_report.md`.
- Start one Secret Scan worker for `.audit/secret_findings.json` and `.audit/secret_report.md`.
- Workers must not edit each other's files.
- Main agent validates both outputs and writes the phase summary."""
    if phase.id == "phase-2-semantic-model":
        return """Default: main agent writes `.audit/semantic_model.json`.
Optional: spawn explorer subagents only for bounded subsystem summaries, such as
auth/session, file/upload, webhook/queue, or admin/config. Explorers return notes;
the main agent owns the final JSON."""
    if phase.id == "phase-2-hypotheses":
        return """Default: main agent writes backlog and shortlist.
Optional: after drafting, spawn one read-only reviewer to check A-H coverage,
concreteness, source anchors, and forbidden pre-validation verdict wording.
The main agent fixes issues and owns final JSON."""
    if phase.id == "phase-2c-verification-checkpoint":
        return """Main agent only:
- Read Phase 0-2 summaries and the generated hypothesis artifacts.
- Present a concise progress report to the user.
- Explain the next Phase 3 tool verification plan and Phase 4 source-validation plan.
- Ask for explicit parallel/sequential choices for both Phase 3 and Phase 4.
- Explain that Phase 3 parallelism is stage-local: Semgrep must complete and
  produce `.audit/semgrep_triage.json` before Joern or CodeQL starts.
- Stop and wait for the user's explicit choices.
- Record the choice with `approve-verification`.
- Do not run Semgrep, Joern, or CodeQL in this checkpoint."""
    if phase.id == "phase-3-verification":
        return """Recommended when subagents are available:
- Read `.audit/verification_checkpoint.json`.
- Run Semgrep first.
- Main agent writes `.audit/semgrep_triage.json` before any semantic verifier starts.
- Main agent then selects exactly one primary semantic verifier: Joern or CodeQL.
- If `tool_verification_mode` is `parallel`, Semgrep worker owns `.audit/semgrep-results.json`.
- If `tool_verification_mode` is `parallel` and Joern is selected after triage, a Joern worker owns `.audit/joern-results.json`, `.audit/semantic_verifier_depth_plan.json`, and `.audit/semantic_verifier_depth_results.json`.
- If `tool_verification_mode` is `parallel` and CodeQL is selected after triage, a CodeQL worker owns `.audit/codeql-results.json`, `.audit/semantic_verifier_depth_plan.json`, and `.audit/semantic_verifier_depth_results.json`.
- Each verification worker may write temporary files only under its private `.audit/tool-work/<semgrep|joern|codeql>/` directory.
- Never start Semgrep and the selected verifier worker together; the triage file is the barrier.
- In `sequential` mode, do not spawn verification workers.
- Standard query packs/querydb are breadth coverage only. The selected semantic verifier must write per-hypothesis depth plan/results for `semantic_review_ids`, or the main agent must write `.audit/skips/semantic_verifier_depth.json` marking breadth-only degraded coverage.
- Main agent records the selection, runs deterministic fusion, and owns `.audit/evidence.json`."""
    if phase.id == "phase-4-source-validation":
        return """Follow the user's checkpoint choice:
- Read `.audit/verification_checkpoint.json`.
- If `source_validation_mode` is `sequential`, do not spawn source-validation workers.
- If `source_validation_mode` is `parallel`, run `plan-source-validation`, split hypothesis ids into disjoint ranges, and delegate batch workers.
- Each source-validation worker handles one to three hypotheses and writes one `.audit/source-validation-parts/<batch>.md`.
- Each source-validation worker may write temporary files only under its assigned `.audit/source-validation-work/<batch>/`.
- Source-validation workers must never write `.audit/source_validation.md`.
- Main agent merges parts into `.audit/source_validation.md`, resolves conflicts,
  and ensures SCA/secret/source-code conclusions remain separated.
- If the user selected `parallel` but no subagent tool is available, write `.audit/skips/source_validation_subagents.json`
  before direct main-agent validation and explain the fallback in the summary."""
    if phase.id == "phase-5-final-report":
        return """Optional:
- Main agent writes `.audit/audit_report.md`.
- Main agent must read `templates/audit_report_template.md` and use it as the report structure.
- One read-only reviewer can return pass/fail on required sections, counts,
  skipped-tool limitations, and improper mixing of SCA/secret/source findings.
- Main agent applies fixes before delivery."""
    if phase.id == "phase-0b-graph-context":
        return """Default: main agent handles graphify hygiene and normalization.
Optional: an explorer may inspect graphify output quality, but the main agent
owns `.audit/graph_context.json` and the stop/continue decision."""
    return "No subagent is needed for this deterministic phase."


def dispatch_plan(repo: Path, state: dict[str, Any], phase: Phase) -> dict[str, Any]:
    audit_dir = repo / ".audit"
    plan = {
        "schema": "graph-reasoning-code-audit/dispatch-plan-v1",
        "repo_root": str(repo.resolve()),
        "phase": phase.id,
        "title": phase.title,
        "kind": phase.kind,
        "main_agent_role": "orchestrator",
        "dispatch_policy": phase.dispatch,
        "instructions": dispatch_hints(phase),
        "required_outputs": list(phase.required_outputs),
        "references": reference_list(phase),
        "prior_summaries": prior_summaries(repo, phase),
        "state_file": ".audit/audit_state.json",
        "current_task": f".audit/tasks/{phase.id}.task.md",
        "created_at": utc_now(),
    }
    checkpoint = verification_checkpoint_path(audit_dir)
    if phase.id == "phase-3-verification" and checkpoint.exists():
        try:
            data = load_json(checkpoint)
            tool_mode = data.get("tool_verification_mode", data.get("verification_mode"))
            plan["tool_verification_mode"] = tool_mode
            plan["verification_mode"] = tool_mode
            plan["verification_checkpoint"] = ".audit/verification_checkpoint.json"
            plan["phase_3_funnel"] = {
                "ordered_stages": [
                    "semgrep",
                    "semgrep_triage",
                    "selected_semantic_verifier",
                    "semantic_depth_accounting",
                    "evidence_fusion",
                ],
                "barrier": ".audit/semgrep_triage.json",
                "parallelism_scope": "stage-local only; do not run Semgrep and Joern/CodeQL concurrently",
                "depth_policy": "CodeQL/Joern breadth coverage is insufficient when semantic_review_ids exist; require semantic_verifier_depth_plan.json and semantic_verifier_depth_results.json or skips/semantic_verifier_depth.json",
            }
        except Exception:  # noqa: BLE001 - dispatch plan should still be writable.
            plan["verification_checkpoint"] = ".audit/verification_checkpoint.json"
            plan["tool_verification_mode"] = "unreadable"
            plan["verification_mode"] = "unreadable"
    if phase.id == "phase-4-source-validation" and checkpoint.exists():
        try:
            data = load_json(checkpoint)
            plan["source_validation_mode"] = data.get("source_validation_mode")
            plan["verification_checkpoint"] = ".audit/verification_checkpoint.json"
        except Exception:  # noqa: BLE001 - dispatch plan should still be writable.
            plan["verification_checkpoint"] = ".audit/verification_checkpoint.json"
            plan["source_validation_mode"] = "unreadable"
    return plan


def write_task(repo: Path, state: dict[str, Any], phase: Phase) -> Path:
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    task_path, _ = phase_paths(repo, phase)
    body = task_body(repo, state, phase)
    task_path.write_text(body, encoding="utf-8")
    (audit_dir / "tasks" / "current.task.md").write_text(body, encoding="utf-8")
    write_json(audit_dir / "tasks" / "dispatch_plan.json", dispatch_plan(repo, state, phase))
    state["phases"][phase.id]["task_generated_at"] = utc_now()
    state["phases"][phase.id]["task_file"] = rel_to_repo(repo, task_path)
    state["phases"][phase.id]["dispatch_file"] = ".audit/tasks/dispatch_plan.json"
    save_state(repo, state)
    return task_path


def validate_phase(repo: Path, phase: Phase) -> CheckResult:
    return phase.check(repo / ".audit")


def mark_history(state: dict[str, Any], event: str, phase_id: str, detail: str = "") -> None:
    state.setdefault("history", []).append({"at": utc_now(), "event": event, "phase": phase_id, "detail": detail})


def advance(repo: Path, state: dict[str, Any]) -> tuple[bool, str]:
    phase = current_phase(state)
    result = validate_phase(repo, phase)
    if not result.ok:
        return False, "Cannot advance:\n" + "\n".join(f"- {message}" for message in result.messages)

    summary_path = repo / ".audit" / "summaries" / f"{phase.id}.md"
    if not summary_path.exists():
        return False, f"Cannot advance: missing summary {rel_to_repo(repo, summary_path)}"

    state["phases"][phase.id]["status"] = "complete"
    state["phases"][phase.id]["completed_at"] = utc_now()
    mark_history(state, "complete", phase.id)

    index = phase_index(phase.id)
    if index + 1 >= len(PHASES):
        state["current_phase"] = None
        mark_history(state, "done", phase.id)
        save_state(repo, state)
        return True, "Audit flow complete."

    next_phase = PHASES[index + 1]
    state["current_phase"] = next_phase.id
    state["phases"][next_phase.id]["status"] = "current"
    mark_history(state, "advance", next_phase.id)
    save_state(repo, state)
    task = write_task(repo, state, next_phase)
    return True, f"Advanced to {next_phase.title}. Task: {rel_to_repo(repo, task)}"


def cmd_init(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    skill_dir = args.skill_dir.resolve() if args.skill_dir else default_skill_dir()
    state = create_state(repo, skill_dir, args.force)
    phase = current_phase(state)
    task_path = repo / ".audit" / "tasks" / f"{phase.id}.task.md"
    print(f"Initialized audit flow at {repo / '.audit'}")
    print(f"Current phase: {phase.title}")
    print(f"Task: {rel_to_repo(repo, task_path)}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0
    current = state.get("current_phase")
    print(f"Repo: {state.get('repo_root')}")
    print(f"Audit dir: {state.get('audit_dir')}")
    print(f"Current phase: {current or 'DONE'}")
    for phase in PHASES:
        meta = state["phases"][phase.id]
        marker = "*" if phase.id == current else " "
        print(f"{marker} {phase.id}: {meta.get('status')}")
    return 0


def cmd_task(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    task = write_task(repo, state, phase)
    print(f"Regenerated task: {rel_to_repo(repo, task)}")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    if phase.id != "phase-0a-tool-preflight" and not args.force:
        raise SystemExit(f"Preflight is only expected in phase-0a-tool-preflight; current phase is {phase.id}. Use --force to rerun.")
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    status = preflight_tools()
    write_json(tool_cache_path(audit_dir), status)
    report = write_preflight_report(repo, status)
    mark_history(state, "preflight", phase.id, "tool_status.json")
    save_state(repo, state)
    print(f"Wrote {rel_to_repo(repo, tool_cache_path(audit_dir))}")
    print(f"Wrote {rel_to_repo(repo, report)}")
    required_missing = status["summary"]["required_missing"]
    if required_missing:
        print("Required tools missing: " + ", ".join(required_missing))
        return 1
    print("Required tools available. Report the preflight summary to the user and wait for approval.")
    return 0


def cmd_select_verifier(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    tool_file = tool_cache_path(audit_dir)
    if not tool_file.exists():
        raise SystemExit("Run preflight before selecting a semantic verifier.")
    tool_status = load_json(tool_file)
    selection = select_semantic_verifier(repo, tool_status, args.verifier)
    write_json(semantic_verifier_path(audit_dir), selection)
    print(f"Wrote {rel_to_repo(repo, semantic_verifier_path(audit_dir))}")
    print(f"Selected semantic verifier: {selection['chosen']}")
    print(f"Reason: {selection['reason']}")
    return 0


def cmd_plan_source_validation(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    dispatch = plan_source_validation(repo, args.batch_size)
    path = source_validation_dispatch_path(audit_dir)
    write_json(path, dispatch)
    for batch in dispatch["batches"]:
        work_rel = str(batch["worker_work_dir"]).removeprefix(".audit/").rstrip("/")
        (audit_dir / work_rel).mkdir(parents=True, exist_ok=True)
    print(f"Wrote {rel_to_repo(repo, path)}")
    print(f"Hypotheses: {dispatch['hypothesis_count']}")
    print(f"Batches: {len(dispatch['batches'])}")
    print("Workers may write only their assigned source-validation part files; main agent owns source_validation.md.")
    return 0


def cmd_approve_preflight(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    if phase.id != "phase-0a-tool-preflight" and not args.force:
        raise SystemExit(f"Approval is only expected in phase-0a-tool-preflight; current phase is {phase.id}. Use --force to record anyway.")
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    if not tool_cache_path(audit_dir).exists():
        raise SystemExit("Run preflight before approving.")
    payload = {
        "schema": "graph-reasoning-code-audit/preflight-approval-v1",
        "status": "approved",
        "approved_by": args.by,
        "note": args.note,
        "approved_at": utc_now(),
        "tool_status": ".audit/tool_status.json",
        "graphify_mode": args.graphify_mode,
        "graphify_mode_reason": args.graphify_mode_reason,
    }
    write_json(approval_path(audit_dir), payload)
    graphify_payload = {
        "schema": "graph-reasoning-code-audit/graphify-mode-v1",
        "status": "approved",
        "mode": args.graphify_mode,
        "reason": args.graphify_mode_reason,
        "approved_by": args.by,
        "approved_at": payload["approved_at"],
        "preflight_approval": ".audit/preflight_approval.json",
    }
    write_json(graphify_mode_path(audit_dir), graphify_payload)
    mark_history(state, "approve-preflight", phase.id, args.by)
    save_state(repo, state)
    print(f"Wrote {rel_to_repo(repo, approval_path(audit_dir))}")
    print(f"Wrote {rel_to_repo(repo, graphify_mode_path(audit_dir))}")
    print(f"Graphify mode: {args.graphify_mode}")
    return 0


def cmd_approve_verification(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    if phase.id != "phase-2c-verification-checkpoint" and not args.force:
        raise SystemExit(
            f"Verification approval is only expected in phase-2c-verification-checkpoint; current phase is {phase.id}. Use --force to record anyway."
        )
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    tool_mode = args.tool_mode or args.mode
    source_mode = args.source_mode or args.mode
    if not tool_mode or not source_mode:
        raise SystemExit("approve-verification requires --tool-mode and --source-mode, or legacy --mode to set both.")
    payload = {
        "schema": "graph-reasoning-code-audit/verification-checkpoint-v1",
        "status": "approved",
        "approved_by": args.by,
        "approved_at": utc_now(),
        "reported_to_user": True,
        "user_choice_recorded": True,
        "tool_verification_mode": tool_mode,
        "source_validation_mode": source_mode,
        "verification_mode": tool_mode,
        "progress_summary": args.progress_summary,
        "next_steps": args.next_steps,
        "note": args.note,
    }
    write_json(verification_checkpoint_path(audit_dir), payload)
    mark_history(state, "approve-verification", phase.id, f"tool={tool_mode}; source={source_mode}")
    save_state(repo, state)
    print(f"Wrote {rel_to_repo(repo, verification_checkpoint_path(audit_dir))}")
    print(f"Tool verification mode: {tool_mode}")
    print(f"Source validation mode: {source_mode}")
    return 0


def cmd_approve_semantic_depth_degradation(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    if phase.id != "phase-3-verification" and not args.force:
        raise SystemExit(
            f"Semantic-depth degradation approval is only expected in phase-3-verification; current phase is {phase.id}. Use --force to record anyway."
        )
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    degraded_path = audit_dir / "skips" / "semantic_verifier_depth.json"
    if not degraded_path.exists():
        raise SystemExit("Write skips/semantic_verifier_depth.json before approving degraded semantic verification.")
    payload = {
        "schema": "graph-reasoning-code-audit/semantic-depth-degradation-approval-v1",
        "status": "approved",
        "decision": args.decision,
        "approved_by": args.by,
        "approved_at": utc_now(),
        "reported_to_user": True,
        "degradation_record": ".audit/skips/semantic_verifier_depth.json",
        "summary": args.summary,
        "next_steps": args.next_steps,
        "note": args.note,
    }
    write_json(semantic_depth_approval_path(audit_dir), payload)
    mark_history(state, "approve-semantic-depth-degradation", phase.id, f"decision={args.decision}")
    save_state(repo, state)
    print(f"Wrote {rel_to_repo(repo, semantic_depth_approval_path(audit_dir))}")
    print(f"Semantic-depth decision: {args.decision}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    phase = current_phase(state)
    result = validate_phase(repo, phase)
    if result.ok:
        print(f"OK: {phase.title}")
        return 0
    print(f"NOT READY: {phase.title}")
    for message in result.messages:
        print(f"- {message}")
    return 1


def cmd_next(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    state = load_state(repo)
    success, message = advance(repo, state)
    print(message)
    return 0 if success else 1


def cmd_skip(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    audit_dir = repo / ".audit"
    ensure_dirs(audit_dir)
    payload = {
        "tool": args.tool,
        "status": args.status,
        "reason": args.reason,
        "uncovered": args.uncovered or [],
        "created_at": utc_now(),
    }
    path = audit_dir / "skips" / f"{args.name}.json"
    write_json(path, payload)
    print(f"Wrote skip record: {rel_to_repo(repo, path)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Initialize .audit state and the first task.")
    init.add_argument("--repo", required=True, type=Path)
    init.add_argument("--skill-dir", type=Path, default=None)
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    status = sub.add_parser("status", help="Show audit flow status.")
    status.add_argument("--repo", required=True, type=Path)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    task = sub.add_parser("task", help="Regenerate current task file.")
    task.add_argument("--repo", required=True, type=Path)
    task.set_defaults(func=cmd_task)

    preflight = sub.add_parser("preflight", help="Check required and optional audit tools.")
    preflight.add_argument("--repo", required=True, type=Path)
    preflight.add_argument("--force", action="store_true")
    preflight.set_defaults(func=cmd_preflight)

    approve = sub.add_parser("approve-preflight", help="Record user approval to continue after tool preflight.")
    approve.add_argument("--repo", required=True, type=Path)
    approve.add_argument("--by", default="user")
    approve.add_argument("--note", default="")
    approve.add_argument(
        "--graphify-mode",
        choices=["ast", "deep", "existing"],
        required=True,
        help="Graphify mode approved by the user: ast is recommended for code-only audit; deep includes non-code semantic extraction; existing reuses existing graph output.",
    )
    approve.add_argument(
        "--graphify-mode-reason",
        default="",
        help="Short reason for the selected Graphify mode.",
    )
    approve.add_argument("--force", action="store_true")
    approve.set_defaults(func=cmd_approve_preflight)

    verify_approval = sub.add_parser(
        "approve-verification",
        help="Record user approval at the Phase 2C verification checkpoint.",
    )
    verify_approval.add_argument("--repo", required=True, type=Path)
    verify_approval.add_argument("--tool-mode", choices=["parallel", "sequential"])
    verify_approval.add_argument("--source-mode", choices=["parallel", "sequential"])
    verify_approval.add_argument("--mode", choices=["parallel", "sequential"], help="Legacy shortcut: set both --tool-mode and --source-mode.")
    verify_approval.add_argument("--by", default="user")
    verify_approval.add_argument("--progress-summary", required=True)
    verify_approval.add_argument("--next-steps", required=True)
    verify_approval.add_argument("--note", default="")
    verify_approval.add_argument("--force", action="store_true")
    verify_approval.set_defaults(func=cmd_approve_verification)

    select_verifier = sub.add_parser("select-verifier", help="Pick Joern or CodeQL for Phase 3 based on repo language support.")
    select_verifier.add_argument("--repo", required=True, type=Path)
    select_verifier.add_argument(
        "--verifier",
        choices=["auto", "codeql", "joern", "unavailable"],
        default="auto",
        help="Override automatic verifier selection when the user or operator explicitly chooses one.",
    )
    select_verifier.set_defaults(func=cmd_select_verifier)

    depth_approval = sub.add_parser(
        "approve-semantic-depth-degradation",
        help="Record user approval after CodeQL/Joern hypothesis-depth validation degrades.",
    )
    depth_approval.add_argument("--repo", required=True, type=Path)
    depth_approval.add_argument("--decision", choices=["continue", "retry", "switch", "narrow"], required=True)
    depth_approval.add_argument("--by", default="user")
    depth_approval.add_argument("--summary", required=True)
    depth_approval.add_argument("--next-steps", required=True)
    depth_approval.add_argument("--note", default="")
    depth_approval.add_argument("--force", action="store_true")
    depth_approval.set_defaults(func=cmd_approve_semantic_depth_degradation)

    source_validation_plan = sub.add_parser(
        "plan-source-validation",
        help="Create a disjoint Phase 4B source-validation worker dispatch plan.",
    )
    source_validation_plan.add_argument("--repo", required=True, type=Path)
    source_validation_plan.add_argument("--batch-size", type=int, default=SOURCE_VALIDATION_DEFAULT_BATCH_SIZE)
    source_validation_plan.set_defaults(func=cmd_plan_source_validation)

    validate = sub.add_parser("validate", help="Validate current phase artifacts.")
    validate.add_argument("--repo", required=True, type=Path)
    validate.set_defaults(func=cmd_validate)

    next_cmd = sub.add_parser("next", help="Validate current phase and advance.")
    next_cmd.add_argument("--repo", required=True, type=Path)
    next_cmd.set_defaults(func=cmd_next)

    skip = sub.add_parser("skip", help="Write a skip record for optional tooling.")
    skip.add_argument("--repo", required=True, type=Path)
    skip.add_argument(
        "--name",
        required=True,
        choices=[
            "sca",
            "secret_scan",
            "semgrep",
            "joern",
            "codeql",
            "guard_coverage",
            "semantic_verifier_depth",
            "source_validation_subagents",
            "graph_context_degraded",
        ],
    )
    skip.add_argument("--tool", required=True)
    skip.add_argument("--status", choices=["skipped", "degraded"], default="skipped")
    skip.add_argument("--reason", required=True)
    skip.add_argument("--uncovered", action="append", default=[])
    skip.set_defaults(func=cmd_skip)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
