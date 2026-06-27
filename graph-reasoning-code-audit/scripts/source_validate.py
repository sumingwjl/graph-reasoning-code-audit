#!/usr/bin/env python3
"""Prepare source-validation packets for LLM adjudication.

This script does deterministic evidence collection only. It does not decide
whether a hypothesis is a real vulnerability.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CLASS_TO_PLAYBOOK = {
    "A": "A. Identity and Access Control",
    "B": "B. Workflow and State Machine",
    "C": "C. Business Logic and Abuse",
    "D": "D. Injection and Unsafe Interpretation",
    "E": "E. Data Exposure and Privacy",
    "F": "F. Secrets, Crypto, and Session Security",
    "G": "G. External Boundaries, Files, and Network",
    "H": "H. Concurrency, Consistency, and Resource Exhaustion",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


@dataclass(frozen=True)
class SourceRef:
    path: str
    line: int | None = None
    note: str = ""


def parse_source_ref(value: Any) -> SourceRef | None:
    if isinstance(value, dict):
        path = value.get("path") or value.get("file")
        if not path:
            return None
        line = value.get("line") or value.get("start", {}).get("line") if isinstance(value.get("start"), dict) else value.get("line")
        try:
            line_int = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_int = None
        return SourceRef(normalize_path(str(path)), line_int, str(value.get("note") or "tool evidence"))

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if ":" in text:
            maybe_path, maybe_line = text.rsplit(":", 1)
            try:
                return SourceRef(normalize_path(maybe_path), int(maybe_line), "seed")
            except ValueError:
                pass
        return SourceRef(normalize_path(text), None, "seed")

    return None


def collect_locations(finding: dict[str, Any], hypothesis: dict[str, Any]) -> list[SourceRef]:
    refs: list[SourceRef] = []

    for value in hypothesis.get("evidence_seed", []):
        ref = parse_source_ref(value)
        if ref:
            refs.append(ref)

    for value in finding.get("locations", []):
        ref = parse_source_ref(value)
        if ref:
            refs.append(ref)

    tool_evidence = finding.get("tool_evidence") or {}
    for items in tool_evidence.values():
        if not isinstance(items, list):
            continue
        for item in items:
            for key in ("locations", "evidence", "source_locations"):
                values = item.get(key) if isinstance(item, dict) else None
                if isinstance(values, list):
                    for value in values:
                        ref = parse_source_ref(value)
                        if ref:
                            refs.append(ref)
            ref = parse_source_ref(item)
            if ref:
                refs.append(ref)

    deduped: list[SourceRef] = []
    seen: set[tuple[str, int | None]] = set()
    for ref in refs:
        key = (ref.path, ref.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return deduped


def dependency_finding_to_hypothesis(item: dict[str, Any]) -> dict[str, Any]:
    package = item.get("package") or "configuration"
    advisory = item.get("advisory") or {}
    advisory_id = advisory.get("id") or "advisory"
    title = f"{package} may be affected by {advisory_id}"
    return {
        "id": item.get("id"),
        "class": "SCA",
        "type": item.get("type") or "known_vulnerable_dependency",
        "title": title,
        "entrypoints": [],
        "resources": [package],
        "sensitive_actions": ["framework/dependency/configuration exposure"],
        "expected_guards": ["fixed version", "safe configuration", "feature disabled or unreachable", "documented mitigation"],
        "suspected_gap": item.get("reasoning") or title,
        "verification_plan": {
            "semgrep": [],
            "joern": [],
            "codeql": [],
            "sca": ["Verify affected range, fixed version, and advisory trigger conditions."],
            "config": ["Verify project configuration and feature reachability."],
        },
        "priority": "high" if advisory.get("severity") in {"critical", "high"} else "medium",
        "confidence_prior": "medium",
        "evidence_seed": [],
    }


def dependency_finding_to_evidence(item: dict[str, Any]) -> dict[str, Any]:
    locations = []
    for key in ("usage_evidence", "config_evidence", "evidence"):
        values = item.get(key)
        if isinstance(values, list):
            locations.extend(value for value in values if isinstance(value, dict))
    return {
        "id": item.get("id"),
        "hypothesis_ids": [item.get("id")],
        "class": "SCA",
        "type": item.get("type") or "known_vulnerable_dependency",
        "title": dependency_finding_to_hypothesis(item)["title"],
        "status": item.get("status") or "needs_review",
        "risk": (item.get("advisory") or {}).get("severity") or "medium",
        "confidence": item.get("confidence") if item.get("confidence") is not None else 0.4,
        "locations": locations,
        "call_paths": [],
        "tool_evidence": {
            "dependency": [item],
            "semgrep": [],
            "joern": [],
            "codeql": [],
        },
        "reasoning_summary": item.get("reasoning") or "",
        "fix_suggestion": item.get("fix_suggestion") or "",
    }


def secret_finding_to_hypothesis(item: dict[str, Any]) -> dict[str, Any]:
    rule_id = item.get("rule_id") or "secret"
    locations = item.get("locations") or []
    title_location = ""
    if locations:
        location = locations[0]
        title_location = f" in {location.get('path', 'source')}"
    return {
        "id": item.get("id"),
        "class": "F",
        "type": "hardcoded_secret",
        "title": f"Hardcoded secret candidate {rule_id}{title_location}",
        "entrypoints": [loc.get("path") for loc in locations if isinstance(loc, dict) and loc.get("path")],
        "resources": ["secret material", rule_id],
        "sensitive_actions": ["credential use", "token signing/verification", "third-party service access"],
        "expected_guards": [
            "secret value is not committed to source/history/artifacts",
            "runtime uses secret manager or deployment environment",
            "test fixtures and placeholders are clearly inert",
        ],
        "suspected_gap": item.get("description") or f"Secret scanner matched {rule_id}",
        "verification_plan": {
            "source": [
                "Verify whether the value is real, placeholder, fixture, or false positive.",
                "Trace whether runtime code or deployment config uses the value.",
                "Identify concrete impact if the secret is effective.",
            ],
            "semgrep": [],
            "joern": [],
            "codeql": [],
        },
        "priority": item.get("risk") or "high",
        "confidence_prior": "high" if numeric_confidence(item.get("confidence")) >= 0.75 else "medium",
        "evidence_seed": locations,
    }


def secret_finding_to_evidence(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "hypothesis_ids": [item.get("id")],
        "class": "F",
        "type": "hardcoded_secret",
        "title": secret_finding_to_hypothesis(item)["title"],
        "status": item.get("status") or "needs_review",
        "risk": item.get("risk") or "high",
        "confidence": item.get("confidence") if item.get("confidence") is not None else 0.6,
        "locations": item.get("locations") or [],
        "call_paths": [],
        "tool_evidence": {
            "secret": [item],
            "semgrep": [],
            "joern": [],
            "codeql": [],
        },
        "reasoning_summary": item.get("reasoning") or "",
        "fix_suggestion": item.get("fix_suggestion") or "",
    }


def severity_rank(severity: str | None) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "unknown": 0}
    return ranks.get(str(severity or "unknown").lower(), 0)


def numeric_confidence(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def dependency_context_item(item: dict[str, Any]) -> dict[str, Any]:
    advisory = item.get("advisory") or {}
    return {
        "id": item.get("id"),
        "package": item.get("package"),
        "version": item.get("version"),
        "ecosystem": item.get("ecosystem"),
        "advisory": {
            "id": advisory.get("id"),
            "aliases": advisory.get("aliases") or [],
            "severity": advisory.get("severity"),
            "affected_range": advisory.get("affected_range"),
            "fixed_versions": advisory.get("fixed_versions") or [],
        },
        "trigger_conditions": item.get("trigger_conditions") or [],
        "reasoning": item.get("reasoning") or "",
        "fix_suggestion": item.get("fix_suggestion") or "",
        "config_evidence": item.get("config_evidence") or [],
        "usage_evidence": item.get("usage_evidence") or [],
    }


def secret_context_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "rule_id": item.get("rule_id"),
        "description": item.get("description"),
        "risk": item.get("risk"),
        "confidence": item.get("confidence"),
        "validation": item.get("validation") or {},
        "locations": item.get("locations") or [],
        "secret": item.get("secret") or {},
        "git_context": item.get("git_context") or {},
        "status": item.get("status") or "needs_review",
        "reasoning": item.get("reasoning") or "",
        "fix_suggestion": item.get("fix_suggestion") or "",
    }


def resolve_file(repo_root: Path, ref_path: str) -> Path | None:
    path = Path(ref_path)
    candidates = []
    if path.is_absolute():
        candidates.append(path)
    candidates.append(repo_root / ref_path)

    repo_name = repo_root.name
    normalized = normalize_path(ref_path)
    if normalized.startswith(repo_name + "/"):
        candidates.append(repo_root / normalized[len(repo_name) + 1 :])

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    basename = Path(ref_path).name
    if not basename:
        return None

    suffix = normalize_path(ref_path)
    matches: list[Path] = []
    for candidate in repo_root.rglob(basename):
        if not candidate.is_file():
            continue
        rel = normalize_path(str(candidate.relative_to(repo_root)))
        if rel.endswith(suffix) or rel.endswith("/" + suffix) or suffix.endswith(rel):
            matches.append(candidate)

    if len(matches) == 1:
        return matches[0]
    if matches:
        return sorted(matches, key=lambda p: len(str(p)))[0]
    return None


def source_window(path: Path, repo_root: Path, line: int | None, context: int, max_lines: int) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    total = len(lines)
    if line is None:
        start = 1
        end = min(total, max_lines)
    else:
        start = max(1, line - context)
        end = min(total, line + context)
    numbered = [{"line": idx, "text": lines[idx - 1]} for idx in range(start, end + 1)]
    return {
        "path": normalize_path(str(path.relative_to(repo_root))),
        "start_line": start,
        "end_line": end,
        "lines": numbered,
    }


def build_prompt(packet_path: Path, playbook_path: str) -> str:
    return f"""# Source Validation Task

Use `references/source_validation_playbooks.md` from this skill, especially the universal verdict contract and the relevant class playbooks.

Input packet:

`{packet_path}`

For each packet item:

1. Restate the claim being checked.
2. Trace the attacker-reachable path from entrypoint to sensitive action.
3. Trace the guard or invariant chain.
4. Apply the vulnerability scope gate: realistic actor trigger, security
   boundary or invariant, sensitive action/asset, missing effective control,
   and concrete harm.
5. Decide `confirmed`, `false_positive`, or `needs_review`.
6. Cite file and line locations from the source windows.
7. For confirmed items, provide a concise evidence path and a taint/slice path
   when available. If no tool taint path exists, state `not_available` and give
   the source-validation path instead.
8. For confirmed items, provide a minimal safe reproduction or payload when it
   is useful and non-destructive. Redact real secrets and destructive values.

Scope rule: this is not a secure-coding-practice or hardening review. Do not
mark an item confirmed just because it lacks defense-in-depth, uses a permissive
default, duplicates auth logic, has a nonideal crypto/config pattern, exposes
minor informational details, lacks parser/queue hardening, or could become risky
after a future misconfiguration. Confirm only when source evidence shows a
realistic actor-triggered path to concrete security impact.

Derived finding rule: if you notice a new issue that is not a packet item, treat
it as a candidate until it passes the same validation contract. Do not put a
derived candidate into the confirmed section of the final report unless
attacker source, sink/action, missing guard/sanitizer, and source citations for
the full path are all present.

Injection rule: for SQL/query injection, raw SQL APIs or string interpolation
alone are not enough. Confirm only if attacker-controlled data can alter query
syntax/semantics and no parameterization, allowlist, escaping, or strong type
boundary makes it inert.

Secret rule: for hardcoded secret matches, a scanner hit alone is not enough.
Confirm only if source/context shows the value is an effective secret or
deployment credential and concrete impact exists. Placeholders, samples,
fixtures, local-only defaults, and inert test values are not confirmed
vulnerabilities.

Use this output shape for each hypothesis:

```json
{{
  "hypothesis_id": "H-001",
  "status": "confirmed|false_positive|needs_review",
  "confidence": 0.0,
  "source_locations_checked": [
    {{"path": "src/file.ts", "line": 10, "note": "why this line matters"}}
  ],
  "scope_gate": {{
    "actor_trigger": "present|missing|unclear",
    "security_boundary_or_invariant": "present|missing|unclear",
    "sensitive_action_or_asset": "present|missing|unclear",
    "missing_effective_control": "present|missing|unclear",
    "concrete_harm": "present|missing|unclear"
  }},
  "attacker_path": [],
  "evidence_path": [],
  "taint_or_slice_path": {{
    "status": "available|not_available|not_applicable",
    "source": "attacker-controlled field or trigger",
    "propagation": [],
    "sink": "sensitive action/interpreter/state write",
    "missing_or_ineffective_guard": "guard name or reason"
  }},
  "guard_or_invariant_chain": [],
  "minimal_reproduction": {{
    "status": "provided|not_safe|not_applicable|needs_environment",
    "payload": "safe minimal request/body/steps, with secrets and destructive values redacted",
    "notes": "preconditions and safety limits"
  }},
  "reasoning": "short source-grounded explanation",
  "residual_questions": []
}}
```

Write the final human-readable adjudication to `source_validation.md`.
The playbook reference is `{playbook_path}`.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--dependency-findings", type=Path)
    parser.add_argument("--secret-findings", type=Path)
    parser.add_argument("--max-dependency-findings", type=int, default=20)
    parser.add_argument("--max-secret-findings", type=int, default=30)
    parser.add_argument(
        "--min-dependency-severity",
        choices=["unknown", "low", "medium", "high", "critical"],
        default="medium",
    )
    parser.add_argument(
        "--include-dependency-findings-as-items",
        action="store_true",
        help="Treat dependency findings as source-validation items. Default is to attach them as auxiliary SCA context only.",
    )
    parser.add_argument(
        "--include-secret-findings-as-items",
        action="store_true",
        help="Treat secret findings as source-validation items. Default is to attach them as auxiliary secret context only.",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prompt-output", type=Path)
    parser.add_argument("--context-lines", type=int, default=18)
    parser.add_argument("--max-file-lines", type=int, default=120)
    parser.add_argument("--max-windows-per-finding", type=int, default=24)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    hypotheses_payload = load_json(args.hypotheses)
    evidence_payload = load_json(args.evidence)
    hypotheses = {item["id"]: item for item in hypotheses_payload.get("hypotheses", [])}
    findings = list(evidence_payload.get("findings", []))
    auxiliary_dependency_findings: list[dict[str, Any]] = []
    auxiliary_secret_findings: list[dict[str, Any]] = []

    if args.dependency_findings and args.dependency_findings.exists():
        dependency_payload = load_json(args.dependency_findings)
        dependency_items = [
            item
            for item in dependency_payload.get("findings", [])
            if severity_rank((item.get("advisory") or {}).get("severity")) >= severity_rank(args.min_dependency_severity)
        ]
        dependency_items = sorted(
            dependency_items,
            key=lambda item: (
                -severity_rank((item.get("advisory") or {}).get("severity")),
                str(item.get("package") or ""),
                str((item.get("advisory") or {}).get("id") or ""),
            ),
        )[: args.max_dependency_findings]
        for dependency_item in dependency_items:
            auxiliary_dependency_findings.append(dependency_context_item(dependency_item))
            if args.include_dependency_findings_as_items:
                hid = dependency_item.get("id")
                if not hid:
                    continue
                hypotheses[str(hid)] = dependency_finding_to_hypothesis(dependency_item)
                findings.append(dependency_finding_to_evidence(dependency_item))

    if args.secret_findings and args.secret_findings.exists():
        secret_payload = load_json(args.secret_findings)
        secret_items = sorted(
            secret_payload.get("findings", []),
            key=lambda item: (
                -severity_rank(item.get("risk")),
                -numeric_confidence(item.get("confidence")),
                str(item.get("rule_id") or ""),
            ),
        )[: args.max_secret_findings]
        for secret_item in secret_items:
            auxiliary_secret_findings.append(secret_context_item(secret_item))
            if args.include_secret_findings_as_items:
                hid = secret_item.get("id")
                if not hid:
                    continue
                hypotheses[str(hid)] = secret_finding_to_hypothesis(secret_item)
                findings.append(secret_finding_to_evidence(secret_item))

    items: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for finding in findings:
        hypothesis_ids = finding.get("hypothesis_ids") or []
        if not hypothesis_ids:
            continue
        hid = str(hypothesis_ids[0])
        hypothesis = hypotheses.get(hid)
        if not hypothesis:
            continue

        source_refs = collect_locations(finding, hypothesis)
        windows: list[dict[str, Any]] = []
        seen_windows: set[tuple[str, int, int]] = set()

        for ref in source_refs:
            resolved = resolve_file(repo_root, ref.path)
            if not resolved:
                unresolved.append({"hypothesis_id": hid, "path": ref.path, "line": ref.line, "note": ref.note})
                continue
            window = source_window(resolved, repo_root, ref.line, args.context_lines, args.max_file_lines)
            key = (window["path"], window["start_line"], window["end_line"])
            if key in seen_windows:
                continue
            seen_windows.add(key)
            window["requested_line"] = ref.line
            window["note"] = ref.note
            windows.append(window)
            if len(windows) >= args.max_windows_per_finding:
                break

        items.append(
            {
                "hypothesis": hypothesis,
                "finding": {
                    "id": finding.get("id"),
                    "preliminary_status": finding.get("status"),
                    "risk": finding.get("risk"),
                    "confidence": finding.get("confidence"),
                    "reasoning_summary": finding.get("reasoning_summary"),
                    "tool_evidence_counts": {
                        name: len(values) if isinstance(values, list) else 0
                        for name, values in (finding.get("tool_evidence") or {}).items()
                    },
                },
                "playbook": CLASS_TO_PLAYBOOK.get(hypothesis.get("class"), "Universal Verdict Contract"),
                "validation_contract": {
                    "confirmed_requires": [
                        "attacker-reachable entrypoint",
                        "sensitive action reachable from that entrypoint",
                        "expected guard/invariant missing, bypassable, or ineffective",
                        "concrete security impact or business harm",
                        "source citations for the path and missing guard",
                    ],
                    "vulnerability_scope_rule": (
                        "This audit confirms exploitable vulnerabilities, not code-quality, "
                        "secure-coding-practice, or generic hardening findings. Missing "
                        "defense-in-depth, weak style, duplicate implementations, permissive "
                        "but non-exploitable config, placeholder-looking secrets, parser/queue "
                        "hardening gaps, or 'could become risky if misconfigured' observations "
                        "must not be marked confirmed unless source evidence shows a realistic "
                        "actor-triggered path to concrete security impact."
                    ),
                    "derived_finding_rule": (
                        "New issues discovered during validation are derived candidates. "
                        "Do not mark them confirmed or put them in the final confirmed report "
                        "unless the same contract is checked: attacker source, sink/action, "
                        "missing guard/sanitizer, and source citations for the full path."
                    ),
                    "injection_rule": (
                        "For SQL/query injection, raw SQL APIs or string interpolation alone "
                        "are suspicious patterns. Confirm only if attacker-controlled data can "
                        "alter query syntax/semantics and no parameterization, allowlist, "
                        "escaping, or strong type boundary makes it inert."
                    ),
                    "secret_rule": (
                        "For hardcoded secret matches, scanner output is discovery evidence. "
                        "Confirm only if source/context shows the value is an effective secret "
                        "or deployment credential and concrete impact exists. Placeholders, "
                        "samples, fixtures, local-only defaults, and inert test values are not "
                        "confirmed vulnerabilities."
                    ),
                    "false_positive_requires": [
                        "suspicious path exists or was reasonably checked",
                        "guard/invariant chain covers the sensitive action before execution",
                        "source citations for each important guard step",
                    ],
                    "default_when_uncertain": "needs_review",
                },
                "source_windows": windows,
            }
        )

    packet = {
        "schema": "graph-reasoning-code-audit/source-validation-packet-v1",
        "repo_root": str(repo_root),
        "auxiliary_context": {
            "dependency_findings": auxiliary_dependency_findings,
            "dependency_context_rule": (
                "Use these SCA signals to prioritize, explain exploitability, or request follow-up checks. "
                "Do not convert a version match into a source-code vulnerability verdict by itself."
            ),
            "secret_findings": auxiliary_secret_findings,
            "secret_context_rule": (
                "Use these secret scanner matches as discovery signals. Confirm hardcoded secret exposure "
                "only after checking whether the value is effective, runtime-used or deployable, and harmful. "
                "Do not confirm placeholders, samples, fixtures, or inert local defaults."
            ),
        },
        "items": items,
        "unresolved_locations": unresolved,
    }
    write_json(args.output, packet)

    if args.prompt_output:
        args.prompt_output.parent.mkdir(parents=True, exist_ok=True)
        args.prompt_output.write_text(
            build_prompt(args.output, "references/source_validation_playbooks.md"),
            encoding="utf-8",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
