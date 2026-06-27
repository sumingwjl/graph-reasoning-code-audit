#!/usr/bin/env python3
"""Create Joern verification tasks from hypotheses, with optional passthrough results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        return [item for item in data.get("hypotheses", []) if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def tasks_for(hypothesis: dict[str, Any]) -> list[dict[str, Any]]:
    hid = str(hypothesis.get("id") or "")
    htype = str(hypothesis.get("type") or "")
    tasks = ["reachability"]
    if htype in {"idor", "auth_bypass", "vertical_privilege", "frontend_only_check", "alternate_entrypoint", "tenant_isolation_bypass", "role_confusion"}:
        tasks.extend(["guard_dominance", "dataflow"])
    if htype in {"state_skip", "state_reversal", "repeated_transition", "check_write_split"}:
        tasks.extend(["guard_dominance", "slice"])
    if htype in {"replay", "double_submit", "business_constraint_missing", "invariant_violation", "rate_limit_missing", "economic_abuse", "approval_bypass"}:
        tasks.extend(["dataflow", "slice"])
    if htype in {"sql_injection", "nosql_injection", "command_injection", "template_injection", "xss", "open_redirect", "unsafe_eval", "ldap_xpath_injection"}:
        tasks.extend(["dataflow", "slice"])
    if htype in {"sensitive_data_exposure", "overbroad_query", "logging_leak", "cache_leak", "debug_admin_exposure"}:
        tasks.extend(["dataflow", "slice"])
    if htype in {"hardcoded_secret", "weak_crypto", "jwt_misuse", "session_fixation", "csrf", "password_reset_flaw"}:
        tasks.extend(["guard_dominance", "dataflow"])
    if htype in {"ssrf", "path_traversal", "unsafe_file_upload", "unsafe_deserialization", "webhook_signature_missing", "xxe", "request_smuggling_proxy_trust"}:
        tasks.extend(["dataflow", "slice", "guard_dominance"])
    if htype in {"race_condition", "transaction_missing", "resource_exhaustion", "regex_dos", "queue_job_abuse"}:
        tasks.extend(["slice", "dataflow"])
    return [
        {
            "hypothesis_id": hid,
            "task": task,
            "entrypoints": hypothesis.get("entrypoints", []),
            "sensitive_actions": hypothesis.get("sensitive_actions", []),
            "expected_guards": hypothesis.get("expected_guards", []),
            "query_strategy": "full_cpg_single_hypothesis_first",
            "fallback_strategy": "focused_cpg_for_relevant_language_directory_or_module",
            "status": "planned",
        }
        for task in sorted(set(tasks))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--results",
        type=Path,
        help="Optional Joern JSON results to wrap as normalized evidence.",
    )
    parser.add_argument(
        "--status",
        choices=["planned", "skipped", "error"],
        default="planned",
        help="Status to use when no Joern CLI results are provided.",
    )
    parser.add_argument("--reason", default="", help="Reason for skipped/error Joern status.")
    parser.add_argument("--uncovered-language", action="append", default=[], help="Language left uncovered when Joern is skipped.")
    parser.add_argument("--uncovered-dir", action="append", default=[], help="Source directory left uncovered when Joern is skipped.")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.results and args.results.exists():
        raw = json.loads(args.results.read_text(encoding="utf-8-sig"))
        payload = {
            "tool": "joern",
            "status": "ok",
            "results": raw if isinstance(raw, list) else raw.get("results", []),
            "raw": raw,
        }
    else:
        hypotheses = load_hypotheses(args.hypotheses)
        planned = []
        for hypothesis in hypotheses:
            planned.extend(tasks_for(hypothesis))
        payload = {
            "tool": "joern",
            "status": args.status,
            **({"reason": args.reason} if args.reason else {}),
            **({"uncovered_languages": args.uncovered_language} if args.uncovered_language else {}),
            **({"uncovered_dirs": args.uncovered_dir} if args.uncovered_dir else {}),
            "results": planned,
        }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
