#!/usr/bin/env python3
"""Create semgrep_triage.json as the Phase 3 funnel barrier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    data = load_json(path, {"hypotheses": []})
    if isinstance(data, dict):
        return [item for item in data.get("hypotheses", []) if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def index_semgrep(payload: Any) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(payload, dict):
        return indexed
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        hid = item.get("hypothesis_id") or (item.get("metadata") or {}).get("hypothesis_id")
        if hid:
            indexed.setdefault(str(hid), []).append(item)
    return indexed


SEMANTIC_FRIENDLY_TYPES = {
    "auth_bypass",
    "idor",
    "vertical_privilege",
    "tenant_isolation_bypass",
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "template_injection",
    "xss",
    "open_redirect",
    "unsafe_eval",
    "ldap_xpath_injection",
    "sensitive_data_exposure",
    "overbroad_query",
    "logging_leak",
    "cache_leak",
    "debug_admin_exposure",
    "hardcoded_secret",
    "weak_crypto",
    "jwt_misuse",
    "session_fixation",
    "csrf",
    "password_reset_flaw",
    "ssrf",
    "path_traversal",
    "unsafe_file_upload",
    "unsafe_deserialization",
    "webhook_signature_missing",
    "xxe",
    "race_condition",
    "transaction_missing",
    "resource_exhaustion",
    "regex_dos",
}

SOURCE_FIRST_TYPES = {
    "missing_authentication_architecture",
    "missing_authorization_architecture",
    "missing_tenant_isolation_architecture",
    "missing_security_boundary",
    "missing_control_plane",
    "invariant_violation",
    "business_constraint_missing",
    "economic_abuse",
    "approval_bypass",
    "double_submit",
    "replay",
}

DATAFLOW_FRIENDLY_TYPES = {
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "template_injection",
    "xss",
    "open_redirect",
    "unsafe_eval",
    "ldap_xpath_injection",
    "sensitive_data_exposure",
    "overbroad_query",
    "logging_leak",
    "cache_leak",
    "debug_admin_exposure",
    "hardcoded_secret",
    "weak_crypto",
    "jwt_misuse",
    "session_fixation",
    "ssrf",
    "path_traversal",
    "unsafe_file_upload",
    "unsafe_deserialization",
    "webhook_signature_missing",
    "xxe",
    "race_condition",
    "transaction_missing",
    "resource_exhaustion",
    "regex_dos",
}


def suitability(hypothesis: dict[str, Any]) -> dict[str, str]:
    value = hypothesis.get("verification_suitability")
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    return {}


def needs_semantic_review(hypothesis: dict[str, Any], hits: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    hclass = str(hypothesis.get("class") or "")
    htype = str(hypothesis.get("type") or "")
    priority = str(hypothesis.get("priority") or hypothesis.get("confidence_prior") or "medium")
    declared = suitability(hypothesis)
    reasons: list[str] = []

    preferred_path = declared.get("preferred_path", "")
    codeql = declared.get("codeql", "")
    joern = declared.get("joern", "")
    semantic_declared = codeql in {"good", "limited"} or joern in {"good", "limited"}
    if hclass == "ARCH" or htype in SOURCE_FIRST_TYPES:
        return False, ["architecture_or_business_logic_requires_source_validation"]
    if preferred_path == "source_only" and not (semantic_declared and htype in DATAFLOW_FRIENDLY_TYPES):
        return False, ["verification_suitability_prefers_source_only"]
    if semantic_declared:
        reasons.append("declared_codeql_or_joern_suitable")
        if preferred_path == "source_only":
            reasons.append("semantic_suitability_overrides_source_only_for_dataflow_candidate")
        if hits:
            reasons.append("semgrep_has_locations")
        return True, reasons
    if codeql in {"poor", "not_applicable"} and joern in {"poor", "not_applicable"}:
        return False, ["declared_codeql_and_joern_not_suitable"]

    if htype in SEMANTIC_FRIENDLY_TYPES:
        reasons.append("type_is_semantic_verifier_candidate")
        if hits:
            reasons.append("semgrep_has_locations")
        if priority == "high":
            reasons.append("high_priority")
        return True, reasons
    if hclass in {"D", "E", "F", "G", "H"} and htype not in SOURCE_FIRST_TYPES:
        reasons.append("class_often_benefits_from_semantic_verifier")
        if hits:
            reasons.append("semgrep_has_locations")
        return True, reasons
    return False, ["source_validation_is_better_fit"]


def triage_item(hypothesis: dict[str, Any], hits: list[dict[str, Any]]) -> dict[str, Any]:
    hid = str(hypothesis.get("id") or "")
    hit_count = len(hits)
    semantic_review, reasons = needs_semantic_review(hypothesis, hits)
    declared = suitability(hypothesis)
    if hit_count and "semgrep_has_locations" not in reasons:
        reasons.append("semgrep_has_locations")
    return {
        "hypothesis_id": hid,
        "semgrep_hit_count": hit_count,
        "semantic_review": semantic_review,
        "source_validation": True,
        "triage": "semantic_review" if semantic_review else "source_validation_only",
        "verifier_suitability": {
            "semgrep": declared.get("semgrep", "unknown"),
            "codeql": declared.get("codeql", "unknown"),
            "joern": declared.get("joern", "unknown"),
            "preferred_path": declared.get("preferred_path", "inferred"),
        },
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--semgrep", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    hypotheses = load_hypotheses(args.hypotheses)
    semgrep = load_json(args.semgrep, {})
    indexed = index_semgrep(semgrep)
    items = [triage_item(item, indexed.get(str(item.get("id") or ""), [])) for item in hypotheses]
    semantic_ids = [item["hypothesis_id"] for item in items if item["semantic_review"]]
    payload = {
        "schema": "graph-reasoning-code-audit/semgrep-triage-v1",
        "hypothesis_count": len(hypotheses),
        "semantic_review_count": len(semantic_ids),
        "source_validation_count": len([item for item in items if item["source_validation"]]),
        "semantic_review_ids": semantic_ids,
        "items": items,
        "policy": "Semgrep is the first funnel stage. CodeQL/Joern receive only hypotheses suitable for semantic verification; architecture and source-only hypotheses go directly to source validation.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
