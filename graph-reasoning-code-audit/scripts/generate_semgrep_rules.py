#!/usr/bin/env python3
"""Generate simple Semgrep rule stubs from hypotheses.json."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


TYPE_TO_TEMPLATE = {
    "idor": "taint",
    "auth_bypass": "guard",
    "vertical_privilege": "guard",
    "frontend_only_check": "guard",
    "alternate_entrypoint": "guard",
    "tenant_isolation_bypass": "guard",
    "role_confusion": "guard",
    "state_skip": "state",
    "state_reversal": "state",
    "repeated_transition": "state",
    "check_write_split": "state",
    "invariant_violation": "business",
    "replay": "business",
    "double_submit": "business",
    "business_constraint_missing": "business",
    "rate_limit_missing": "business",
    "economic_abuse": "business",
    "approval_bypass": "guard",
    "sql_injection": "taint",
    "nosql_injection": "taint",
    "command_injection": "taint",
    "template_injection": "taint",
    "xss": "taint",
    "open_redirect": "taint",
    "unsafe_eval": "taint",
    "ldap_xpath_injection": "taint",
    "sensitive_data_exposure": "guard",
    "overbroad_query": "guard",
    "logging_leak": "guard",
    "cache_leak": "guard",
    "debug_admin_exposure": "guard",
    "hardcoded_secret": "guard",
    "weak_crypto": "guard",
    "jwt_misuse": "guard",
    "session_fixation": "guard",
    "csrf": "guard",
    "password_reset_flaw": "guard",
    "ssrf": "taint",
    "path_traversal": "taint",
    "unsafe_file_upload": "taint",
    "unsafe_deserialization": "taint",
    "webhook_signature_missing": "guard",
    "xxe": "taint",
    "request_smuggling_proxy_trust": "guard",
    "race_condition": "state",
    "transaction_missing": "state",
    "resource_exhaustion": "business",
    "regex_dos": "business",
    "queue_job_abuse": "business",
}


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return normalized or "hypothesis"


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        return [item for item in data.get("hypotheses", []) if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def yaml_list(values: list[str], indent: int) -> list[str]:
    pad = " " * indent
    if not values:
        return [f"{pad}[]"]
    return [f"{pad}- {json.dumps(value)}" for value in values]


def targets_for(hypothesis: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("entrypoints", "sensitive_actions", "evidence_seed"):
        raw = hypothesis.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item:
                    values.append(item)
                elif isinstance(item, dict):
                    location = item.get("location") or item.get("path") or item.get("name")
                    if location:
                        values.append(str(location))
    return sorted(set(values))


def regex_for(hypothesis: dict[str, Any]) -> str:
    htype = str(hypothesis.get("type") or "")
    hclass = str(hypothesis.get("class") or "")
    by_type = {
        "auth_bypass": r"(?i)\b(authenticate|accountability|authorize|requireAdmin|canAccess|ForbiddenError)\b",
        "idor": r"(?i)\b(params|primaryKey|validateAccess|accountability|owner|tenant|permission)\b",
        "vertical_privilege": r"(?i)\b(admin|role|policy|permission|ForbiddenError|requireAdmin)\b",
        "frontend_only_check": r"(?i)\b(permission|role|admin|metadata|frontend|app_access)\b",
        "alternate_entrypoint": r"(?i)\b(router\.|accountability|validateAccess|processPayload|PermissionsService|ItemsService)\b",
        "tenant_isolation_bypass": r"(?i)\b(tenant|organization|workspace|accountability|policy|permission)\b",
        "role_confusion": r"(?i)\b(role|roles|policy|share|impersonat|accountability)\b",
        "state_skip": r"(?i)\b(status|state|stage|phase|transition|update|where)\b",
        "state_reversal": r"(?i)\b(status|state|stage|phase|previous|rollback|cancel)\b",
        "repeated_transition": r"(?i)\b(next_token|refresh|idempot|once|status|state|transaction|where)\b",
        "check_write_split": r"(?i)\b(validate|check|where|update|insert|transaction|lock)\b",
        "rate_limit_missing": r"(?i)\b(rate.?limit|consume|resetPassword|requestPasswordReset|login|limit)\b",
        "replay": r"(?i)\b(eventId|nonce|requestId|idempot|token|webhook|retry)\b",
        "double_submit": r"(?i)\b(create|submit|capture|charge|order|idempot|transaction)\b",
        "business_constraint_missing": r"(?i)\b(quota|limit|approval|payment|inventory|points|entitlement)\b",
        "economic_abuse": r"(?i)\b(price|amount|credit|coupon|discount|refund|balance)\b",
        "approval_bypass": r"(?i)\b(approve|approval|review|admin|maker|checker)\b",
        "template_injection": r"(?i)\b(render|tokenize|template|system_prompt|safeParse|args)\b",
        "unsafe_eval": r"(?i)\b(eval|Function|vm\.|script|expression)\b",
        "command_injection": r"(?i)\b(exec|spawn|execFile|shell|command)\b",
        "sql_injection": r"(?i)\b(raw|knex\.raw|query|whereRaw|select)\b",
        "nosql_injection": r"(?i)\b(\$where|\$regex|filter|query|selector)\b",
        "xss": r"(?i)\b(html|script|sanitize|escape|render|markup)\b",
        "open_redirect": r"(?i)\b(redirect|returnUrl|callback|url|Url)\b",
        "sensitive_data_exposure": r"(?i)\b(password|secret|token|payload|redact|logger|response)\b",
        "overbroad_query": r"(?i)\b(fields|limit:-?1|permissionCache|fetchAccountabilityCollectionAccess|payload)\b",
        "logging_leak": r"(?i)\b(logger|console|password|secret|token|payload)\b",
        "cache_leak": r"(?i)\b(cache|key|accountability|tenant|user|role)\b",
        "debug_admin_exposure": r"(?i)\b(debug|admin|introspection|system|development)\b",
        "hardcoded_secret": r"(?i)\b(secret|api.?key|password|private.?key|token)\b",
        "weak_crypto": r"(?i)\b(SECRET|jwt\.sign|jwt\.verify|random|crypto|cookie|session)\b",
        "jwt_misuse": r"(?i)\b(jwt|issuer|audience|verify|decode|sign)\b",
        "session_fixation": r"(?i)\b(session|refresh|cookie|next_token|token)\b",
        "csrf": r"(?i)\b(csrf|sameSite|cookie|origin|referer)\b",
        "password_reset_flaw": r"(?i)\b(resetPassword|requestPasswordReset|reset_url|token)\b",
        "ssrf": r"(?i)\b(fetch|request|axios|got|Url|url|hostname)\b",
        "path_traversal": r"(?i)\b(path|filename|readFile|writeFile|createReadStream|normalize)\b",
        "unsafe_file_upload": r"(?i)\b(upload|mime|filename|storage|write|type)\b",
        "unsafe_deserialization": r"(?i)\b(deserialize|parse|yaml|xml|pickle|load)\b",
        "webhook_signature_missing": r"(?i)\b(webhook|signature|secret|verifyAndParseWebhook|x-webhook-token|rawBody)\b",
        "xxe": r"(?i)\b(xml|doctype|entity|parser)\b",
        "request_smuggling_proxy_trust": r"(?i)\b(proxy|trust|forwarded|host|header)\b",
        "race_condition": r"(?i)\b(transaction|lock|where|update|insert|race|concurrent)\b",
        "transaction_missing": r"(?i)\b(transaction|knex|update|insert|delete|where)\b",
        "resource_exhaustion": r"(?i)\b(MAX_BATCH_MUTATION|trackMutations|limit|batch|queue|cache\.clear)\b",
        "regex_dos": r"(?i)\b(RegExp|regex|match|replace|parse)\b",
        "queue_job_abuse": r"(?i)\b(queue|job|worker|retry|schedule)\b",
    }
    by_class = {
        "A": r"(?i)\b(accountability|permission|admin|role|authorize|ForbiddenError)\b",
        "B": r"(?i)\b(status|state|transition|transaction|update)\b",
        "C": r"(?i)\b(limit|quota|idempot|approval|payment|inventory|rate)\b",
        "D": r"(?i)\b(render|eval|exec|raw|template|sanitize)\b",
        "E": r"(?i)\b(payload|fields|redact|cache|logger|export)\b",
        "F": r"(?i)\b(secret|jwt|session|cookie|crypto|token)\b",
        "G": r"(?i)\b(webhook|url|file|upload|signature|storage|parser)\b",
        "H": r"(?i)\b(transaction|lock|limit|batch|queue|cache|regex)\b",
    }
    return by_type.get(htype) or by_class.get(hclass) or r"(?i)\b(accountability|permission|validate|token|secret|query|update)\b"


def rule_for(hypothesis: dict[str, Any]) -> str:
    hid = str(hypothesis.get("id") or "H-000")
    htype = str(hypothesis.get("type") or "unknown")
    title = str(hypothesis.get("title") or htype)
    expected_guards = [str(item) for item in hypothesis.get("expected_guards", []) if item]
    target_values = targets_for(hypothesis)

    lines = [
        f"  - id: poc-{slug(hid)}-{slug(htype)}",
        "    languages: [generic]",
        "    severity: WARNING",
        f"    message: {json.dumps(title + ' (' + hid + ')')}",
        "    metadata:",
        f"      hypothesis_id: {json.dumps(hid)}",
        f"      hypothesis_type: {json.dumps(htype)}",
        f"      hypothesis_class: {json.dumps(str(hypothesis.get('class') or ''))}",
        "      expected_guards:",
        *yaml_list(expected_guards, 8),
        "      targets:",
        *yaml_list(target_values, 8),
        f"      evidence_kind: {json.dumps('keyword_signal')}",
        f"    pattern-regex: {json.dumps(regex_for(hypothesis))}",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hypotheses", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    hypotheses = load_hypotheses(args.hypotheses)
    content = ["rules:"]
    if hypotheses:
        content.extend(rule_for(item) for item in hypotheses)
    else:
        content.append("  []")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(content) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
