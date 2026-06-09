# Schemas

All generated JSON must be UTF-8, deterministic enough to diff, and use paths
relative to the audited repository when possible.

## graph_context.json

Produced by `scripts/normalize_graphify.py`.

```json
{
  "repo": {
    "name": "string",
    "root": "string"
  },
  "sources": {
    "graph_json": "string",
    "graph_report": "string"
  },
  "graphify_semantic_artifacts": {
    "semantic_dirs": [],
    "semantic_file_count": 0,
    "semantic_total_bytes": 0
  },
  "graphify_quality": {
    "has_semantic_artifacts": true,
    "semantic_file_count": 0,
    "hyperedge_count": 0,
    "inferred_or_ambiguous_edge_count": 0,
    "ast_only_likely": false,
    "warnings": []
  },
  "graphify_input_warnings": [
    {
      "kind": "node|hyperedge",
      "path": "string",
      "note": "string"
    }
  ],
  "nodes": [
    {
      "id": "string",
      "label": "string",
      "type": "file|symbol|doc|config|unknown",
      "path": "string|null",
      "score": 0,
      "metadata": {}
    }
  ],
  "edges": [
    {
      "source": "string",
      "target": "string",
      "type": "string",
      "metadata": {}
    }
  ],
  "hyperedges": [
    {
      "id": "string",
      "label": "string",
      "relation": "string",
      "nodes": [],
      "source_file": "string|null",
      "confidence": "string|null",
      "confidence_score": 0,
      "description": "string|null",
      "metadata": {}
    }
  ],
  "entrypoint_candidates": [],
  "sensitive_candidates": [],
  "core_paths": [],
  "report_summary": "string"
}
```

## semantic_model.json

Produced by the agent from `graph_context.json`, key source snippets, README,
API docs, schemas, routes, controllers, service code, and config.

```json
{
  "scope": {
    "repo": "string",
    "languages": [],
    "frameworks": []
  },
  "roles": [
    {
      "name": "string",
      "evidence": []
    }
  ],
  "resources": [
    {
      "name": "string",
      "owner_fields": [],
      "state_fields": [],
      "evidence": []
    }
  ],
  "ownership_rules": [
    {
      "id": "OR-001",
      "resource": "string",
      "rule": "string",
      "guards": [],
      "evidence": []
    }
  ],
  "states": [
    {
      "resource": "string",
      "field": "string",
      "values": [],
      "evidence": []
    }
  ],
  "transitions": [
    {
      "id": "TR-001",
      "resource": "string",
      "from": "string|unknown",
      "to": "string",
      "action": "string",
      "guards": [],
      "side_effects": [],
      "evidence": []
    }
  ],
  "guards": [
    {
      "name": "string",
      "kind": "authn|authz|ownership|state|invariant|rate_limit|idempotency|unknown",
      "location": "file:line or symbol",
      "evidence": []
    }
  ],
  "invariants": [
    {
      "id": "INV-001",
      "statement": "string",
      "resources": [],
      "evidence": []
    }
  ],
  "sensitive_actions": [
    {
      "id": "SA-001",
      "name": "string",
      "kind": "permission|state_transition|payment|inventory|points|quota|approval|data_change|unknown",
      "entrypoints": [],
      "sinks": [],
      "expected_guards": [],
      "evidence": []
    }
  ],
  "entrypoints": [
    {
      "id": "EP-001",
      "name": "string",
      "kind": "http|rpc|cli|queue|job|hook|unknown",
      "location": "file:line or symbol",
      "auth_context": "string|unknown",
      "evidence": []
    }
  ],
  "uncertainties": []
}
```

## hypothesis_backlog.json

Produced by the agent from `semantic_model.json` and optional
`dependency_findings.json`. This is a recall-oriented candidate pool, not a
verification verdict. Large repositories should usually have dozens of concrete
candidates here before the shortlist is selected.

```json
{
  "coverage_notes": "string",
  "uncertainties": [],
  "hypotheses": [
    {
      "id": "HB-001",
      "class": "A|B|C|D|E|F|G|H",
      "type": "auth_bypass|idor|vertical_privilege|frontend_only_check|alternate_entrypoint|tenant_isolation_bypass|role_confusion|state_skip|state_reversal|repeated_transition|check_write_split|invariant_violation|replay|double_submit|business_constraint_missing|rate_limit_missing|economic_abuse|approval_bypass|sql_injection|nosql_injection|command_injection|template_injection|xss|open_redirect|unsafe_eval|ldap_xpath_injection|sensitive_data_exposure|overbroad_query|logging_leak|cache_leak|debug_admin_exposure|hardcoded_secret|weak_crypto|jwt_misuse|session_fixation|csrf|password_reset_flaw|ssrf|path_traversal|unsafe_file_upload|unsafe_deserialization|webhook_signature_missing|xxe|request_smuggling_proxy_trust|race_condition|transaction_missing|resource_exhaustion|regex_dos|queue_job_abuse",
      "title": "string",
      "entrypoints": [],
      "resources": [],
      "sensitive_actions": [],
      "expected_guards": [],
      "suspected_gap": "string",
      "verification_plan": {
        "semgrep": [],
        "joern": [],
        "codeql": [],
        "sca": [],
        "config": []
      },
      "priority": "high|medium|low",
      "confidence_prior": "high|medium|low",
      "evidence_seed": [],
      "backlog_status": "candidate|selected|validated|merged|deferred|rejected",
      "granularity": "entrypoint|handler|service|sink|config",
      "coverage_area": "string",
      "selection_reason": "string",
      "validation_status": "unvalidated|confirmed|needs_review|false_positive|blocked",
      "validation_notes": "string"
    }
  ]
}
```

## hypotheses.json

Produced by the agent from `hypothesis_backlog.json`. This is the current
verification shortlist, not complete audit coverage.

```json
{
  "hypotheses": [
    {
      "id": "H-001",
      "backlog_ids": ["HB-001"],
      "class": "A|B|C|D|E|F|G|H",
      "type": "auth_bypass|idor|vertical_privilege|frontend_only_check|alternate_entrypoint|tenant_isolation_bypass|role_confusion|state_skip|state_reversal|repeated_transition|check_write_split|invariant_violation|replay|double_submit|business_constraint_missing|rate_limit_missing|economic_abuse|approval_bypass|sql_injection|nosql_injection|command_injection|template_injection|xss|open_redirect|unsafe_eval|ldap_xpath_injection|sensitive_data_exposure|overbroad_query|logging_leak|cache_leak|debug_admin_exposure|hardcoded_secret|weak_crypto|jwt_misuse|session_fixation|csrf|password_reset_flaw|ssrf|path_traversal|unsafe_file_upload|unsafe_deserialization|webhook_signature_missing|xxe|request_smuggling_proxy_trust|race_condition|transaction_missing|resource_exhaustion|regex_dos|queue_job_abuse",
      "title": "string",
      "entrypoints": [],
      "resources": [],
      "sensitive_actions": [],
      "expected_guards": [],
      "suspected_gap": "string",
      "verification_plan": {
        "semgrep": [],
        "joern": [],
        "codeql": [],
        "sca": [],
        "config": []
      },
      "priority": "high|medium|low",
      "confidence_prior": "high|medium|low",
      "evidence_seed": []
    }
  ]
}
```

## dependency_context.json

Produced by `scripts/collect_dependency_context.py`. This is inventory and
scanner-planning context for SCA review.

```json
{
  "schema": "graph-reasoning-code-audit/dependency-context-v1",
  "repo_root": "string",
  "manifests": [
    {
      "path": "package.json",
      "kind": "npm_manifest",
      "dependency_count": 0,
      "sample_dependencies": {
        "framework": "version"
      }
    }
  ],
  "frameworks": [
    {
      "name": "Next.js",
      "evidence": [
        {"path": "package.json", "dependency": "next", "version": "^1.0.0"}
      ]
    }
  ],
  "config_files": [
    {
      "path": ".env",
      "kind": "env",
      "env_summary": {
        "keys": [],
        "sensitive_key_names": [],
        "values_redacted": true
      }
    }
  ],
  "suggested_scanners": [
    {"tool": "osv-scanner", "command": "osv-scanner scan --recursive --format json --output .audit/osv-results.json <repo-root>"}
  ],
  "subagent_task": {}
}
```

## dependency_findings.json

Produced by the SCA subagent from
`dependency_context.json`, manifests, lockfiles, configs, and scanner outputs.
`scripts/convert_osv_results.py` can produce this schema from OSV-Scanner JSON.

```json
{
  "schema": "graph-reasoning-code-audit/dependency-findings-v1",
  "findings": [
    {
      "id": "D-001",
      "class": "SCA",
      "type": "known_vulnerable_dependency|vulnerable_framework_config|dangerous_config|vulnerable_feature_enabled",
      "package": "string|null",
      "version": "string|null",
      "ecosystem": "npm|PyPI|Go|Maven|Cargo|RubyGems|Packagist|NuGet|container|config|unknown",
      "advisory": {
        "id": "CVE/GHSA/OSV id or config rule id",
        "source": "osv|github_advisory|npm_audit|pip_audit|trivy|manual",
        "severity": "critical|high|medium|low|unknown",
        "affected_range": "string",
        "fixed_versions": []
      },
      "trigger_conditions": [],
      "usage_evidence": [
        {"path": "src/file.ts", "line": 10, "note": "string"}
      ],
      "config_evidence": [
        {"path": "config/file", "line": 10, "note": "string"}
      ],
      "status": "confirmed|needs_review|false_positive",
      "confidence": 0.0,
      "reasoning": "string",
      "fix_suggestion": "string"
    }
  ]
}
```

## secret_findings.json

Produced by `scripts/normalize_betterleaks.py` from Betterleaks JSON output, or
by adapting Gitleaks/TruffleHog output to the same schema.

```json
{
  "schema": "graph-reasoning-code-audit/secret-findings-v1",
  "source": {
    "tool": "betterleaks",
    "input": ".audit/betterleaks-git.json",
    "source_kind": "betterleaks-git|betterleaks-dir|gitleaks|trufflehog|rg"
  },
  "findings": [
    {
      "id": "S-001",
      "class": "F",
      "type": "hardcoded_secret",
      "tool": "betterleaks-git",
      "rule_id": "string",
      "description": "string",
      "risk": "critical|high|medium|low|unknown",
      "confidence": 0.0,
      "validation": {
        "status": "valid|invalid|unknown",
        "raw": {}
      },
      "locations": [
        {"path": "src/file.ts", "line": 10, "end_line": 10, "note": "string"}
      ],
      "secret": {
        "redacted": "abcd...wxyz",
        "match_redacted": "abcd...wxyz",
        "entropy": 0.0
      },
      "git_context": {
        "commit": "string",
        "author": "string|null",
        "email": "string|null",
        "date": "string|null",
        "message": "string|null"
      },
      "tags": [],
      "fingerprint": "string",
      "status": "needs_review|confirmed|false_positive",
      "reasoning": "string",
      "fix_suggestion": "string"
    }
  ],
  "summary": {
    "findings": 0,
    "valid": 0,
    "invalid": 0,
    "unknown": 0
  }
}
```

## evidence.json

Produced by `scripts/fuse_evidence.py`.

```json
{
  "findings": [
    {
      "id": "F-001",
      "hypothesis_ids": [],
      "class": "A|B|C|D|E|F|G|H",
      "type": "string",
      "title": "string",
      "status": "confirmed|needs_review|false_positive",
      "risk": "critical|high|medium|low|info",
      "confidence": 0.0,
      "locations": [],
      "call_paths": [],
      "tool_evidence": {
        "semgrep": [],
        "joern": [],
        "codeql": []
      },
      "reasoning_summary": "string",
      "fix_suggestion": "string"
    }
  ],
  "stats": {
    "hypotheses": 0,
    "confirmed": 0,
    "needs_review": 0,
    "false_positive": 0
  }
}
```

## guard_coverage.json

Produced by `scripts/assess_guard_coverage.py`.

```json
{
  "coverage": [
    {
      "hypothesis_id": "H-001",
      "title": "string",
      "coverage": "covered|partial|unknown",
      "reason": "string",
      "request_accountability": {
        "coverage": "covered|partial|unknown",
        "guard_chain": []
      },
      "covered_sinks": [
        {
          "sink_family": "string",
          "coverage": "covered|covered_if_accountability_present|partial|unknown",
          "guard_chain": []
        }
      ],
      "open_questions": [],
      "evidence": [
        {
          "path": "src/file.ts",
          "line": 10,
          "note": "string"
        }
      ]
    }
  ],
  "summary": {
    "assessed": 0,
    "covered": 0,
    "partial": 0,
    "unknown": 0,
    "confirmed_missing_guard": 0
  }
}
```

## source_validation_packet.json

Produced by `scripts/source_validate.py`. This is an evidence packet for LLM
source validation, not a vulnerability verdict.

```json
{
  "schema": "graph-reasoning-code-audit/source-validation-packet-v1",
  "repo_root": "string",
  "auxiliary_context": {
    "dependency_findings": [],
    "dependency_context_rule": "string",
    "secret_findings": [],
    "secret_context_rule": "string"
  },
  "items": [
    {
      "hypothesis": {},
      "finding": {
        "id": "F-001",
        "preliminary_status": "confirmed|needs_review|false_positive",
        "risk": "critical|high|medium|low|info",
        "confidence": 0.0,
        "reasoning_summary": "string",
        "tool_evidence_counts": {
          "semgrep": 0,
          "joern": 0,
          "codeql": 0
        }
      },
      "playbook": "A. Identity and Access Control|B. Workflow and State Machine|C. Business Logic and Abuse|D. Injection and Unsafe Interpretation|E. Data Exposure and Privacy|F. Secrets, Crypto, and Session Security|G. External Boundaries, Files, and Network|H. Concurrency, Consistency, and Resource Exhaustion",
      "validation_contract": {
        "confirmed_requires": [],
        "vulnerability_scope_rule": "string",
        "derived_finding_rule": "string",
        "injection_rule": "string",
        "secret_rule": "string",
        "false_positive_requires": [],
        "default_when_uncertain": "needs_review"
      },
      "source_windows": [
        {
          "path": "src/file.ts",
          "start_line": 1,
          "end_line": 20,
          "requested_line": 10,
          "note": "string",
          "lines": [
            {"line": 1, "text": "source text"}
          ]
        }
      ]
    }
  ],
  "unresolved_locations": []
}
```
