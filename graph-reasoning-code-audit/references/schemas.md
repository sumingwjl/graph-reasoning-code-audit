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
  "graphify_code_quality": {
    "has_code_graph": true,
    "has_code_edges": true,
    "has_structural_code_edges": true,
    "code_node_count": 0,
    "code_file_count": 0,
    "code_edge_count": 0,
    "structural_code_edge_count": 0,
    "relation_counts": {},
    "warnings": []
  },
  "graphify_quality": {
    "has_code_graph": true,
    "has_code_edges": true,
    "has_structural_code_edges": true,
    "code_node_count": 0,
    "code_file_count": 0,
    "code_edge_count": 0,
    "structural_code_edge_count": 0,
    "has_semantic_artifacts": true,
    "has_raw_semantic_artifacts": true,
    "has_semantic_graph_signals": true,
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

Rules:

- `graphify_code_quality` is the Phase 0B gate for code audit.
- `graphify_quality.ast_only_likely` is informational. It is normal when the
  approved Graphify mode is `ast`.
- `graphify_semantic_artifacts` and `hyperedges` are optional for code-only
  audit. They are expected only when the user selected `deep` or reused an
  existing graph that includes non-code semantic extraction.

## preflight_approval.json

Produced by `python -m orchestrator.audit_flow approve-preflight` after the
main agent reports tool availability and asks which Graphify mode to use.

```json
{
  "schema": "graph-reasoning-code-audit/preflight-approval-v1",
  "status": "approved",
  "approved_by": "user",
  "note": "string",
  "approved_at": "2026-01-01T00:00:00+00:00",
  "tool_status": ".audit/tool_status.json",
  "graphify_mode": "ast|deep|existing",
  "graphify_mode_reason": "string"
}
```

Rules:

- `ast` is the recommended default for code audit.
- `deep` means the user approved including security-relevant non-code files.
- `existing` means Phase 0B should reuse and normalize an existing graphify
  output.

## graphify_mode.json

Produced together with `preflight_approval.json` for convenient Phase 0B reads.

```json
{
  "schema": "graph-reasoning-code-audit/graphify-mode-v1",
  "status": "approved",
  "mode": "ast|deep|existing",
  "reason": "string",
  "approved_by": "user",
  "approved_at": "2026-01-01T00:00:00+00:00",
  "preflight_approval": ".audit/preflight_approval.json"
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
      "class": "ARCH|A|B|C|D|E|F|G|H",
      "type": "missing_authentication_architecture|missing_authorization_architecture|missing_tenant_isolation_architecture|missing_security_boundary|missing_control_plane|auth_bypass|idor|vertical_privilege|frontend_only_check|alternate_entrypoint|tenant_isolation_bypass|role_confusion|state_skip|state_reversal|repeated_transition|check_write_split|invariant_violation|replay|double_submit|business_constraint_missing|rate_limit_missing|economic_abuse|approval_bypass|sql_injection|nosql_injection|command_injection|template_injection|xss|open_redirect|unsafe_eval|ldap_xpath_injection|sensitive_data_exposure|overbroad_query|logging_leak|cache_leak|debug_admin_exposure|hardcoded_secret|weak_crypto|jwt_misuse|session_fixation|csrf|password_reset_flaw|ssrf|path_traversal|unsafe_file_upload|unsafe_deserialization|webhook_signature_missing|xxe|request_smuggling_proxy_trust|race_condition|transaction_missing|resource_exhaustion|regex_dos|queue_job_abuse",
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
      "verification_suitability": {
        "semgrep": "good|limited|poor",
        "codeql": "good|limited|poor|not_applicable",
        "joern": "good|limited|poor|not_applicable",
        "source": "required",
        "preferred_path": "semantic_then_source|source_only|semgrep_then_source",
        "rationale": "string"
      },
      "priority": "high|medium|low",
      "confidence_prior": "high|medium|low",
      "evidence_seed": [],
      "backlog_status": "candidate|selected|validated|merged|deferred|rejected",
      "granularity": "architecture|system|root_cause|entrypoint|handler|service|sink|config",
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
      "class": "ARCH|A|B|C|D|E|F|G|H",
      "type": "missing_authentication_architecture|missing_authorization_architecture|missing_tenant_isolation_architecture|missing_security_boundary|missing_control_plane|auth_bypass|idor|vertical_privilege|frontend_only_check|alternate_entrypoint|tenant_isolation_bypass|role_confusion|state_skip|state_reversal|repeated_transition|check_write_split|invariant_violation|replay|double_submit|business_constraint_missing|rate_limit_missing|economic_abuse|approval_bypass|sql_injection|nosql_injection|command_injection|template_injection|xss|open_redirect|unsafe_eval|ldap_xpath_injection|sensitive_data_exposure|overbroad_query|logging_leak|cache_leak|debug_admin_exposure|hardcoded_secret|weak_crypto|jwt_misuse|session_fixation|csrf|password_reset_flaw|ssrf|path_traversal|unsafe_file_upload|unsafe_deserialization|webhook_signature_missing|xxe|request_smuggling_proxy_trust|race_condition|transaction_missing|resource_exhaustion|regex_dos|queue_job_abuse",
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
      "verification_suitability": {
        "semgrep": "good|limited|poor",
        "codeql": "good|limited|poor|not_applicable",
        "joern": "good|limited|poor|not_applicable",
        "source": "required",
        "preferred_path": "semantic_then_source|source_only|semgrep_then_source",
        "rationale": "string"
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
  "is_git_repo": false,
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
    {
      "tool": "osv-scanner",
      "mode": "manifest_or_lockfile",
      "command": "osv-scanner scan --lockfile=path/to/manifest-or-lockfile --format json --output .audit/osv-results.json",
      "reason": "Prefer manifest/lockfile scanning for ZIP or non-Git repositories."
    },
    {
      "tool": "osv-scanner",
      "mode": "recursive",
      "command": "osv-scanner scan --recursive --format json --output .audit/osv-results.json <repo-root>",
      "reason": "Fallback broad scan; gitignore warnings are not failure if JSON results exist."
    }
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

## semgrep_triage.json

Produced by `scripts/triage_semgrep.py` after Semgrep completes and before
Joern or CodeQL starts. This is the Phase 3 funnel barrier.

```json
{
  "schema": "graph-reasoning-code-audit/semgrep-triage-v1",
  "hypothesis_count": 0,
  "semantic_review_count": 0,
  "source_validation_count": 0,
  "semantic_review_ids": ["H-001"],
  "items": [
    {
      "hypothesis_id": "H-001",
      "semgrep_hit_count": 0,
      "semantic_review": true,
      "source_validation": true,
      "triage": "semantic_review|source_validation_only",
      "verifier_suitability": {
        "semgrep": "good|limited|poor|unknown",
        "codeql": "good|limited|poor|not_applicable|unknown",
        "joern": "good|limited|poor|not_applicable|unknown",
        "preferred_path": "semantic_then_source|source_only|semgrep_then_source|inferred"
      },
      "reasons": []
    }
  ],
  "policy": "string"
}
```

Rules:

- `semgrep_triage.json` must exist before Joern or CodeQL starts.
- `semantic_review_ids` are the only default targets for Joern or CodeQL. They
  represent semantic-verifier suitability, not severity.
- ARCH/source-only hypotheses should have `triage: source_validation_only` even
  when high priority.
- `source_validation` remains true for the current shortlist unless the user
  explicitly narrows scope.

## semantic_verifier_depth_plan.json

Produced after `semgrep_triage.json` and
`semantic_verifier_selection.json`, before CodeQL or Joern runs targeted
hypothesis checks. Standard CodeQL packs and Joern querydb runs are breadth
coverage only; this plan records hypothesis-depth work.

```json
{
  "schema": "graph-reasoning-code-audit/semantic-verifier-depth-plan-v1",
  "selected_verifier": "codeql|joern",
  "breadth_coverage": {
    "enabled": true,
    "mode": "full_cpg_first|standard_packs_first",
    "commands": ["string"],
    "result_paths": ["string"],
    "fallback_policy": "string"
  },
  "semantic_review_ids": ["H-001"],
  "tasks": [
    {
      "hypothesis_id": "H-001",
      "query_intent": "string",
      "query_kind": "codeql_custom|codeql_standard_mapped|joern_structural|joern_dataflow|joern_slice|manual_tool_gap",
      "source_symbols": [],
      "sink_symbols": [],
      "guard_symbols": [],
      "expected_result_path": ".audit/tool-work/codeql/results/H-001.sarif",
      "status": "planned"
    }
  ]
}
```

Rules:

- `tasks` must cover every id in `semgrep_triage.json.semantic_review_ids`.
- Each task is for one hypothesis. Do not use one broad all-hypotheses query as
  a substitute.
- Breadth coverage may be recorded, but it does not satisfy depth validation.

## semantic_verifier_depth_results.json

Produced after the selected semantic verifier attempts targeted checks for
`semantic_review_ids`.

```json
{
  "schema": "graph-reasoning-code-audit/semantic-verifier-depth-results-v1",
  "selected_verifier": "codeql|joern",
  "coverage_status": "depth_complete|partial|breadth_only",
  "breadth_coverage": {
    "status": "completed|degraded|skipped",
    "commands_run": ["string"],
    "result_paths": ["string"],
    "limitations": []
  },
  "results": [
    {
      "hypothesis_id": "H-001",
      "coverage_mode": "depth",
      "query_intent": "string",
      "query_kind": "codeql_custom|codeql_standard_mapped|joern_structural|joern_dataflow|joern_slice|manual_tool_gap",
      "query_file": ".audit/tool-work/codeql/queries/H-001.ql",
      "result_path": ".audit/tool-work/codeql/results/H-001.sarif",
      "status": "hit|miss|error|skipped",
      "locations": [],
      "paths": [],
      "source_symbols": [],
      "sink_symbols": [],
      "guard_symbols": [],
      "limitations": []
    }
  ]
}
```

Rules:

- `results` must cover every id in `semgrep_triage.json.semantic_review_ids`,
  unless `.audit/skips/semantic_verifier_depth.json` marks the uncovered ids as
  degraded.
- Every result must set `coverage_mode` to `depth`.
- `breadth_coverage.status` is required so broad CodeQL/Joern coverage is not
  silently omitted.
- `error` and `skipped` results must include `limitations`.
- `coverage_status: breadth_only` is a degradation marker, not a valid complete
  P3 semantic-verifier result by itself.
- If `.audit/skips/semantic_verifier_depth.json` exists, `coverage_status` must
  not be `depth_complete`.
- A hypothesis id must not appear in both `results` and
  `skips/semantic_verifier_depth.json.uncovered`.

## skips/semantic_verifier_depth.json

Produced when the selected CodeQL or Joern verifier only completed breadth
coverage, or could not run targeted per-hypothesis checks.

```json
{
  "tool": "codeql|joern",
  "status": "degraded",
  "reason": "standard packs/querydb ran, but no targeted hypothesis-depth queries completed",
  "uncovered": ["H-001"],
  "created_at": "2026-01-01T00:00:00+00:00"
}
```

This creates a hard user checkpoint. The main agent must immediately report the
degradation and wait for the user's decision before evidence fusion or Phase 4.
Do not continue by only mentioning the gap in the phase summary.

## semantic_verifier_depth_approval.json

Produced by `python -m orchestrator.audit_flow approve-semantic-depth-degradation`
after the user reviews degraded CodeQL/Joern hypothesis-depth coverage.

```json
{
  "schema": "graph-reasoning-code-audit/semantic-depth-degradation-approval-v1",
  "status": "approved",
  "decision": "continue|retry|switch|narrow",
  "approved_by": "user",
  "approved_at": "2026-01-01T00:00:00+00:00",
  "reported_to_user": true,
  "degradation_record": ".audit/skips/semantic_verifier_depth.json",
  "summary": "string",
  "next_steps": "string",
  "note": "string"
}
```

Rules:

- Required when `.audit/skips/semantic_verifier_depth.json` exists.
- `decision=continue` allows evidence fusion and Phase 4 to proceed with the
  semantic-verifier gap visible.
- `decision=retry`, `switch`, or `narrow` means the agent must perform the
  approved action before continuing.

## evidence.json

Produced by `scripts/fuse_evidence.py` after `semgrep_triage.json` and the
selected semantic verifier output exist or are explicitly skipped.

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

## verification_checkpoint.json

Produced by `python -m orchestrator.audit_flow approve-verification` after the
main agent reports Phase 0-2 progress and the user chooses how Phase 3 tool
verification and Phase 4 source validation should run.

```json
{
  "schema": "graph-reasoning-code-audit/verification-checkpoint-v1",
  "status": "approved",
  "approved_by": "user",
  "approved_at": "2026-01-01T00:00:00+00:00",
  "reported_to_user": true,
  "user_choice_recorded": true,
  "tool_verification_mode": "parallel|sequential",
  "source_validation_mode": "parallel|sequential",
  "verification_mode": "parallel|sequential",
  "progress_summary": "string",
  "next_steps": "string",
  "note": "string"
}
```

Rules:

- `tool_verification_mode` must be `parallel` or `sequential`.
- `source_validation_mode` must be `parallel` or `sequential`.
- `verification_mode` is a backward-compatible alias for
  `tool_verification_mode`.
- `reported_to_user` and `user_choice_recorded` must be true.
- The checkpoint must exist before Phase 3 evidence or Phase 4 source
  validation is considered valid.
- If `tool_verification_mode=parallel`, Semgrep and the selected semantic
  verifier may run in separate workers with disjoint output files.
- If `tool_verification_mode=sequential`, Phase 3 verification stays in the
  main agent/session.
- If `source_validation_mode=parallel`, Phase 4 may use source-validation
  workers with one to three hypotheses each and disjoint part files.
- If `source_validation_mode=sequential`, Phase 4 source validation stays in
  the main agent/session.

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

## source_validation_dispatch.json

Produced by `python -m orchestrator.audit_flow plan-source-validation`. This is
the Phase 4B worker dispatch plan. It prevents parallel workers from writing the
same aggregate file.

```json
{
  "schema": "graph-reasoning-code-audit/source-validation-dispatch-v1",
  "created_at": "2026-01-01T00:00:00+00:00",
  "repo_root": "string",
  "hypothesis_count": 6,
  "batch_size": 3,
  "parallel_requested": true,
  "parallel_required": true,
  "write_policy": {
    "aggregate_owner": "main-agent",
    "aggregate_output": ".audit/source_validation.md",
    "worker_outputs_dir": ".audit/source-validation-parts/",
    "worker_work_dir_root": ".audit/source-validation-work/",
    "worker_may_write_aggregate": false
  },
  "batches": [
    {
      "batch_id": "batch-001",
      "hypothesis_ids": ["H-001", "H-002", "H-003"],
      "worker_output": ".audit/source-validation-parts/batch-001.md",
      "worker_work_dir": ".audit/source-validation-work/batch-001/",
      "status": "pending"
    }
  ]
}
```

Rules:

- `batches` must be an array.
- Each batch must include `batch_id`, `hypothesis_ids`, `worker_output`,
  `worker_work_dir`, and `status`.
- `hypothesis_ids` must be disjoint across batches.
- Each batch should contain one to three hypothesis ids.
- Each completed batch part must include a `## Worker Metadata` section naming
  the executor, batch id, assigned ids, worker work dir, and files checked.
- `worker_output` must be under `.audit/source-validation-parts/`.
- `worker_work_dir` must be under `.audit/source-validation-work/` and unique
  to the batch id.
- Workers may write scratch files only under their assigned `worker_work_dir`.
- `write_policy.worker_may_write_aggregate` must be `false`.
- `parallel_requested` means the user selected `source_validation_mode=parallel`
  at Phase 2C.
- `parallel_required` must stay `true` when the user selected parallel mode. If
  subagents are unavailable, write `skips/source_validation_subagents.json`
  before direct main-agent fallback.
- Only the main agent writes `.audit/source_validation.md`.
