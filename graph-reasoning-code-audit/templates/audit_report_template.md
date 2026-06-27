# Code Audit Report

## Executive Summary

- Confirmed vulnerabilities: {{confirmed_vulnerability_count}}
- Needs review: {{needs_review_count}}
- False positives: {{false_positive_count}}
- Secret exposure findings: {{secret_confirmed_count}} confirmed / {{secret_needs_review_count}} needs review
- SCA findings: {{sca_high_priority_count}} high-priority advisories, reported separately

## Scope and Tool Coverage

| Area | Status | Notes |
| --- | --- | --- |
| Graphify | {{graphify_status}} | {{graphify_notes}} |
| Semgrep | {{semgrep_status}} | {{semgrep_notes}} |
| Joern CLI | {{joern_status}} | {{joern_notes}} |
| CodeQL | {{codeql_status}} | {{codeql_notes}} |
| Betterleaks | {{betterleaks_status}} | {{betterleaks_notes}} |
| OSV/SCA | {{sca_status}} | {{sca_notes}} |

## Confirmed Vulnerabilities

## Root Cause / Cross-Cutting Architecture Findings

Use this section when one ARCH hypothesis explains several concrete findings,
such as missing authentication architecture, missing authorization architecture,
missing tenant isolation, or a missing webhook/plugin/admin boundary. Keep the
source-grounded proof standard the same as for normal confirmed vulnerabilities.

### {{hypothesis_id}} [{{risk}}] {{architecture_root_cause_title}}

- Missing global control: {{authentication_authorization_tenant_or_boundary_control}}
- Affected entrypoint families: {{routes_handlers_jobs_or_integrations}}
- Representative concrete impacts: {{linked_hypothesis_ids_or_findings}}
- Source evidence: `{{path}}:{{line}}` - {{why_this_line_matters}}
- Why this is a root cause: {{short_explanation}}
- Required fix pattern: {{central_control_or_policy_architecture_to_add}}

Do not use this section for generic hardening. Use it only when source evidence
shows the control plane is absent or consistently bypassed.

### {{hypothesis_id}} [{{risk}}] {{short_vulnerability_title}}

**Impact**

{{concrete_attacker_impact}}

**Affected Code**

- `{{path}}:{{line}}` - {{why_this_line_matters}}

**Evidence Path**

```text
{{entrypoint_or_trigger}}
  -> {{controller_or_handler}}
  -> {{service_or_helper}}
  -> {{missing_or_ineffective_guard}}
  -> {{sensitive_sink_or_action}}
```

**Taint / Slice Path**

```text
status: available|not_available|not_applicable
source: {{attacker_controlled_field_or_trigger}}
propagation:
  -> {{step_1}}
  -> {{step_2}}
sink: {{sensitive_action_interpreter_or_state_write}}
missing guard: {{expected_guard_or_invariant}}
tool evidence: Semgrep|Joern|CodeQL|source-validation only
```

If no machine taint/slice path exists, write `status: not_available` and do not
claim tool confirmation.

**Minimal Reproduction / Payload**

```http
{{safe_minimal_request_command_state_transition_or_pseudocode}}
```

Use placeholders and redaction for real secrets, destructive values, tenant ids,
hostnames, and credentials. If a payload would be unsafe, destructive, or
deployment-specific, write:

`Not provided: {{reason}}. Verification steps: {{safe_steps}}.`

**Why Confirmed**

{{source_grounded_confirmation_reason}}

**Fix**

{{concrete_remediation_steps}}

## Needs Review

For each item, include exact missing evidence and next verification action. Do
not include exploit payloads for unconfirmed items.

### {{hypothesis_id}} [{{risk}}] {{title}}

- Missing evidence: {{missing_evidence}}
- Next verification action: {{next_verification_action}}
- Checked locations: {{checked_locations}}

## False Positives

For each item, include the guard/invariant chain that disproves the hypothesis.

### {{hypothesis_id}} {{title}}

- Disproving guard/invariant chain: {{guard_or_invariant_chain}}
- Checked locations: {{checked_locations}}

## Secret Exposure

Separate confirmed effective secrets from scanner-only matches. Never print real
secret values; use redacted values from `secret_report.md`.

## SCA Summary

Keep dependency advisories separate from source-code vulnerability conclusions.

## Deferred Backlog and Limitations

List unvalidated classes, skipped tools, partial language coverage, contaminated
graph inputs if any, and why those limitations affect conclusions.
