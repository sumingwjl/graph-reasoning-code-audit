# Source Validation Playbooks

Use this reference when validating fused evidence back against source code.
The deterministic scripts prepare evidence packets; the agent makes the final
source-grounded judgment.

Dependency/framework/configuration scanner results may appear in packet
`auxiliary_context`. Use those SCA signals to prioritize hypotheses, explain
exploitability, or request follow-up checks. Do not turn a dependency version
match into a source-code vulnerability verdict by itself.

Secret scanner results may also appear in `auxiliary_context`. Use those
matches as strong discovery signals, but validate whether the value is an
effective secret, placeholder, fixture, or false positive before calling it a
vulnerability.

## Universal Verdict Contract

For every hypothesis, produce exactly one status:

- `confirmed`: source evidence shows an attacker-reachable path to a sensitive action and the expected guard/invariant is missing, bypassable, or ineffective.
- `false_positive`: source evidence shows the suspicious path is covered by an effective guard/invariant before the sensitive action.
- `needs_review`: evidence is incomplete, ambiguous, deployment-dependent, or requires dynamic validation.

Never mark `confirmed` from naming patterns alone. Every verdict must cite specific source locations and explain the path or guard chain.

## Vulnerability Scope Gate

This skill reports exploitable vulnerabilities, not code-quality or hardening
findings. A confirmed vulnerability must satisfy all of these:

- attacker, low-trust user, tenant, plugin, webhook, uploaded file, network peer,
  or compromised dependency has a realistic way to trigger the path;
- the path crosses a security boundary or violates an intended business/security
  invariant;
- a sensitive action, interpreter sink, secret/session property, privileged
  resource, private data, financial/business effect, or availability boundary is
  affected;
- the relevant backend guard, sanitizer, authorization check, state check,
  quota, signature, allowlist, transaction, or invariant is missing, bypassable,
  or ineffective;
- concrete harm is explainable without relying on speculative future
  misconfiguration.

Treat the following as out of scope for confirmed vulnerability counts unless
the full gate above is met:

- missing defense-in-depth when an effective global, middleware, service, or
  storage guard dominates the sensitive action;
- permissive or nonideal configuration without credentials, cross-origin
  authority, exploitable browser context, or deployment evidence;
- hardcoded-looking placeholders or config fields without an exposed effective
  secret or reachable token/session impact;
- weak crypto helpers not used on credentials, sessions, signatures, or
  sensitive data;
- duplicate implementations, maintainability risks, code smells, missing
  annotations, and "could become risky if someone changes config";
- informational endpoints, schema/error detail exposure, parser hardening gaps,
  queue-depth concerns, retry/idempotency concerns, or leeway values unless the
  report shows a credible abuse path and impact.

These observations may be recorded as optional hardening notes or limitations,
but they must not be placed in the confirmed vulnerability section or included
in confirmed vulnerability totals.

## Derived Finding Gate

During source validation the agent may discover issues that were not formal
items in `hypotheses.json` / `source_validation_packet.json`. Treat these as
derived candidates, not final confirmed findings.

A derived candidate may be mentioned in `source_validation.md` only as
`needs_review` unless it is validated with the same contract as a normal
hypothesis:

- attacker-reachable entrypoint
- attacker-controlled source or violated invariant
- sensitive sink/action
- missing or ineffective guard/sanitizer
- source citations for the full path

If any element is missing, add the item to follow-up work or the next hypothesis
batch. Do not place it in the confirmed section of `audit_report.md`. Tool labels
such as `confirmed`, raw dangerous API names, or scanner severity do not satisfy
this gate by themselves.

## A. Identity and Access Control

Validate:

- Entrypoint reaches attacker-controlled or low-trust input.
- Principal context is created, propagated, and enforced backend-side.
- Ownership, tenancy, role, policy, or share checks dominate the sensitive action on all reachable paths.
- Alternate entrypoints use equivalent backend enforcement.

Confirm only when the sensitive action is reachable without the expected backend guard, or when a guard uses attacker-controlled data incorrectly.

False positive when the code shows a complete chain from entrypoint to sink with the expected guard before the sink.

## B. Workflow and State Machine

Validate:

- State field is authoritative, not cosmetic.
- Transition entrypoint is identified.
- Allowed from-states are checked before write.
- Write and side effects are atomic, locked, idempotent, or otherwise protected.
- Repeated transitions do not repeat one-time effects.

Confirm when a forbidden transition, repeated transition, or check/write race is source-reachable and lacks an effective state guard.

False positive when the transition enforces valid from-state and protects the write/side effects atomically or idempotently.

## C. Business Logic and Abuse

Validate:

- Invariant is stated in one sentence.
- Trust boundary and attacker-controlled fields are identified.
- Sensitive effect is identified.
- Validation, dedupe, idempotency, quota, approval, uniqueness, or transaction constraints are present on all routes.
- Alternate paths do not bypass the same business rule.

Confirm when source shows the sensitive effect can violate the invariant without an effective backend constraint.

False positive when the invariant is enforced by backend code or durable storage constraints before the sensitive effect.

## D. Injection and Unsafe Interpretation

Validate:

- Attacker input reaches a sink that interprets data as code, query, selector, expression, command, path, or markup.
- Sanitization, parameterization, allowlisting, or escaping is present and context-appropriate.
- Alternate sinks or helper functions do not reintroduce the same unsafe interpretation.

Confirm when attacker-controlled input reaches a dangerous interpreter without an effective sanitization or binding step.

False positive when the value is parameterized, escaped, allowlisted, or otherwise made inert in the relevant context.

### SQL Injection Confirmation Checklist

For `sql_injection`, `nosql_injection`, and ORM raw-query hypotheses,
`confirmed` requires all of the following:

- exact attacker-controlled source is identified;
- exact SQL/query interpreter sink is identified;
- source value is concatenated, interpolated, or otherwise inserted into query
  syntax;
- the inserted value remains capable of changing query syntax or semantics;
- no parameter binding, allowlist, escaping, or type boundary makes the value
  inert;
- source citations cover entrypoint -> source -> transformation -> sink.

Do not mark SQL injection confirmed from raw SQL APIs, ORM `Execute*` methods,
query-builder names, or string interpolation alone. These are
`suspicious_pattern` unless attacker-controlled query text is proven.

Strong type boundaries usually prevent SQL syntax injection. If the value is a
numeric type, boolean, enum, GUID parsed before the sink, or a database identity
field copied from trusted storage, do not mark confirmed unless the code shows a
way for the attacker to control raw query syntax anyway. Use `needs_review` or
`false_positive`, and record hardening recommendations separately from
vulnerability findings.

## E. Data Exposure and Privacy

Validate:

- Sensitive data is identified.
- The response/log/cache/export path is reachable from attacker-controlled input or trust boundary.
- Field-level filtering, redaction, authz, cache scoping, or debug gating is enforced.
- Alternate serialization or export paths do not bypass the same privacy rule.

Confirm when the code can return, log, cache, or export sensitive data across trust boundaries without an effective guard.

False positive when the sensitive data is filtered, redacted, scoped, or blocked before exposure.

## F. Secrets, Crypto, and Session Security

Validate:

- Secret, key, token, session, or reset flow is identified.
- Crypto, token validation, rotation, freshness, binding, or cookie protection is correct for the threat model.
- Sensitive secret material is not hardcoded, logged, or exposed.
- Alternate auth/session paths preserve the same security properties.

Confirm when secret handling, token validation, or session binding is source-weak in a way that directly affects attacker access.

False positive when the code uses the right cryptographic or session controls and the sensitive value is not exposed.

### Hardcoded Secret Confirmation Checklist

For Betterleaks, Gitleaks, TruffleHog, or keyword secret matches, `confirmed`
requires all of the following:

- exact secret location is identified and cited;
- the value is not only a placeholder, sample, test fixture, documentation
  value, generated fake, or intentionally inert local-development default;
- the value is committed to source, Git history, distributable artifacts, or a
  reachable deployment/config path;
- runtime code, deployment config, or service integration shows what the secret
  controls;
- concrete harm is stated, such as JWT/session forgery, cloud/API access,
  database access, private-key misuse, webhook abuse, admin access, or sensitive
  data access.

Validation from a scanner can raise confidence, but source/context validation
still needs to cite why the secret is effective and harmful. If only the string
looks secret-like, use `needs_review` or `false_positive`.

## G. External Boundaries, Files, and Network

Validate:

- External boundary is identified: file, URL, archive, upload, webhook, parser, object storage, email, proxy, or third-party service.
- User-controlled values reach the boundary sink.
- Allowlists, signature checks, path normalization, upload policy, parser hardening, or proxy trust rules are present.
- Alternate entrypoints do not bypass the same boundary controls.

Confirm when the boundary sink is attacker-controlled without adequate validation or signature/allowlist control.

False positive when the sink is constrained by path normalization, signature verification, allowlist, or safe parser settings.

## H. Concurrency, Consistency, and Resource Exhaustion

Validate:

- Contended resource, state, or quota is identified.
- Concurrent or repeated operations can reach a race, missing transaction, or resource exhaustion path.
- Locks, CAS, transactions, dedupe, rate limits, pagination limits, or bounds are present where needed.
- Alternate work paths do not bypass the same control.

Confirm when a race, retry, or unbounded input can violate the invariant or exhaust resources without an effective guard.

False positive when the path is bounded, transactional, locked, or otherwise resilient to the abuse pattern.

## Required Output Per Hypothesis

```json
{
  "hypothesis_id": "H-001",
  "status": "confirmed|false_positive|needs_review",
  "confidence": 0.0,
  "source_locations_checked": [
    {"path": "src/file.ts", "line": 10, "note": "why this line matters"}
  ],
  "scope_gate": {
    "actor_trigger": "present|missing|unclear",
    "security_boundary_or_invariant": "present|missing|unclear",
    "sensitive_action_or_asset": "present|missing|unclear",
    "missing_effective_control": "present|missing|unclear",
    "concrete_harm": "present|missing|unclear"
  },
  "attacker_path": ["entrypoint", "data/control flow step", "sink"],
  "evidence_path": ["entrypoint", "controller/handler", "service", "guard or missing guard", "sink/action"],
  "taint_or_slice_path": {
    "status": "available|not_available|not_applicable",
    "source": "attacker-controlled field or trigger",
    "propagation": ["step 1", "step 2"],
    "sink": "sensitive action/interpreter/state write",
    "missing_or_ineffective_guard": "guard name or reason"
  },
  "guard_or_invariant_chain": ["guard step 1", "guard step 2"],
  "minimal_reproduction": {
    "status": "provided|not_safe|not_applicable|needs_environment",
    "payload": "safe minimal request/body/steps, with destructive values redacted or replaced",
    "notes": "preconditions and safety limits"
  },
  "reasoning": "short source-grounded explanation",
  "residual_questions": []
}
```

For confirmed items, fill `evidence_path` and either `taint_or_slice_path` or a
clear explanation that taint/slice evidence is not applicable. Provide a minimal
safe reproduction or payload when doing so does not expose real secrets, enable
destructive abuse, or require unknown deployment credentials. Redact real
tokens, keys, hostnames, tenant ids, and destructive values.
