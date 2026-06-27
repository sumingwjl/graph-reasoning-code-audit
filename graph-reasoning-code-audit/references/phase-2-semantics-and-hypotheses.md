# Phase 2: Semantics and Hypotheses

Use this phase to produce the security semantic model, broad hypothesis backlog,
and current verification shortlist.

Read `schemas.md` and `hypothesis_types.md` before writing JSON.

## Security Semantic Model

Create `.audit/semantic_model.json` from:

- `.audit/graph_context.json`
- graphify report summary
- graphify code graph nodes, code edges, core paths, entrypoint candidates,
  sensitive candidates, and high-value communities
- graphify hyperedges when present
- key source snippets
- README, API docs, schemas, route/controller/service/model/config files
- optional dependency findings as context
- optional secret findings as context, especially validated Betterleaks matches

Extract:

- roles
- resources
- ownership rules
- states
- transitions
- guards
- invariants
- sensitive actions
- entrypoints
- uncertainties

Each non-obvious role, resource, guard, sensitive action, and entrypoint should
include evidence with a file path, line/symbol when available, or graph node id.
Use bounded source reads: start from `graph_context.json.core_paths`,
entrypoint candidates, sensitive candidates, route/controller/service/config
files, and README/API docs. Do not browse the entire repository when graphify
already identified a focused candidate set.

Do not conclude that a vulnerability exists in this step. Capture uncertainty
explicitly.

Before writing the backlog, perform a global-control review from the semantic
model:

- authentication architecture: where principal/session/token identity is
  created and enforced;
- authorization architecture: where ownership, tenancy, role, permission, or
  policy checks are enforced;
- tenant/workspace/account isolation;
- security boundaries for admin, webhook, plugin, upload, queue, file, network,
  and third-party integration paths;
- shared guard/control-plane mechanisms such as middleware, interceptors,
  decorators, service guards, policy engines, state machines, quotas, approvals,
  transactions, and audit controls.

If the semantic model shows a system-level control is absent or consistently
unused, create an ARCH backlog candidate. Do not hide that root cause by only
creating separate endpoint-level A-H candidates.

## Hypothesis Backlog

Create `.audit/hypothesis_backlog.json` from `semantic_model.json`.

This is the broad discovery layer. Favor recall over precision. For a large
framework or monorepo, expect roughly 40-80 concrete candidates unless the audit
scope is explicitly narrow.

This backlog is vulnerability-focused. A candidate should describe:

- an actor or low-trust trigger;
- a reachable entrypoint or operation;
- an affected asset, security boundary, or business invariant;
- the missing or bypassable guard/invariant being tested;
- concrete impact if true.

Do not create backlog items that are only secure-coding style, maintainability,
defense-in-depth, or generic hardening observations. If a weak practice has no
current attacker path or concrete harm, record it only in `uncertainties` or
defer it as hardening context outside the vulnerability backlog.

Backlog requirements:

- Cover all A-H classes when relevant, and include ARCH when a system-level
  missing control explains multiple concrete candidates.
- Include candidates across major entrypoint families: REST, GraphQL,
  WebSocket/realtime, auth/session, file/upload/assets, extension/plugin,
  webhook/callback, queue/job/flow, import/export, admin/config, cache.
- Keep each candidate concrete: name file paths, routes, handlers, service
  methods, resources, sensitive actions, and expected guards.
- Include expected impact in exploit terms, such as unauthorized read/write,
  privilege escalation, account/session compromise, injection, SSRF, sensitive
  data exposure, harmful business invariant violation, or credible resource
  exhaustion.
- For hardcoded secret candidates, anchor the hypothesis to
  `secret_findings.json` and state what the secret controls, whether runtime
  code appears to use it, and the concrete impact if it is effective.
- Record low-confidence candidates instead of silently dropping them.
- Keep generated audit-report text out of the evidence seed.
- Set `backlog_status: candidate` and `validation_status: unvalidated`.
- If fewer than 30 candidates are produced for a large repo, explain why in
  `coverage_notes` or `uncertainties`.
- Every selected candidate should cite at least one concrete evidence seed from
  `semantic_model.json`, graph context, scanner context, or a source path. Do
  not invent candidates from generic framework checklists alone.
- Keep a coverage matrix in `coverage_notes`: which ARCH/A-H classes were
  covered, which were intentionally deferred, and why.

Do not use words like `confirmed`, `proven`, or `finding` for backlog items.
Use `candidate`, `hypothesis`, `suspected_gap`, and `needs verification`.

## Verification Shortlist

Create `.audit/hypotheses.json` from `hypothesis_backlog.json`.

This is one verification batch, not complete audit coverage. Usually select
10-20 items per pass.

Selection rules:

- Prefer concrete handler/service/sink hypotheses over broad subsystem concerns,
  except when an ARCH root-cause hypothesis explains several concrete paths and
  has direct source/semantic-model evidence.
- If backend-sensitive entrypoints exist and the semantic model shows no
  authentication or authorization architecture, shortlist one root-cause
  hypothesis before endpoint-specific derivatives. Use `H-000` only when the
  root cause is audit-wide and intentionally first in the batch.
- Prefer candidates with plausible exploitability and user/security impact over
  best-practice gaps.
- Preserve traceability with `backlog_ids`.
- Split broad backlog items into multiple specific shortlisted hypotheses when
  needed, but keep the root-cause hypothesis when the split items share the same
  missing global control.
- Do not shortlist items whose only claim is missing annotations, permissive
  defaults, duplicated auth helpers, weak operational hygiene, or lack of
  parser/queue hardening unless the candidate also states a reachable exploit
  path and concrete harm.
- Mark selected backlog items as `selected`.
- Do not call the shortlist "findings".
- Do not write `confirmed gap` or similar verdict wording before source
  validation.

For each shortlisted hypothesis, set `verification_suitability`:

- `semgrep`: `good|limited|poor`
- `codeql`: `good|limited|poor|not_applicable`
- `joern`: `good|limited|poor|not_applicable`
- `source`: usually `required`
- `preferred_path`: `semantic_then_source|source_only|semgrep_then_source`
- `rationale`: one sentence

Use `source_only` for ARCH root causes, business/workflow logic that requires
whole-program reasoning by source inspection, or hypotheses where CodeQL/Joern
cannot plausibly prove the missing control. Do not force CodeQL/Joern to run
just to discover the hypothesis is not suitable.

Use SCA findings only as auxiliary context. A vulnerable dependency may raise
priority or suggest a query, but it should not create a source-code hypothesis
without source anchors.

Use secret findings differently from SCA: high-confidence Betterleaks matches
may create F-class secret-exposure hypotheses when they have source locations.
Still do not call them confirmed until source/context validation distinguishes
real secrets from placeholders, fixtures, and false positives.

## Quality Gate

Before moving to verification:

- JSON must parse.
- `hypothesis_backlog.json` should include `coverage_notes`, `uncertainties`,
  and candidates across relevant ARCH/A-H classes.
- `hypotheses.json` must have `backlog_ids` for every item.
- `hypotheses.json` must include `verification_suitability` for every item.
- No item should be marked confirmed.
- If `graph_context.json` has input warnings, discard these artifacts and rerun
  graphify on a clean corpus.
- If `graph_context.json.graphify_code_quality` reports missing code nodes,
  code edges, or structural code edges, do not run a normal hypothesis pass
  unless the user explicitly accepts degraded graph context.
- Do not treat `graphify_quality.ast_only_likely` as degraded by itself. AST/code
  graph mode is the recommended default for code audit.

## Verification Checkpoint

After `hypothesis_backlog.json` and `hypotheses.json` are written and validated,
stop before Phase 3. This is a hard user checkpoint.

Report concisely:

- completed work in Phase 0-2;
- graphify mode, code graph quality, degraded context, skipped tools, or corpus
  filtering notes;
- SCA and secret scan status;
- backlog candidate count and current shortlist count;
- main hypothesis classes/themes in the current batch;
- what Phase 3 will do next: Semgrep first, then `semgrep_triage.json`, then
  exactly one selected semantic verifier, Joern or CodeQL, only for triaged
  targets;
- what Phase 4 source validation will do after evidence is fused.

Ask the user to choose both execution modes:

- Phase 3 tool verification:
  - `parallel`: use subagents inside each funnel stage. Semgrep must finish
    and `semgrep_triage.json` must be written before Joern or CodeQL starts.
  - `sequential`: keep Phase 3 in the main agent/session. This is simpler but
    uses more main-agent context.
- Phase 4 source validation:
  - `parallel`: after packet generation, split hypotheses into disjoint worker
    batches of one to three hypotheses each.
  - `sequential`: keep source validation in the main agent/session.

Do not choose silently for the user. Do not run Semgrep, Joern, or CodeQL until
both choices are recorded:

```bash
python -m orchestrator.audit_flow approve-verification \
  --repo /path/to/repo \
  --tool-mode parallel \
  --source-mode parallel \
  --by "user" \
  --progress-summary "Phase 0-2 complete; N backlog candidates and M shortlisted hypotheses are ready." \
  --next-steps "Run Semgrep first, write semgrep_triage.json, run one selected semantic verifier only for triaged targets, then fuse evidence and validate source according to the selected source-validation mode."
```
