# Phase 2: Semantics and Hypotheses

Use this phase to produce the security semantic model, broad hypothesis backlog,
and current verification shortlist.

Read `schemas.md` and `hypothesis_types.md` before writing JSON.

## Security Semantic Model

Create `.audit/semantic_model.json` from:

- `.audit/graph_context.json`
- graphify report summary
- graphify hyperedges and high-value communities
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

Do not conclude that a vulnerability exists in this step. Capture uncertainty
explicitly.

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

- Cover all A-H classes when relevant.
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

Do not use words like `confirmed`, `proven`, or `finding` for backlog items.
Use `candidate`, `hypothesis`, `suspected_gap`, and `needs verification`.

## Verification Shortlist

Create `.audit/hypotheses.json` from `hypothesis_backlog.json`.

This is one verification batch, not complete audit coverage. Usually select
10-20 items per pass.

Selection rules:

- Prefer concrete handler/service/sink hypotheses over broad subsystem concerns.
- Prefer candidates with plausible exploitability and user/security impact over
  best-practice gaps.
- Preserve traceability with `backlog_ids`.
- Split broad backlog items into multiple specific shortlisted hypotheses when
  needed.
- Do not shortlist items whose only claim is missing annotations, permissive
  defaults, duplicated auth helpers, weak operational hygiene, or lack of
  parser/queue hardening unless the candidate also states a reachable exploit
  path and concrete harm.
- Mark selected backlog items as `selected`.
- Do not call the shortlist "findings".
- Do not write `confirmed gap` or similar verdict wording before source
  validation.

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
  and candidates across A-H classes.
- `hypotheses.json` must have `backlog_ids` for every item.
- No item should be marked confirmed.
- If `graph_context.json` has input warnings, discard these artifacts and rerun
  graphify on a clean corpus.
- If `graph_context.json.graphify_quality.ast_only_likely` is true, do not run a
  normal hypothesis pass unless the user explicitly accepts degraded graph
  context. Prefer rerunning graphify with `/graphify <repo> --mode deep --no-viz`.
