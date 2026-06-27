# Phase 4: Source Validation and Reporting

Use this phase to validate evidence against source, decide whether to continue
with another backlog batch, and write the final report.

## Prepare Source-Validation Packet

Read `source_validation_playbooks.md`, then run:

```bash
python scripts/source_validate.py \
  --repo-root /path/to/repo \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --evidence /path/to/repo/.audit/evidence.json \
  --dependency-findings /path/to/repo/.audit/dependency_findings.json \
  --secret-findings /path/to/repo/.audit/secret_findings.json \
  --min-dependency-severity medium \
  --max-dependency-findings 20 \
  --output /path/to/repo/.audit/source_validation_packet.json \
  --prompt-output /path/to/repo/.audit/source_validation_prompt.md
```

This script gathers evidence and source windows. It does not decide whether a
hypothesis is real.

Dependency findings are auxiliary context by default. Use
`--include-dependency-findings-as-items` only when the user explicitly asks for
source-level validation of specific dependency advisories.

Secret findings are auxiliary context by default, but high-confidence hardcoded
secret findings are often worth validating even when Phase 2 missed them. Use
`--include-secret-findings-as-items` when the user wants the current pass to
adjudicate secret exposure directly.

## Validate Against Source

Before validating, read `.audit/verification_checkpoint.json` and follow
`source_validation_mode`.

Use the packet, prompt, playbooks, raw tool results, and source tree to write
`.audit/source_validation.md`.

### Parallel Batch Validation

Use this section only when `source_validation_mode` is `parallel`. When
`source_validation_mode` is `sequential`, keep validation in the main
agent/session and do not spawn source-validation workers.

When parallel source validation is selected, split validation into independent
worker batches before reading many source files:

```bash
python -m orchestrator.audit_flow plan-source-validation --repo /path/to/repo
```

This writes `.audit/source_validation_dispatch.json`. Each batch worker receives
only one to three assigned hypothesis ids, writes its assigned part file, and
uses only its assigned scratch directory:

```text
.audit/source-validation-parts/batch-001.md
.audit/source-validation-parts/batch-002.md
.audit/source-validation-work/batch-001/
.audit/source-validation-work/batch-002/
```

Workers must not write `.audit/source_validation.md`, `audit_report.md`,
`hypotheses.json`, or any other aggregate artifact. The main agent alone merges
part files into `.audit/source_validation.md`, resolves contradictions, and
writes the phase summary.

Use this dispatch shape:

```json
{
  "schema": "graph-reasoning-code-audit/source-validation-dispatch-v1",
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

Do not put more than three hypothesis ids in one batch. Workers may write
scratch files only under their assigned `worker_work_dir`. If validator errors,
fix the dispatch JSON to match this shape rather than weakening file ownership.

When the user selected `parallel`, `parallel_required` must stay `true`. Do not
complete the work sequentially and then backfill part files. If subagents are
unavailable or fail, write `skips/source_validation_subagents.json` before any
main-agent fallback and say so in the phase summary.

If the user selected `parallel` but the current AI runtime has no subagent tool,
write a skip record before direct main-agent validation:

```bash
python -m orchestrator.audit_flow skip --repo /path/to/repo \
  --name source_validation_subagents \
  --tool subagent-runtime \
  --reason "subagent tool unavailable; main agent validated the batch directly" \
  --uncovered "parallel source-validation isolation"
```

Then record `subagent_unavailable_main_agent_fallback` in the phase summary.

Recommended worker part shape:

```md
# Source Validation Part: batch-001

## Worker Metadata

- Executor: subagent|main-agent-fallback
- Batch id: batch-001
- Assigned hypothesis ids: H-001, H-002
- Worker work dir: .audit/source-validation-work/batch-001/
- Files checked: ...

## Scope

- Hypothesis ids: H-001, H-002
- Files checked: ...

## H-001: <title>

- status: confirmed|needs_review|false_positive
- source locations checked:
- scope gate:
- guard/invariant chain:
- evidence path:
- taint/slice path: available|not_available|not_applicable
- derived candidates noticed:
- residual questions:
```

If a worker notices a derived issue outside its assigned ids, it may record the
candidate in its own part file only. It must not edit the backlog or final
report. The main agent decides whether to promote the derived candidate after
merging all parts.

For each hypothesis, record:

- final status: `confirmed`, `needs_review`, or `false_positive`
- source locations checked
- whether it passes the vulnerability scope gate: realistic actor trigger,
  security boundary or invariant, sensitive action/asset, missing effective
  control, and concrete harm
- guard/invariant chain observed in code
- concise evidence path from entrypoint/source to sink/action
- taint or slice path when Semgrep, Joern, CodeQL, or source tracing provides
  one; explicitly say `not available` or `not applicable` rather than inventing
  tool evidence
- minimal safe reproduction or payload when useful and non-destructive
- whether evidence confirms a missing guard, proves coverage, or remains
  inconclusive
- residual questions that depend on deployment config, extensions, or product
  policy

This is the first phase where vulnerability verdicts are allowed.

If source validation only proves an unsafe practice or missing
defense-in-depth, do not mark it `confirmed`. Use `false_positive` when an
effective guard exists, or `needs_review` when exploitability depends on
deployment/runtime evidence. Optional hardening notes must be separated from
vulnerability findings.

## Derived Findings

If source validation, Joern follow-up, Semgrep review, or manual source reading
discovers a new issue that was not in the packet, treat it as a derived
candidate:

1. Give it a temporary id such as `D-001`.
2. Record why it was noticed and which source lines triggered it.
3. Validate it with the same source-validation contract before calling it
   confirmed.
4. If the full contract cannot be checked in the current pass, leave it as
   `needs_review` and add it to the next hypothesis batch.

Do not move derived candidates directly into the confirmed section of
`audit_report.md`. Dangerous API exposure, scanner severity, or a tool result
named `confirmed` is not enough.

## Continue or Stop

After validating the current shortlist, inspect `hypothesis_backlog.json`.
Treat `hypotheses.json` as one batch.

Continue with another shortlist batch when:

- the user requested broad coverage or a full audit;
- high-priority backlog items remain unvalidated;
- the first batch found no issues but large entrypoint families or A-H classes
  remain uncovered;
- source validation discovered new entrypoints, guards, sinks, or dependency
  context that change prioritization.

Stop and report when:

- the user requested a quick pass or PoC run;
- remaining backlog items are low priority, duplicate, deferred, or blocked;
- current findings are enough for the requested decision;
- time or tool limits make further validation impractical.

If stopping with unvalidated backlog items, say so explicitly in
`audit_report.md`.

## User-Facing Report

Write `.audit/audit_report.md` directly from the report template. Do not use a
brittle Markdown parser to transform `source_validation.md`.

Read `templates/audit_report_template.md` before writing the report. Preserve
the section order unless the current audit has a clear reason to add a section.
Replace placeholders with source-grounded content and remove example placeholder
blocks that do not apply.

Use:

- `source_validation.md`
- `source_validation_packet.json`
- `evidence.json` or `evidence-final.json`
- `semgrep-results.json`
- `joern-results.json`
- `codeql-results.json`
- `dependency_findings.json`
- `sca_report.md`
- `secret_findings.json`
- `secret_report.md`
- `hypothesis_backlog.json`
- checked source files

The final report must include:

- scope and tool coverage
- blocked or skipped tools
- for each skipped verification tool, exact uncovered language/directories and
  how that limits confirmed/needs-review conclusions
- backlog coverage: validated, unvalidated, deferred, and rejected counts by
  class or coverage area
- confirmed source-code vulnerabilities
- confirmed vulnerability totals that exclude hardening/code-practice
  observations
- whether each confirmed item is confirmed by machine evidence, source
  validation, or both
- needs-review items and exact follow-up checks
- false positives and the guard/invariant chain that disproves them
- derived candidates, separated from confirmed findings, with follow-up checks
- SCA summary, clearly separated from source-code findings
- secret exposure summary, clearly separated from generic source-code logic bugs
- optional hardening observations, clearly separated and not counted as
  vulnerabilities
- limitations, especially missing CPG, Semgrep timeout, unsupported languages,
  or contaminated graph inputs

This is the primary artifact to present to the user.
