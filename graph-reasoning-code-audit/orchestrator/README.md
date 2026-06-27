# Phase-Oriented Audit Runner

This helper breaks `graph-reasoning-code-audit` into small, resumable phases so
AI CLI tools do not need to keep the whole audit in one context window.

## Usage

Run commands from the `graph-reasoning-code-audit` directory so Python can import
the `orchestrator` package:

```bash
python -m orchestrator.audit_flow init --repo /path/to/repo
python -m orchestrator.audit_flow status --repo /path/to/repo
```

The first phase is a hard tool preflight checkpoint:

```bash
python -m orchestrator.audit_flow preflight --repo /path/to/repo
```

Report `.audit/summaries/phase-0a-tool-preflight.md` to the user and wait for
approval. Then record approval and advance:

```bash
python -m orchestrator.audit_flow approve-preflight --repo /path/to/repo --by "user"
python -m orchestrator.audit_flow next --repo /path/to/repo
```

Open and execute only the current task:

```bash
cat /path/to/repo/.audit/tasks/current.task.md
```

After the task writes its required artifacts and summary:

```bash
python -m orchestrator.audit_flow validate --repo /path/to/repo
python -m orchestrator.audit_flow next --repo /path/to/repo
```

## Design

- `.audit/audit_state.json` records phase status.
- `.audit/tasks/current.task.md` is the only task the AI CLI should execute.
- `.audit/summaries/*.md` carry compact cross-phase memory.
- `.audit/*.json` and `.audit/*.md` artifacts are the durable handoff between
  phases.
- `.audit/tasks/dispatch_plan.json` tells the main agent whether the current
  phase is main-agent only, optionally parallelizable, or recommended for
  subagent batch work.
- Optional tool failures should be recorded with `skip`, not left in chat.

The main AI session remains the orchestrator. Subagents, when available, should
only receive narrow tasks with exact read/write ownership. See
`references/orchestration-protocol.md`.

## Skip Records

```bash
python -m orchestrator.audit_flow skip --repo /path/to/repo \
  --name semgrep --tool semgrep --reason "not installed" \
  --uncovered "Semgrep pattern evidence"
```

Supported skip names are `sca`, `secret_scan`, `semgrep`, `joern`, `codeql`,
`guard_coverage`, `semantic_verifier_depth`, `source_validation_subagents`, and
`graph_context_degraded`.

When CodeQL or Joern depth validation degrades, report the gap to the user and
record the decision before evidence fusion:

```bash
python -m orchestrator.audit_flow approve-semantic-depth-degradation \
  --repo /path/to/repo \
  --decision continue \
  --summary "Targeted CodeQL depth validation degraded for H-001." \
  --next-steps "Continue to source validation with the semantic-verifier gap visible."
```
