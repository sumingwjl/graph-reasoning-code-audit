---
name: graph-reasoning-code-audit
description: Use this skill to run a modular graph-reasoning code audit workflow focused on exploitable source-code vulnerabilities, not code-quality or generic hardening review. It consumes graphify code graph/AST repository context, extracts a security semantic model, builds a broad hypothesis backlog, runs Betterleaks or compatible secret scanning for hardcoded credentials, selects verification batches, uses SCA as auxiliary context, verifies through an ordered funnel (Semgrep first, semgrep_triage barrier, then exactly one selected semantic verifier such as Joern CLI or CodeQL), validates evidence against source, and writes a user-facing audit report. Use for repository security review, hypothesis-driven code audit, graphify-assisted audit, secret exposure review, and source-grounded vulnerability triage.
---

# Graph Reasoning Code Audit

Use this skill as an orchestrator. Keep this file small; load phase references
only when the phase is about to run.

## Phase-Oriented Runner

Version 2.0 is designed to avoid long-context degradation in AI CLI tools such
as Claude Code, Codex, and similar coding agents. Prefer the phase-oriented
runner over a single long chat session.

The runner stores workflow state in `.audit/audit_state.json`, writes focused
tasks under `.audit/tasks/`, and expects each phase to write a short summary
under `.audit/summaries/`. Treat those files as the source of truth instead of
prior chat memory.

Initialize a repository audit:

```bash
python -m orchestrator.audit_flow init --repo /path/to/repo
```

The first generated task is always **Phase 0A Tool Preflight**. Run it before
any graph or audit generation:

```bash
python -m orchestrator.audit_flow preflight --repo /path/to/repo
```

Report `.audit/summaries/phase-0a-tool-preflight.md` to the user and stop. The
user must explicitly approve continuing with the detected tool availability and
limitations. After approval, record it:

```bash
python -m orchestrator.audit_flow approve-preflight --repo /path/to/repo --by "user"
python -m orchestrator.audit_flow next --repo /path/to/repo
```

At this first checkpoint, ask the user which Graphify mode Phase 0B should use
and record it with approval:

```bash
python -m orchestrator.audit_flow approve-preflight --repo /path/to/repo \
  --by "user" \
  --graphify-mode ast \
  --graphify-mode-reason "Code audit only; use Graphify AST/code graph and skip non-code semantic extraction."
```

Use `ast` by default and recommend it for code audit. Use `deep` only when the
user wants security-relevant non-code files such as architecture docs, OpenAPI
specs, threat models, deployment notes, or diagrams included. Use `existing`
only to normalize an already-built graphify output.

Then execute only the generated current task:

```bash
cat /path/to/repo/.audit/tasks/current.task.md
```

After completing that task, validate and advance:

```bash
python -m orchestrator.audit_flow validate --repo /path/to/repo
python -m orchestrator.audit_flow next --repo /path/to/repo
```

Use status at any time:

```bash
python -m orchestrator.audit_flow status --repo /path/to/repo
```

If an optional tool is unavailable, write a skip record instead of keeping the
reason only in chat:

```bash
python -m orchestrator.audit_flow skip --repo /path/to/repo \
  --name codeql --tool codeql --reason "not installed in PATH" \
  --uncovered "CodeQL semantic/data-flow verification"
```

When resuming after context compaction or a new AI CLI session, read
`.audit/tasks/current.task.md`, the listed prior summaries, and only the
references named by the task.

## Main Agent / Subagent Protocol

The main AI session is the **orchestrator**. Its job is to control the phase
runner, keep artifact boundaries clean, dispatch narrow subagents when useful,
validate outputs, and write phase summaries. It should not try to keep the full
audit in chat memory.

Read `references/orchestration-protocol.md` before delegating or parallelizing.
Each generated task also writes `.audit/tasks/dispatch_plan.json`; use that file
as the current phase's machine-readable dispatch policy.

Quality and delegation are phase-specific:

| Phase | Main Agent | Subagent Policy | Persistent Output |
|---|---|---|---|
| Phase 0A Tool Preflight | Runs tool checks, reports to user, waits for approval | No subagent | `tool_status.json`, approval, summary |
| Phase 0B Graphify | Owns hygiene gate and `graph_context.json` | Optional explorer only | `graph_context.json`, summary |
| Phase 1 SCA/Secret | Runs setup and validates results | Optional parallel SCA and secret workers | findings/reports or skip records |
| Phase 2A Semantics | Owns final `semantic_model.json` | Optional bounded subsystem explorers | `semantic_model.json` |
| Phase 2B Hypotheses | Owns backlog and shortlist | Optional read-only coverage/verdict reviewer | `hypothesis_backlog.json`, `hypotheses.json` |
| Phase 2C Verification Checkpoint | Reports progress and asks user to choose Phase 3 and Phase 4 execution modes | No subagent | `verification_checkpoint.json` |
| Phase 3 Verification | Owns funnel barriers, semantic depth accounting, degradation checkpoint, fusion, and skipped-tool accounting | Optional workers are stage-local: Semgrep first, then triage, then exactly one semantic verifier; each worker gets a private `.audit/tool-work/<worker>/` dir | `semgrep-results.json`, `semgrep_triage.json`, selected verifier output, `semantic_verifier_selection.json`, `semantic_verifier_depth_plan.json`/`semantic_verifier_depth_results.json` or `skips/semantic_verifier_depth.json` plus `semantic_verifier_depth_approval.json`, `evidence.json` |
| Phase 4A Packet | Runs deterministic packet builder | No subagent needed | packet and prompt |
| Phase 4B Validation | Owns merged validation verdicts | Use batch workers only if Phase 2C selected parallel source validation; each worker handles 1-3 hypotheses, one part file, and one private work dir | `source_validation_dispatch.json`, `source-validation-parts/*.md`, `source-validation-work/<batch>/`, `source_validation.md` |
| Phase 5 Report | Owns final report | Optional read-only report reviewer | `audit_report.md` |

Subagents must receive exact read/write scopes. They never own the whole audit,
never rely on prior chat, and never modify artifacts outside their assignment.
If the runtime has no subagent tool, the main agent performs the phase directly
and records `subagent_unavailable_main_agent_fallback` in the phase summary.

## Audit Classes

- A. Identity and access control
- B. Workflow and state machine
- C. Business logic and abuse
- D. Injection and unsafe interpretation
- E. Data exposure and privacy
- F. Secrets, crypto, and session security
- G. External boundaries, files, and network
- H. Concurrency, consistency, and resource exhaustion

Dependency/framework/configuration scanning is an auxiliary SCA track. Use it to
inform prioritization and exploitability, not as proof of source-code
vulnerabilities.

Hardcoded secret discovery is a separate Secret Scan track. Prefer Betterleaks;
use LLM judgment only to classify scanner matches as effective secrets,
placeholders, test fixtures, false positives, or confirmed exposure.

## Hard Rules

- Write every generated audit artifact under `.audit/`.
- Keep graphify output read-only after generation.
- This is a vulnerability audit, not a code-quality, secure-coding-practice, or
  generic hardening audit. Confirm only issues with a realistic actor-triggered
  path to concrete security impact.
- Do not count missing defense-in-depth, weak style, duplicate implementations,
  broad best-practice gaps, or "could become risky if misconfigured" items as
  confirmed vulnerabilities unless source validation proves a reachable bypass
  or harmful effect.
- Treat Graphify AST/code-graph output as the normal input for code audit.
  Graphify semantic extraction is optional and mainly for security-relevant
  non-code files. Do not mark code-only AST output degraded merely because
  semantic cache files, inferred edges, or hyperedges are absent.
- Exclude previous audit reports, generated findings, `.audit/`, scanner
  outputs, and old `graphify-out/` directories from the graphify corpus.
- If `graph_context.json` reports input contamination, stop hypothesis
  generation and rerun graphify on a clean source tree.
- Do not use Joern MCP. Use Joern CLI directly only when Joern is selected as
  the primary semantic verifier. Use CodeQL only when selected as the primary
  semantic verifier, especially where Joern language support is weak or
  build-aware data flow is useful. Do not run both by default.
- Treat CodeQL standard packs and Joern querydb/prebuilt rules as breadth
  coverage. If `semgrep_triage.json.semantic_review_ids` is non-empty, the
  selected verifier must produce per-hypothesis depth plan/results, or write
  `skips/semantic_verifier_depth.json` with `status: degraded`.
- If semantic verifier depth is degraded, immediately report it to the user and
  wait for a decision. Do not fuse evidence or advance to Phase 4 until
  `semantic_verifier_depth_approval.json` records the user's decision.
- Do not call a hypothesis confirmed before source validation.
- Do not call a derived observation confirmed until it is promoted to a
  hypothesis candidate and validated with the same source contract.
- Keep SCA findings separate from source-code findings unless the user asks to
  deep-dive a specific advisory.
- Keep secret scanner matches separate from generic source-code findings until
  source/context validation proves the secret is effective or harmful.
- Treat `hypotheses.json` as the current verification batch, not complete audit
  coverage.
- After generating `hypotheses.json`, stop at Phase 2C and ask the user whether
  Phase 3 tool verification and Phase 4 source validation should each use
  parallel subagents or sequential main-agent execution. Do not run Semgrep,
  Joern, CodeQL, or source validation until `verification_checkpoint.json`
  records both choices.
- The final user-facing report is `.audit/audit_report.md`, written by the LLM
  after source validation.

## Load References

Always read:

- `references/schemas.md` before creating or modifying JSON artifacts.
- `references/hypothesis_types.md` before generating backlog or shortlist.

Load phase references only when needed:

- `references/phase-0-setup-and-graphify.md` for tool checks, Graphify mode
  choice, input hygiene, and `graph_context.json`. Prefer the installed official
  graphify skill or slash command first; use CLI fallback only when needed.
- `references/phase-1-sca.md` for dependency/config scanner context and SCA
  reporting.
- `references/phase-1b-secret-scan.md` for Betterleaks/Gitleaks/TruffleHog
  hardcoded secret scanning and `secret_findings.json`.
- `references/phase-2-semantics-and-hypotheses.md` for `semantic_model.json`,
  `hypothesis_backlog.json`, and `hypotheses.json`.
- `references/phase-3-verification.md` for Semgrep, Joern CLI, CodeQL, guard
  coverage, and evidence fusion.
- `references/phase-4-source-validation-and-reporting.md` for
  `source_validation_packet.json`, `source_validation.md`, batch continuation,
  and `audit_report.md`.
- `templates/audit_report_template.md` before writing `.audit/audit_report.md`.
- `references/semgrep_templates.md` only when generating Semgrep rules.
- `references/joern_queries.md` only when planning or interpreting Joern CLI
  verification.
- `references/codeql_queries.md` only when planning or interpreting CodeQL
  verification.
- `references/source_validation_playbooks.md` before source validation.

## Workflow

1. Setup and Graphify
   - Confirm local tools and paths.
   - At the first checkpoint, ask the user to choose Graphify mode. Recommend
     `ast` for code audit; use `deep` only for security-relevant non-code files.
   - Ensure clean Graphify code graph/AST output exists.
   - Normalize graphify output to `.audit/graph_context.json`.
   - Stop if contamination warnings appear.

2. SCA Context
   - Collect dependency/config context early.
   - Run OSV-Scanner or another scanner when available.
   - Produce `dependency_findings.json` and `sca_report.md`.

3. Secret Scan
   - Run Betterleaks when available, or ask for the executable path if it is not
     in `PATH`.
   - Produce `secret_findings.json` and `secret_report.md`.

4. Semantics and Hypotheses
   - Produce `semantic_model.json`.
   - Use high-confidence secret findings as F-class hypothesis input.
   - Produce broad `hypothesis_backlog.json`.
   - Select one verification batch as `hypotheses.json`.
   - Stop at the verification checkpoint, report current progress to the user,
     and record whether Phase 3 tool verification and Phase 4 source validation
     should run in `parallel` or `sequential` mode.

5. Verification
   - Generate and run Semgrep evidence rules.
   - Write `semgrep_triage.json` as the funnel barrier.
   - Select exactly one primary semantic verifier, Joern CLI or CodeQL, based
     on tool availability, repository language support, build feasibility, and
     Semgrep triage.
   - Run only the selected semantic verifier by default and record the
     unselected verifier as skipped or out of scope for this batch.
   - Never start Joern or CodeQL before Semgrep and `semgrep_triage.json`.
   - Distinguish broad standard/querydb coverage from hypothesis-depth
     validation. If CodeQL or Joern only completes breadth coverage, mark
     semantic verifier depth as degraded instead of treating P3 as
     depth-complete.
   - Stop for user review when semantic verifier depth is degraded. Continue,
     retry, switch, or narrow only after recording
     `semantic_verifier_depth_approval.json`.
   - Fuse evidence and optionally assess deterministic guard coverage.
   - Keep tool failures explicit; do not treat plans as evidence.

6. Source Validation and Reporting
   - Prepare `source_validation_packet.json`.
   - Validate each shortlisted hypothesis against source.
   - Decide whether another backlog batch is needed.
   - Write `.audit/audit_report.md`.

## Artifact Map

Core artifacts:

- `.audit/graph_context.json`
- `.audit/dependency_context.json`
- `.audit/dependency_findings.json`
- `.audit/sca_report.md`
- `.audit/betterleaks-git.json`
- `.audit/betterleaks-dir.json`
- `.audit/secret_findings.json`
- `.audit/secret_report.md`
- `.audit/semantic_model.json`
- `.audit/hypothesis_backlog.json`
- `.audit/hypotheses.json`
- `.audit/verification_checkpoint.json`
- `.audit/semgrep-rules.yml`
- `.audit/semgrep-results.json`
- `.audit/semgrep_triage.json`
- `.audit/joern-results.json`
- `.audit/semantic_verifier_depth_plan.json`
- `.audit/semantic_verifier_depth_results.json`
- `.audit/skips/semantic_verifier_depth.json`
- `.audit/semantic_verifier_depth_approval.json`
- `.audit/tool-work/semgrep/`
- `.audit/tool-work/joern/`
- `.audit/tool-work/codeql/`
- `.audit/codeql-results.json`
- `.audit/evidence.json`
- `.audit/guard_coverage.json`
- `.audit/evidence-final.json`
- `.audit/final_report.md`
- `.audit/source_validation_packet.json`
- `.audit/source_validation_prompt.md`
- `.audit/source_validation_dispatch.json`
- `.audit/source-validation-parts/<batch>.md`
- `.audit/source-validation-work/<batch>/`
- `.audit/source_validation.md`
- `.audit/audit_report.md`

When this skill runs graphify itself, graphify outputs should live under
`.audit/graphify-out/` when the local graphify entrypoint supports an output
directory.

## Completion Criteria

An audit pass is complete only when:

- graph input hygiene was checked;
- the current verification batch was validated against source;
- unvalidated backlog coverage is reported;
- skipped or failed tools are listed;
- SCA is separated from source-code vulnerability conclusions;
- secret scanner matches are separated from confirmed exposure conclusions;
- `.audit/audit_report.md` is written.
