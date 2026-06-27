# Orchestration Protocol

This workflow is a harness for AI CLI tools. The main agent is the
orchestrator; it owns phase control, artifact validation, summaries, and final
integration. Subagents are optional workers or reviewers with narrow file and
artifact ownership.

Do not use chat history as workflow memory. Use:

- `.audit/audit_state.json` for phase status
- `.audit/tasks/current.task.md` for the current phase contract
- `.audit/tasks/dispatch_plan.json` for main-agent vs subagent policy
- `.audit/summaries/*.md` for compact cross-phase memory
- `.audit/*.json` and `.audit/*.md` as phase handoff artifacts

## Main-Agent Duties

The main agent must:

- initialize, validate, and advance the flow with `orchestrator.audit_flow`;
- run Phase 0A tool preflight before graph generation or audit work;
- report the preflight summary to the user and wait for explicit approval;
- prefer the installed official graphify skill or slash command before CLI fallback;
- read only the current task, named references, and prior summaries;
- decide whether the local runtime has subagent support;
- start subagents only when the dispatch plan says they are useful;
- give each subagent a bounded task, exact inputs, exact outputs, and explicit
  write ownership;
- collect subagent outputs, fix or integrate them, then write the phase summary;
- never leave tool failures only in chat; record skips under `.audit/skips/`.

If no subagent tool exists, the main agent performs the work directly and notes
`subagent_unavailable_main_agent_fallback` in the phase summary.

## Subagent Rules

Subagents must not own the whole audit. They receive a small task and return or
write a named artifact.

Every subagent prompt must include:

- the repository root;
- the current phase id;
- the exact files it may read;
- the exact files it may write, or `read-only review`;
- the schema or report shape it must satisfy;
- forbidden actions, especially not changing unrelated artifacts and not
  confirming vulnerabilities before source validation.

Subagents should not read prior chat. Their context comes from task files,
summaries, schemas, and source windows.

## File Ownership

Only the main agent may write aggregate artifacts:

- `.audit/semantic_model.json`
- `.audit/hypothesis_backlog.json`
- `.audit/hypotheses.json`
- `.audit/verification_checkpoint.json`
- `.audit/semgrep_triage.json`
- `.audit/semantic_verifier_selection.json`
- `.audit/skips/semantic_verifier_depth.json`
- `.audit/semantic_verifier_depth_approval.json`
- `.audit/evidence.json`
- `.audit/source_validation.md`
- `.audit/audit_report.md`
- `.audit/summaries/*.md`

Parallel workers must write only their assigned output path and their private
work directory. For Phase 3, workers use `.audit/tool-work/<worker>/`. For Phase
4B, workers write `.audit/source-validation-parts/<batch-id>.md` and scratch
files only under `.audit/source-validation-work/<batch-id>/`; the main agent
merges part files into `.audit/source_validation.md`. Never start two workers
with permission to write the same file or directory.

## Phase Dispatch Matrix

| Phase | Main-agent role | Subagent policy | Artifact policy |
|---|---|---|---|
| Phase 0A tool preflight | Run tool checks, report availability/limitations, wait for user approval | No subagent | Main agent writes `tool_status.json`, `preflight_approval.json`, and summary |
| Phase 0B graph context | Run or normalize graphify, enforce input hygiene | Optional explorer only for graphify output interpretation | Main agent writes `graph_context.json` and summary |
| Phase 1 SCA/secret | Run deterministic inventory/scanners, record skips | Optional parallel workers for SCA and secret scan if tools are slow/independent | Workers may write only their assigned findings/report files |
| Phase 2A semantic model | Integrate source, graph, SCA, secrets into one model | Usually main agent; optional explorer workers for bounded subsystem summaries | Main agent owns final `semantic_model.json` |
| Phase 2B hypotheses | Build backlog and select current batch | Usually main agent; optional reviewer subagent checks coverage and forbidden verdict wording | Main agent owns final `hypothesis_backlog.json` and `hypotheses.json` |
| Phase 2C verification checkpoint | Report Phase 0-2 progress and ask user to choose Phase 3 and Phase 4 execution modes | No subagent | Main agent writes `verification_checkpoint.json`; no verification tools run |
| Phase 3 verification | Run the ordered funnel: Semgrep, triage, selected semantic verifier, semantic depth accounting, degradation checkpoint, evidence fusion | Parallel workers are stage-local only. Semgrep may use a worker first; after `semgrep_triage.json`, one selected semantic verifier worker may run if needed | Each worker owns only its tool output, semantic depth plan/results if assigned, and `.audit/tool-work/<worker>/`; main agent owns `semgrep_triage.json`, `semantic_verifier_selection.json`, `skips/semantic_verifier_depth.json`, `semantic_verifier_depth_approval.json`, and `evidence.json` |
| Phase 4A source packet | Run deterministic packet builder | No subagent needed | Main agent writes packet and prompt |
| Phase 4B source validation | Adjudicate each hypothesis against source according to `source_validation_mode` | Batch workers are used only if user selected `source_validation_mode=parallel`; each owns 1-3 hypothesis ids, one part file, and one private work dir | Main agent writes `source_validation_dispatch.json` when parallel batching is used, merges parts into `source_validation.md`, and prevents premature confirmation |
| Phase 5 final report | Write final user-facing report | Optional reviewer subagent for report completeness and separation of SCA/secrets/source findings | Main agent owns `audit_report.md` |

## Recommended Subagent Prompts

### SCA Worker

```text
You are the SCA worker for graph-reasoning-code-audit.
Repo: <repo>
Read: .audit/dependency_context.json, dependency manifests and lockfiles.
Write only: .audit/dependency_findings.json and .audit/sca_report.md.
Keep dependency advisories separate from source-code vulnerability findings.
If the scanner is unavailable, write .audit/skips/sca.json with the exact reason.
Return a short summary of artifacts written and limitations.
```

### Secret Scan Worker

```text
You are the secret-scan worker for graph-reasoning-code-audit.
Repo: <repo>
Read: source tree, scanner raw outputs if present.
Write only: .audit/secret_findings.json and .audit/secret_report.md.
Never print raw secret values; use redacted fields only.
If Betterleaks or fallback tools are unavailable, write .audit/skips/secret_scan.json.
Return a short summary of artifacts written and limitations.
```

### Verification Worker

```text
You are the <Semgrep|Joern|CodeQL> verification worker.
Repo: <repo>
Read: .audit/hypotheses.json, .audit/verification_checkpoint.json, and the relevant phase references.
Write only: <assigned output path>, assigned semantic depth artifacts when you
are the selected Joern/CodeQL worker, and .audit/tool-work/<semgrep|joern|codeql>/.
Run only when .audit/verification_checkpoint.json has tool_verification_mode=parallel.
If you are Joern or CodeQL, also read .audit/semgrep_triage.json and only
review triaged semantic targets. Never start before semgrep_triage.json exists.
If you are Joern or CodeQL and semantic_review_ids is non-empty, also write
.audit/semantic_verifier_depth_plan.json and
.audit/semantic_verifier_depth_results.json with one depth result per triaged
hypothesis. Standard packs/querydb are breadth coverage only.
Do not write .audit/semantic_verifier_selection.json, .audit/evidence.json, or summaries.
Tool results are evidence, not final vulnerability verdicts.
Record skipped languages/directories exactly when coverage is partial. If you
only completed breadth coverage, tell the main agent to write
.audit/skips/semantic_verifier_depth.json with status=degraded and the uncovered ids.
The main agent must then stop for user review and record
.audit/semantic_verifier_depth_approval.json before evidence fusion.
Return a short summary of hits, skips, and uncovered areas.
```

### Source Validation Batch Worker

```text
You are a source-validation worker for graph-reasoning-code-audit.
Repo: <repo>
Validate only hypothesis ids: <ids>.
Handle one to three hypothesis ids only; ask the main agent to split larger
batches before starting.
Read: .audit/source_validation_packet.json, .audit/source_validation_prompt.md,
references/source_validation_playbooks.md, .audit/source_validation_dispatch.json,
and source windows/files for those ids.
Write only: .audit/source-validation-parts/<batch-id>.md and
.audit/source-validation-work/<batch-id>/.
Run only when .audit/verification_checkpoint.json has source_validation_mode=parallel.
Use statuses only: confirmed, needs_review, false_positive.
Do not validate hypotheses outside your assigned ids.
Do not write .audit/source_validation.md or .audit/audit_report.md.
Return a short summary of statuses and unresolved questions.
```

### Report Reviewer

```text
You are a final-report reviewer.
Read only: .audit/audit_report.md, .audit/source_validation.md, .audit/evidence*.json,
.audit/dependency_findings.json, .audit/secret_findings.json, and summaries.
Do not edit files. Return pass/fail with missing required sections, incorrect
counting, or improper mixing of SCA/secret/source-code findings.
```
