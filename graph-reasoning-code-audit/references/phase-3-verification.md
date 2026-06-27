# Phase 3: Verification

Use this phase as an ordered funnel: Semgrep evidence, Semgrep triage, exactly
one primary semantic verifier for triaged targets, deterministic guard coverage,
and evidence fusion.

Do not run Semgrep and Joern/CodeQL at the same time. `tool_verification_mode =
parallel` means workers may be used inside each funnel stage; it does not remove
the Semgrep triage barrier.

## Semantic Verifier Selection

Run Semgrep for evidence collection, write `.audit/semgrep_triage.json`, then
select one primary semantic verifier: Joern CLI or CodeQL. Do not run Joern and
CodeQL both by default.

Record the semantic verifier decision after Semgrep triage and before running
the semantic verifier:

```bash
python -m orchestrator.audit_flow select-verifier --repo /path/to/repo
```

If the user or operator explicitly chooses the verifier, record that override:

```bash
python -m orchestrator.audit_flow select-verifier --repo /path/to/repo --verifier codeql
```

Use `--verifier joern` for Joern, or `--verifier unavailable` when neither
semantic verifier should run in this pass.

Write the selected verifier output only:

- Joern selected: write `.audit/joern-results.json`; leave CodeQL absent or
  record `.audit/skips/codeql.json` if useful for limitations.
- CodeQL selected: write `.audit/codeql-results.json`; leave Joern absent or
  record `.audit/skips/joern.json` if useful for limitations.
- Neither available: write skip records, keep Semgrep/source validation as the
  remaining evidence path, and record the coverage gap.

The selected semantic verifier must read `.audit/semgrep_triage.json` and focus
on `semantic_review_ids`. Hypotheses that are not semantic-review targets still
continue to Phase 4 source validation.

Do not treat `semantic_review_ids` as a severity list. It is a verifier
suitability list. ARCH root causes, business-logic/control-plane gaps, and
items whose `verification_suitability.preferred_path` is `source_only` should
normally be excluded from CodeQL/Joern depth validation and handled in Phase 4.
This is not degradation; it is the intended path for hypotheses that static
semantic verifiers cannot prove well.

Separate breadth from depth:

- Breadth coverage: CodeQL standard query packs, Joern querydb/prebuilt rules,
  and other broad scans. Useful, but not sufficient for hypothesis-depth
  validation.
- Depth validation: one targeted CodeQL or Joern result per
  `semantic_review_id`, driven by `hypotheses.json` and `semgrep_triage.json`.

If `semantic_review_ids` is non-empty and CodeQL or Joern is selected, P3 must
produce either:

- `.audit/semantic_verifier_depth_plan.json` and
  `.audit/semantic_verifier_depth_results.json`; or
- `.audit/skips/semantic_verifier_depth.json` with `status: "degraded"`, a
  reason, and every uncovered `semantic_review_id`.

The depth plan and depth results must also account for breadth coverage. A
selected verifier may report breadth coverage as `completed`, `degraded`, or
`skipped`, but it must not silently omit it. For Joern, breadth normally means
full-CPG inventory/querydb/prebuilt coverage. For CodeQL, breadth normally means
standard query-pack coverage.

Breadth-only CodeQL/Joern verification is a degraded semantic-verifier result.
This is a hard user checkpoint. Immediately report the attempted verifier,
the breadth/depth status, uncovered `semantic_review_ids`, and the available
choices: continue to source validation with degraded semantic verification,
retry with more time/custom queries, switch verifier if available, or narrow
scope. Stop until the user decides.

After the user decides, record it:

```bash
python -m orchestrator.audit_flow approve-semantic-depth-degradation \
  --repo /path/to/repo \
  --decision continue \
  --by "user" \
  --summary "CodeQL standard packs ran, but targeted depth coverage failed for H-001 and H-002." \
  --next-steps "Continue to Phase 4 source validation with degraded semantic-verifier coverage visible."
```

Do not run evidence fusion or advance to Phase 4 while
`.audit/skips/semantic_verifier_depth.json` exists without
`.audit/semantic_verifier_depth_approval.json`.

Create the depth plan with:

```bash
python scripts/plan_semantic_depth.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --triage /path/to/repo/.audit/semgrep_triage.json \
  --selection /path/to/repo/.audit/semantic_verifier_selection.json \
  --output /path/to/repo/.audit/semantic_verifier_depth_plan.json
```

When Phase 3 runs with parallel workers, each worker may write temporary files
only under its private work directory:

- Semgrep: `.audit/tool-work/semgrep/`
- Joern: `.audit/tool-work/joern/`
- CodeQL: `.audit/tool-work/codeql/`

Only the main agent writes `.audit/semantic_verifier_selection.json`,
`.audit/evidence.json`, summaries, and any other aggregate artifact.
The selected semantic-verifier worker may write
`.audit/semantic_verifier_depth_plan.json` and
`.audit/semantic_verifier_depth_results.json` because they are its assigned
coverage-accounting artifacts.

Run the unselected verifier only when the selected verifier fails to cover the
target language, the user explicitly asks for deeper coverage, or a single
high-risk finding needs cross-tool confirmation. If that happens, explain why in
the phase summary; it is an exception, not the default flow.

## Semgrep Evidence

Generate rule stubs:

```bash
python scripts/generate_semgrep_rules.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --output /path/to/repo/.audit/semgrep-rules.yml
```

Run Semgrep:

```bash
python scripts/run_semgrep.py \
  --repo-root /path/to/repo \
  --config /path/to/repo/.audit/semgrep-rules.yml \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --output /path/to/repo/.audit/semgrep-results.json
```

Generated rules are lightweight evidence rules, not proof of vulnerability. They
are useful for collecting source locations and pattern signals. For stronger
results, replace generic generated rules with language-aware Semgrep rules.

If Semgrep is unavailable, times out, or only produces noisy keyword hits, record
that status and continue to source validation.

Write the funnel barrier:

```bash
python scripts/triage_semgrep.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --semgrep /path/to/repo/.audit/semgrep-results.json \
  --output /path/to/repo/.audit/semgrep_triage.json
```

Do not start Joern or CodeQL until `.audit/semgrep_triage.json` exists.

After triage, inspect `semantic_review_count`:

- If it is zero, record `select-verifier --verifier unavailable` with a reason
  such as "current hypotheses are source-validation-only", then continue to
  evidence fusion/source validation without CodeQL/Joern depth work.
- If it is non-zero, choose exactly one semantic verifier and run depth
  validation only for `semantic_review_ids`.
- Do not run CodeQL/Joern for ARCH/source-only hypotheses just to produce a
  degradation record.

## Joern CLI

Use this section only when `.audit/semantic_verifier_selection.json` selects
`joern`, or when Joern is explicitly used as an exception. First create
verification tasks:

```bash
python scripts/run_joern_queries.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --output /path/to/repo/.audit/joern-results.json
```

Use Joern CLI, not Joern MCP. Keep CPG artifacts under
`.audit/tool-work/joern/`:

```bash
mkdir -p /path/to/repo/.audit/tool-work/joern
joern-parse /path/to/repo \
  --output /path/to/repo/.audit/tool-work/joern/cpg.bin.zip
joern /path/to/repo/.audit/tool-work/joern/cpg.bin.zip
```

Prefer this order:

1. Build or reuse a full source CPG when the project is small/medium or the CPG
   can be generated in reasonable time. Use that full CPG for breadth inventory,
   querydb/prebuilt coverage, and narrow per-hypothesis queries.
2. Query one hypothesis at a time. Restrict by method names, controller/service
   names, filenames, annotations, sink names, guard names, or resource ids from
   `hypotheses.json`. Do not run one broad query for every hypothesis at once.
3. Start with structural checks: endpoints, annotations, dangerous calls, file
   operations, raw SQL calls, auth attributes, service fan-out, and candidate
   guards.
4. Add data-flow/slicing only after structural evidence identifies concrete
   source/sink/guard symbols.
5. Use focused CPGs only as fallback when full-CPG generation/loading/querying
   fails, times out, runs out of memory, or becomes too noisy for a specific
   hypothesis. Focused CPGs do not replace full-CPG breadth coverage unless the
   full CPG was explicitly degraded.
6. If full-CPG queries become slow, noisy, or error-prone, fall back to focused
   CPGs for:
   - one language
   - one entrypoint directory
   - one service/module directory
   - one hypothesis family
7. Use `--nooverlays` for focused first-pass structural CPGs. If
   reaching-definitions or data-flow becomes too expensive, cap it with
   `--max-num-def` and narrow the source directory further.
8. Mark only the uncovered language, directory, or hypothesis as skipped. Do not
   mark Joern globally skipped while smaller scopes are still feasible.

The anti-pattern is: full CPG plus one broad all-hypotheses data-flow query. The
preferred pattern is: full CPG plus one narrow query per hypothesis, with focused
CPG fallback.

Example focused C#/.NET controller pass:

```bash
joern-parse /path/to/repo/src/MyApp.HttpApi.Host/Controllers \
  --language csharpsrc \
  --nooverlays \
  --output /path/to/repo/.audit/tool-work/joern/controllers-cpg.bin
joern --script /path/to/repo/.audit/tool-work/joern/controllers-light.sc --nocolors --maxHeight 200
```

On Windows, Joern can be fragile with paths that contain spaces. Prefer putting
temporary CPGs and scripts under a no-space `.audit/tool-work/joern/` path when
possible, or use Windows 8.3 short paths / forward-slash paths inside Joern
scripts.

Read `joern_queries.md` before writing or interpreting Joern queries. Use Joern
primarily for:

- entrypoint-to-sensitive-action reachability
- guard dominance
- request/resource id data flow
- focused slicing around high-value paths

Before the targeted Joern pass, write
`.audit/semantic_verifier_depth_plan.json`. After the targeted pass, write
`.audit/semantic_verifier_depth_results.json`. Each `semantic_review_id` must
have one result with `coverage_mode: "depth"` and status `hit`, `miss`,
`error`, or `skipped`.

Save normalized Joern CLI results as `.audit/joern-verified-results.json`, then
wrap them:

```bash
python scripts/run_joern_queries.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --results /path/to/repo/.audit/joern-verified-results.json \
  --output /path/to/repo/.audit/joern-results.json
```

If full-project CPG generation or full-CPG per-hypothesis queries fail, time out,
or produce unusable output, try the focused fallback above before skipping. Only
skip after recording what smaller scopes were attempted:

```bash
python scripts/run_joern_queries.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --status skipped \
  --reason "full-project Joern failed; focused scopes attempted: <language/dirs>; remaining uncovered: <language/dirs/risk area>" \
  --output /path/to/repo/.audit/joern-results.json
```

Do not count planned Joern tasks as verified hits. When Joern is skipped for a
multi-language repository, record the uncovered language, directory, and risk
area explicitly. Do not write that Semgrep provided sufficient coverage unless
Semgrep actually covered the same language and source directories. Prefer wording
such as: `Joern skipped for C#/.NET due to CPG size; Python/FastAPI still had
Semgrep and source-validation coverage; .NET remains partially unverified`.

If Joern only ran querydb/prebuilt rules or broad inventory and did not complete
per-hypothesis depth validation, mark degraded coverage:

```bash
python -m orchestrator.audit_flow skip \
  --repo /path/to/repo \
  --name semantic_verifier_depth \
  --tool joern \
  --status degraded \
  --reason "Joern breadth coverage ran, but no targeted hypothesis-depth queries completed" \
  --uncovered H-001
```

Repeat `--uncovered` for every uncovered `semantic_review_id`.
Then stop for the semantic-depth degradation checkpoint described above.

## CodeQL

Use this section only when `.audit/semantic_verifier_selection.json` selects
`codeql`, or when CodeQL is explicitly used as an exception. CodeQL is useful
for C#/.NET, JavaScript/TypeScript, Python, Go, Java/Kotlin, C/C++, Ruby, and
other languages with mature extractors or query packs. Prefer CodeQL when:

- Joern language support is weak for the target code;
- build-aware type/data-flow precision matters;
- a standard CodeQL query can validate an injection, path, crypto, auth, or
  exposure hypothesis;
- the repo already has a usable build command or CodeQL database.

Do not make the audit depend on CodeQL. Many real repositories cannot build on
the audit machine because of private packages, missing SDKs, secrets, databases,
or monorepo setup. If CodeQL was selected and fails, record exact attempted
language, source root, build mode/command, error summary, and uncovered
directories. Then either switch to Joern with a new
`semantic_verifier_selection.json` reason, or continue with Semgrep and source
validation while recording the semantic-verifier gap.

Recommended order:

1. Detect relevant languages from the repo and `semantic_model.json`.
2. Check both extractors and query packs. `codeql resolve languages` confirms
   extraction support, but analysis also needs standard query/library packs or
   local custom queries that can resolve their imports.
3. For non-compiled or build-mode-none-capable languages, try a no-build
   database first.
4. For compiled languages, prefer focused module/project builds over full
   monorepo builds.
5. Run one query pack or custom query set per language/hypothesis family.
6. Write `.audit/semantic_verifier_depth_plan.json` for triaged hypotheses.
7. Run targeted standard-mapped or custom CodeQL queries for each
   `semantic_review_id`, where feasible.
8. Write `.audit/semantic_verifier_depth_results.json`.
9. Normalize SARIF to `.audit/codeql-results.json`.
10. Treat CodeQL hits as evidence, not final vulnerability verdicts.

Before analysis, check local packs:

```bash
codeql resolve languages
codeql resolve packs
```

If extractors are present but query packs/libraries are missing, database
creation may succeed while `database analyze` or custom queries fail with errors
such as `could not resolve module <language>`. Record CodeQL as
`database_created_but_queries_unavailable`, ask the user for the CodeQL query
pack path or installation, and continue with other verifiers.

Artifact layout:

```text
.audit/tool-work/codeql/dbs/<language>/
.audit/tool-work/codeql/results/<language>.sarif
.audit/tool-work/codeql/cache/
.audit/codeql-results.json
```

Examples:

```bash
mkdir -p /path/to/repo/.audit/tool-work/codeql/dbs /path/to/repo/.audit/tool-work/codeql/results
mkdir -p /path/to/repo/.audit/tool-work/codeql/cache

# No-build / build-mode none when supported by the target language and CodeQL version.
codeql database create /path/to/repo/.audit/tool-work/codeql/dbs/javascript \
  --language=javascript \
  --source-root /path/to/repo \
  --build-mode=none

# Focused compiled-language build.
codeql database create /path/to/repo/.audit/tool-work/codeql/dbs/csharp-api \
  --language=csharp \
  --source-root /path/to/repo \
  --command "dotnet build src/MyApp.Api/MyApp.Api.csproj"

codeql database analyze /path/to/repo/.audit/tool-work/codeql/dbs/csharp-api \
  --format=sarifv2.1.0 \
  --output=/path/to/repo/.audit/tool-work/codeql/results/csharp-api.sarif \
  --common-caches=/path/to/repo/.audit/tool-work/codeql/cache \
  codeql/csharp-queries
```

On Windows, `database analyze` may try to create a user-home cache such as
`C:\Users\<user>\.codeql\compile-cache`. If that path is not writable, always
pass `--common-caches <repo>/.audit/tool-work/codeql/cache`.

Normalize SARIF:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif /path/to/repo/.audit/tool-work/codeql/results/csharp-api.sarif \
  --output /path/to/repo/.audit/codeql-results.json
```

For targeted custom queries, attach the result to one hypothesis:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif /path/to/repo/.audit/tool-work/codeql/results/H-001.sarif \
  --hypothesis-id H-001 \
  --output /path/to/repo/.audit/codeql-results.json
```

Read `codeql_queries.md` before planning or interpreting CodeQL results.

If CodeQL only ran standard packs and no result was mapped to targeted
hypothesis-depth checks, mark degraded coverage:

```bash
python -m orchestrator.audit_flow skip \
  --repo /path/to/repo \
  --name semantic_verifier_depth \
  --tool codeql \
  --status degraded \
  --reason "CodeQL breadth coverage ran, but no targeted hypothesis-depth queries completed" \
  --uncovered H-001
```

Repeat `--uncovered` for every uncovered `semantic_review_id`.
Then stop for the semantic-depth degradation checkpoint described above.

## Split-Environment Verification

If the current machine lacks Semgrep or the selected semantic verifier, create a
bundle:

```bash
python scripts/create_verification_bundle.py \
  --audit-dir /path/to/repo/.audit \
  --skill-dir /path/to/graph-reasoning-code-audit \
  --output-dir /path/to/verification-bundle \
  --zip /path/to/verification-bundle.zip
```

Return `semgrep-results.json` plus the selected verifier output from the
verifier machine, then wrap/fuse them on the orchestrator machine.

## Fuse Evidence

Run:

```bash
python scripts/fuse_evidence.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --semgrep /path/to/repo/.audit/semgrep-results.json \
  --joern /path/to/repo/.audit/joern-results.json \
  --codeql /path/to/repo/.audit/codeql-results.json \
  --output /path/to/repo/.audit/evidence.json
```

Evidence fusion is deterministic. Missing Joern or CodeQL input files are read
as empty results, so do not fabricate placeholder results for the unselected
verifier. Do not replace fusion with ad hoc model merging.

## Guard Coverage

Run deterministic guard coverage only when a project-appropriate rule/script is
available:

```bash
python scripts/assess_guard_coverage.py \
  --repo-root /path/to/repo \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --semgrep /path/to/repo/.audit/semgrep-results.json \
  --joern /path/to/repo/.audit/joern-results.json \
  --output /path/to/repo/.audit/guard_coverage.json \
  --markdown /path/to/repo/.audit/guard_coverage.md
```

Run guard coverage only when its inputs match the selected verifier. If CodeQL
was selected and the guard-coverage helper only supports Joern-style inputs,
skip guard coverage and record `.audit/skips/guard_coverage.json`.

If all entries are `unknown`, skip applying coverage. If meaningful coverage is
present:

```bash
python scripts/apply_guard_coverage.py \
  --evidence /path/to/repo/.audit/evidence.json \
  --guard-coverage /path/to/repo/.audit/guard_coverage.json \
  --output /path/to/repo/.audit/evidence-final.json
```

Guard coverage may downgrade a hypothesis. It must not upgrade anything to
confirmed unless tool evidence proves a missing guard or vulnerable path.

## Machine Draft

`final_report.md` is only a machine fusion draft:

```bash
python scripts/render_report.py \
  --evidence /path/to/repo/.audit/evidence-final.json \
  --output /path/to/repo/.audit/final_report.md
```

The final user-facing report is written later after source validation.
