# Phase 3: Verification

Use this phase for Semgrep evidence, Joern CLI verification, CodeQL verification,
deterministic guard coverage, and evidence fusion.

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

## Joern CLI

First create verification tasks:

```bash
python scripts/run_joern_queries.py \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --output /path/to/repo/.audit/joern-results.json
```

Use Joern CLI, not Joern MCP. Keep CPG artifacts under `.audit/joern/`:

```bash
mkdir -p /path/to/repo/.audit/joern
joern-parse /path/to/repo \
  --output /path/to/repo/.audit/joern/cpg.bin.zip
joern /path/to/repo/.audit/joern/cpg.bin.zip
```

Prefer this order:

1. Reuse the full CPG for lightweight inventory and per-hypothesis narrow
   queries when the full CPG is already available or can be generated.
2. Query one hypothesis at a time. Restrict by method names, controller/service
   names, filenames, annotations, sink names, guard names, or resource ids from
   `hypotheses.json`. Do not run one broad query for every hypothesis at once.
3. Start with structural checks: endpoints, annotations, dangerous calls, file
   operations, raw SQL calls, auth attributes, service fan-out, and candidate
   guards.
4. Add data-flow/slicing only after structural evidence identifies concrete
   source/sink/guard symbols.
5. If full-CPG queries become slow, noisy, or error-prone, fall back to focused
   CPGs for:
   - one language
   - one entrypoint directory
   - one service/module directory
   - one hypothesis family
6. Use `--nooverlays` for focused first-pass structural CPGs. If
   reaching-definitions or data-flow becomes too expensive, cap it with
   `--max-num-def` and narrow the source directory further.
7. Mark only the uncovered language, directory, or hypothesis as skipped. Do not
   mark Joern globally skipped while smaller scopes are still feasible.

The anti-pattern is: full CPG plus one broad all-hypotheses data-flow query. The
preferred pattern is: full CPG plus one narrow query per hypothesis, with focused
CPG fallback.

Example focused C#/.NET controller pass:

```bash
joern-parse /path/to/repo/src/MyApp.HttpApi.Host/Controllers \
  --language csharpsrc \
  --nooverlays \
  --output /path/to/repo/.audit/joern/controllers-cpg.bin
joern --script /path/to/repo/.audit/joern/controllers-light.sc --nocolors --maxHeight 200
```

On Windows, Joern can be fragile with paths that contain spaces. Prefer putting
temporary CPGs and scripts under a no-space `.audit/joern/` path when possible,
or use Windows 8.3 short paths / forward-slash paths inside Joern scripts.

Read `joern_queries.md` before writing or interpreting Joern queries. Use Joern
primarily for:

- entrypoint-to-sensitive-action reachability
- guard dominance
- request/resource id data flow
- focused slicing around high-value paths

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

## CodeQL

Use CodeQL as an optional semantic/data-flow verifier. It is especially useful
for C#/.NET, JavaScript/TypeScript, Python, Go, Java/Kotlin, C/C++, Ruby, and
other languages with mature CodeQL extractors or query packs. Prefer CodeQL when:

- Joern language support is weak for the target code;
- build-aware type/data-flow precision matters;
- a standard CodeQL query can validate an injection, path, crypto, auth, or
  exposure hypothesis;
- the repo already has a usable build command or CodeQL database.

Do not make the audit depend on CodeQL. Many real repositories cannot build on
the audit machine because of private packages, missing SDKs, secrets, databases,
or monorepo setup. If CodeQL fails, record exact attempted language, source root,
build mode/command, error summary, and uncovered directories, then continue with
Semgrep, Joern, and source validation.

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
6. Normalize SARIF to `.audit/codeql-results.json`.
7. Treat CodeQL hits as evidence, not final vulnerability verdicts.

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
.audit/codeql/dbs/<language>/
.audit/codeql/results/<language>.sarif
.audit/codeql/cache/
.audit/codeql-results.json
```

Examples:

```bash
mkdir -p /path/to/repo/.audit/codeql/dbs /path/to/repo/.audit/codeql/results
mkdir -p /path/to/repo/.audit/codeql/cache

# No-build / build-mode none when supported by the target language and CodeQL version.
codeql database create /path/to/repo/.audit/codeql/dbs/javascript \
  --language=javascript \
  --source-root /path/to/repo \
  --build-mode=none

# Focused compiled-language build.
codeql database create /path/to/repo/.audit/codeql/dbs/csharp-api \
  --language=csharp \
  --source-root /path/to/repo \
  --command "dotnet build src/MyApp.Api/MyApp.Api.csproj"

codeql database analyze /path/to/repo/.audit/codeql/dbs/csharp-api \
  --format=sarifv2.1.0 \
  --output=/path/to/repo/.audit/codeql/results/csharp-api.sarif \
  --common-caches=/path/to/repo/.audit/codeql/cache \
  codeql/csharp-queries
```

On Windows, `database analyze` may try to create a user-home cache such as
`C:\Users\<user>\.codeql\compile-cache`. If that path is not writable, always
pass `--common-caches <repo>/.audit/codeql/cache`.

Normalize SARIF:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif /path/to/repo/.audit/codeql/results/csharp-api.sarif \
  --output /path/to/repo/.audit/codeql-results.json
```

For targeted custom queries, attach the result to one hypothesis:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif /path/to/repo/.audit/codeql/results/H-001.sarif \
  --hypothesis-id H-001 \
  --output /path/to/repo/.audit/codeql-results.json
```

Read `codeql_queries.md` before planning or interpreting CodeQL results.

## Split-Environment Verification

If the current machine lacks Semgrep, Joern, or CodeQL, create a bundle:

```bash
python scripts/create_verification_bundle.py \
  --audit-dir /path/to/repo/.audit \
  --skill-dir /path/to/graph-reasoning-code-audit \
  --output-dir /path/to/verification-bundle \
  --zip /path/to/verification-bundle.zip
```

Return `semgrep-results.json`, `joern-verified-results.json`, and
`codeql-results.json` from the verifier machine, then wrap/fuse them on the
orchestrator machine.

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

Evidence fusion is deterministic. Do not replace it with ad hoc model merging.

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
