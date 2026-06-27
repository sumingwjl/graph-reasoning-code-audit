# CodeQL Query Notes

Use CodeQL as a hypothesis-driven verifier. Standard query packs are breadth
coverage. They are useful first passes, but they do not satisfy Phase 3 depth
validation unless a result is explicitly mapped to a triaged hypothesis and the
depth result records why that query validates or rejects the hypothesis.

## Role in This Workflow

- CodeQL is evidence, not final adjudication.
- Run CodeQL only when Phase 3 selects it as the primary semantic verifier, or
  when the phase summary records an explicit exception for extra coverage.
- The default Phase 3 policy is Semgrep first, then `semgrep_triage.json`,
  then exactly one semantic verifier: Joern CLI or CodeQL.
- SARIF results must be normalized to `.audit/codeql-results.json`.
- If `semgrep_triage.json.semantic_review_ids` is non-empty, CodeQL must also
  produce `.audit/semantic_verifier_depth_plan.json` and
  `.audit/semantic_verifier_depth_results.json`, or
  `.audit/skips/semantic_verifier_depth.json` with `status: "degraded"`.
- A CodeQL alert is usually `suspicious_pattern` until source validation proves
  attacker source, sink/action, missing guard/sanitizer, and citations.
- Build failures are normal in real audits. Record exact attempts and continue.

## Language Routing

Use these notes when deciding whether CodeQL is the better primary semantic
verifier for the current repository:

- C#/.NET: prefer CodeQL when a focused build/database is feasible and
  build-aware data flow matters.
- JavaScript/TypeScript: prefer CodeQL when standard query packs cover the
  hypothesis family; Semgrep still runs as the evidence collector.
- Python: prefer CodeQL for standard injection, path, crypto, or data-flow
  hypotheses when packs are installed.
- Java/Kotlin: choose CodeQL when query packs/builds are reliable; choose Joern
  instead for lightweight structure/reachability when build setup is fragile.
- Go: prefer CodeQL when module resolution works and query packs are available.
- C/C++: prefer CodeQL when build capture works; choose Joern when builds are
  incomplete but source-level CPG is feasible.

Do not interpret this routing table as permission to run both CodeQL and Joern
by default. If the unselected verifier is used for one high-risk item, record
the exception and its scope in the Phase 3 summary.

## Database Strategy

1. Reuse an existing CodeQL database if present.
2. Check `codeql resolve languages` and `codeql resolve packs`. Language
   extractors are not enough; analysis also needs query/library packs.
3. Try no-build/build-mode none for languages and CodeQL versions that support
   it.
4. For compiled languages, prefer focused project/module builds over full
   monorepo builds.
5. If full build fails, try the smallest project that contains the hypothesis
   entrypoint and sink.
6. If database creation works but query imports fail, record
   `database_created_but_queries_unavailable` and ask for query pack path or
   installation.
7. Record partial coverage rather than hiding failures.

## Evidence Shape

Normalize to:

```json
{
  "tool": "codeql",
  "status": "ok|skipped|error",
  "results": [
    {
      "hypothesis_id": "H-001",
      "task": "codeql",
      "status": "hit|miss|error",
      "locations": [
        {"path": "src/file.cs", "line": 10, "symbol": null}
      ],
      "paths": [
        ["src/controller.cs:12", "src/service.cs:44", "src/repo.cs:80"]
      ],
      "details": {
        "evidence_kind": "suspicious_pattern|taint_path|missing_guard|vuln_path",
        "rule_id": "cs/sql-injection",
        "message": "string"
      }
    }
  ]
}
```

Use `taint_path`, `missing_guard`, or `vuln_path` only when the CodeQL result
contains a concrete path that matches the hypothesis. Standard alerts without a
validated attacker source should remain `suspicious_pattern`.

## Depth Validation Shape

For each id in `semgrep_triage.json.semantic_review_ids`, write one depth result:

```json
{
  "hypothesis_id": "H-001",
  "coverage_mode": "depth",
  "query_intent": "Check whether request-controlled orderId reaches OrderRepository.Update without RequireOwner",
  "query_kind": "codeql_custom|codeql_standard_mapped",
  "query_file": ".audit/tool-work/codeql/queries/H-001.ql",
  "result_path": ".audit/tool-work/codeql/results/H-001.sarif",
  "status": "hit|miss|error|skipped",
  "locations": [],
  "paths": [],
  "source_symbols": ["OrderController.Update"],
  "sink_symbols": ["OrderRepository.Update"],
  "guard_symbols": ["RequireOwner"],
  "limitations": []
}
```

Use `codeql_standard_mapped` only when a standard CodeQL alert directly maps to
one hypothesis and the SARIF location/path addresses that hypothesis. Otherwise
record the standard pack result as breadth coverage and write a degraded depth
record or skip.

## Command Patterns

For custom queries, do not use `codeql query run` as the default path. Create a
local query pack and run it through `codeql database analyze` so language
libraries resolve consistently:

```yaml
# .audit/tool-work/codeql/qlpack.yml
name: audit/depth-queries
version: 0.0.1
dependencies:
  codeql/javascript-all: "*"
```

For JavaScript/TypeScript, first compile a minimal query before writing many
custom checks:

```ql
import javascript

from StringLiteral s
select s, "CodeQL library smoke test"
```

If the smoke query cannot resolve `javascript`, stop and mark semantic depth
degraded. Ask the user whether to retry with a correct CodeQL pack path, switch
verifier, narrow scope, or continue to source validation with the limitation.

Analyze with standard packs:

```bash
codeql database analyze .audit/tool-work/codeql/dbs/<language> \
  --format=sarifv2.1.0 \
  --output=.audit/tool-work/codeql/results/<language>.sarif \
  --common-caches=.audit/tool-work/codeql/cache \
  codeql/<language>-queries
```

Use `--common-caches=.audit/tool-work/codeql/cache` on Windows or locked-down systems to
avoid failures when the default user-home `.codeql` cache is not writable.

Normalize:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif .audit/tool-work/codeql/results/<language>.sarif \
  --output .audit/codeql-results.json
```

For one hypothesis-specific query run:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif .audit/tool-work/codeql/results/H-001.sarif \
  --hypothesis-id H-001 \
  --output .audit/codeql-results.json
```

When only standard packs completed and no targeted hypothesis-depth result was
produced, do not treat CodeQL as depth-complete. Write:

```bash
python -m orchestrator.audit_flow skip \
  --repo <repo> \
  --name semantic_verifier_depth \
  --tool codeql \
  --status degraded \
  --reason "CodeQL standard packs ran, but targeted hypothesis-depth validation did not complete" \
  --uncovered H-001
```

Then stop for the semantic-depth degradation checkpoint; do not continue to
evidence fusion until the user decision is recorded.

## Custom Query Discipline

- Prefer simple AST and configuration queries unless local examples prove the
  exact data-flow API for the installed CodeQL version.
- Do not write multiple complex `DataFlow`, `TaintTracking`, or routing queries
  before one minimal query compiles and runs.
- If a generated query fails on missing methods or type incompatibilities twice,
  stop trying to repair it in chat context. Mark that hypothesis result as
  `error` or mark semantic depth degraded, with the exact API failure in
  `limitations`.
- For Express factory patterns such as `createApp()` returning an `app`, direct
  top-level `app.get(...)` matching is incomplete. Record this as a limitation
  and let Phase 4 source validation inspect the factory manually.
- Standard query-pack alerts count as depth only when the alert directly maps to
  a triaged hypothesis and its location/path validates or rejects that
  hypothesis. Otherwise they are breadth coverage.
