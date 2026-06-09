# CodeQL Query Notes

Use CodeQL as a hypothesis-driven verifier. Prefer standard query packs first,
then focused custom queries only when the hypothesis has concrete source/sink
symbols.

## Role in This Workflow

- CodeQL is evidence, not final adjudication.
- SARIF results must be normalized to `.audit/codeql-results.json`.
- A CodeQL alert is usually `suspicious_pattern` until source validation proves
  attacker source, sink/action, missing guard/sanitizer, and citations.
- Build failures are normal in real audits. Record exact attempts and continue.

## Language Routing

Suggested default:

- C#/.NET: CodeQL first for semantic/data-flow, Joern for route/annotation and
  structural checks.
- JavaScript/TypeScript: CodeQL + Semgrep first, Joern optional.
- Python: CodeQL + Semgrep first, Joern optional.
- Java/Kotlin: Joern and CodeQL are both useful; use both for high-risk items.
- Go: CodeQL + Semgrep, with Joern if local parsing works well.
- C/C++: CodeQL is useful when build capture works; Joern can still provide
  source-level CPG when builds are incomplete.

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

## Command Patterns

Analyze with standard packs:

```bash
codeql database analyze .audit/codeql/dbs/<language> \
  --format=sarifv2.1.0 \
  --output=.audit/codeql/results/<language>.sarif \
  --common-caches=.audit/codeql/cache \
  codeql/<language>-queries
```

Use `--common-caches=.audit/codeql/cache` on Windows or locked-down systems to
avoid failures when the default user-home `.codeql` cache is not writable.

Normalize:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif .audit/codeql/results/<language>.sarif \
  --output .audit/codeql-results.json
```

For one hypothesis-specific query run:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif .audit/codeql/results/H-001.sarif \
  --hypothesis-id H-001 \
  --output .audit/codeql-results.json
```
