# Phase 0: Setup and Graphify

Use this phase for tool checks, graphify deep/semantic extraction, corpus
hygiene, and `graph_context.json`.

## Tool Check

Check tools before running the workflow:

```bash
graphify --help
osv-scanner --version
betterleaks --help
semgrep --version
joern-parse --help
joern --help
codeql version
python --version
```

If a tool is missing or installed outside PATH, ask the user for its location.
On systems where `python` is unavailable, use `python3` or the user-provided
Python path consistently for all scripts.

Joern MCP is out of scope. Use Joern CLI directly, or record Joern as skipped.
CodeQL is optional. If `codeql` is missing from the current shell PATH, ask for
its path or record CodeQL as unavailable for this pass.
Betterleaks is preferred for secret scanning. If `betterleaks` is missing from
the current shell PATH, ask for its executable path before falling back to
Gitleaks, TruffleHog, or an `rg` keyword pass.

## Corpus Hygiene

Before running graphify, exclude generated audit artifacts and previous reports
from the source corpus. Move these outside the repository or ensure graphify does
not ingest them:

- `.audit/`
- old `graphify-out/`
- `security_audit_report.md`
- `audit_report.md`
- `source_validation.md`
- `final_report.md`
- `hypotheses.json`
- `hypothesis_backlog.json`
- `evidence.json`
- `semgrep-results.json`
- `joern-results.json`
- `osv-results.json`
- scanner reports or verification bundles
- secret scanner reports such as `betterleaks-*.json` and
  `secret_findings*.json`

If `graph_context.json` later contains `graphify_input_warnings`, stop
hypothesis generation and rerun graphify on a clean corpus.

## Graphify Deep Mode

For this audit skill, graphify should provide repository structure plus semantic
relationships. AST-only graphify output is degraded context and should not be
used as the normal basis for `semantic_model.json` or `hypothesis_backlog.json`.

If the dedicated graphify skill/slash command is installed, use it instead of
manually recreating graphify internals. The graphify skill knows how to run AST
and semantic extraction together, cache semantic fragments, merge hyperedges, and
generate `graph.json` / `GRAPH_REPORT.md`.

When using the assistant slash command, always include deep mode:

```bash
/graphify /path/to/repo --mode deep
```

For audit use, prefer also skipping heavy visualization when supported:

```bash
/graphify /path/to/repo --mode deep --no-viz
```

For terminal/headless environments, try the locally supported entrypoint:

```bash
graphify /path/to/repo --mode deep
```

If the installed CLI exposes `extract` instead:

```bash
graphify extract /path/to/repo \
  --backend <gemini|kimi|claude|openai|deepseek|ollama> \
  --out /path/to/repo/.audit
```

For large repositories, consider scanning a subfolder, reducing concurrency, or
setting model/token options. Deep graphify output is repository context, not a
security verdict.

Do not manually run only graphify AST extraction for this workflow unless the
user explicitly accepts degraded graph context. If an LLM starts with AST-only
extraction, stop after normalization and either rerun deep mode or mark the pass
as degraded before hypothesis generation.

## Accept Existing Graphify Output

If `graph.json` and `GRAPH_REPORT.md` already exist, inspect the output
directory before rerunning. Semantic/deep output may include:

- `cache/semantic/`, `semantic/`, or `semantics/`
- `.graphify_cached.json` with semantic nodes/edges/hyperedges
- `.graphify_extract.json` containing semantic nodes/edges merged with AST
- inferred semantic edges, communities, or hyperedges
- report lines such as `Extraction: ... INFERRED`

Do not rely only on token-cost wording in `GRAPH_REPORT.md`.

If the output lacks semantic artifacts and hyperedges, treat it as AST-only or
non-deep output. Do not proceed to normal hypothesis generation without an
explicit degraded-context note or a user decision to rerun graphify deep mode.

## Normalize

Run:

```bash
python scripts/normalize_graphify.py \
  --graph-json /path/to/graph.json \
  --graph-report /path/to/GRAPH_REPORT.md \
  --repo-root /path/to/repo \
  --output /path/to/repo/.audit/graph_context.json
```

Check the normalized output:

- `graphify_semantic_artifacts.semantic_file_count` should be greater than zero
  for semantic/deep output.
- `graphify_quality.ast_only_likely` should be false for the normal audit path.
- `graphify_quality.warnings` should be empty or explicitly accepted as a
  degraded-context limitation.
- `hyperedges` should be preserved when graphify produced them.
- `graphify_input_warnings` must be empty before continuing.

Use `graph_context.json` to select files for deeper reading. Treat graphify as a
context compressor, not a vulnerability oracle.

## Graphify Quality Gate

Before Phase 2:

- Stop if `graphify_input_warnings` is non-empty.
- Stop or ask the user before continuing if `graphify_quality.ast_only_likely`
  is true.
- If continuing without deep semantic artifacts, write this limitation into
  `semantic_model.json`, `hypothesis_backlog.json`, and `audit_report.md`.
- Never describe `graph_context.json` itself as the extracted security semantic
  model. Security semantics are produced later by this audit skill from graphify
  context plus source review.
