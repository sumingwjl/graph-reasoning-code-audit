# Phase 0: Setup and Graphify

Use this phase for tool checks, Graphify mode selection, corpus hygiene, code
graph extraction, and `graph_context.json`.

## Tool Check

Check tools before running the workflow:

```bash
osv-scanner --version
betterleaks --help
semgrep --version
joern-parse --help
joern --help
codeql version
python --version
```

Graphify is a required capability for the normal workflow, but the CLI is only
a fallback. Prefer the installed official graphify skill or slash command first.
Check `graphify --help` only when a terminal CLI fallback is needed.

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

Before running Graphify, create or update `.graphifyignore` in the project
root. Graphify reads `.gitignore` automatically and merges `.graphifyignore`
after it. The syntax is the same as `.gitignore`, including `!` negation.
Subdirectory scoping works like Git. `.graphifyignore` can exclude more files;
it does not re-include files already excluded by `.gitignore`.

Use `.graphifyignore` to remove audit-irrelevant binary/media assets and
generated outputs. For example:

```gitignore
.audit/
graphify-out/
security_audit_report.md
audit_report.md
source_validation.md
final_report.md
**/logo*/
**/logos/**
**/brand/**
**/branding/**
**/assets/**/*.png
**/assets/**/*.jpg
**/assets/**/*.jpeg
**/assets/**/*.gif
**/assets/**/*.webp
**/assets/**/*.svg
```

Keep non-code files only when they plausibly affect security reasoning, such as
architecture docs, OpenAPI specs, threat models, deployment notes, protocol
diagrams, screenshots of admin/security UI, or deployment topology. Exclude
product logos, brand marks, icons, decorative marketing images, and large
unrelated media folders by default.

If `graph_context.json` later contains `graphify_input_warnings`, stop
hypothesis generation and rerun graphify on a clean corpus.

## Graphify Mode

The first user checkpoint must choose the Graphify mode. Recommend `ast` for
code audit unless the user explicitly wants security-relevant non-code files
included.

Mode choices:

| Mode | Default | Use when | Expected Graphify behavior |
| --- | --- | --- | --- |
| `ast` | yes | Source-code audit with no important non-code evidence | Code files produce structural graph data through AST/tree-sitter/call/import extraction. Semantic cache, inferred edges, and hyperedges may be absent. This is not degraded. |
| `deep` | no | Security-relevant docs, diagrams, OpenAPI specs, threat models, deployment notes, or admin/security screenshots should be included | Code still uses structural extraction; non-code files may use semantic extraction. |
| `existing` | no | A suitable graphify output already exists | Normalize and quality-check the existing graph. |

If the dedicated graphify skill/slash command is installed, use it instead of
manually recreating graphify internals.

For `ast` mode, use Graphify normally after corpus filtering:

```bash
/graphify /path/to/repo --no-viz
```

If the installed Graphify detects a code-only corpus and skips semantic
extraction, continue. That is the expected path for code audit.

For `deep` mode, include deep mode:

```bash
/graphify /path/to/repo --mode deep
```

Prefer skipping heavy visualization when supported:

```bash
/graphify /path/to/repo --mode deep --no-viz
```

For terminal/headless environments, try the locally supported entrypoint and
match the approved mode:

```bash
graphify /path/to/repo
graphify /path/to/repo --mode deep
```

If the installed CLI exposes `extract` instead:

```bash
graphify extract /path/to/repo \
  --backend <gemini|kimi|claude|openai|deepseek|ollama> \
  --out /path/to/repo/.audit
```

For large repositories, consider scanning a subfolder, reducing concurrency, or
setting model/token options. Graphify output is repository context, not a
security verdict.

## Accept Existing Graphify Output

If `graph.json` and `GRAPH_REPORT.md` already exist, inspect the output
directory before rerunning. Useful code-audit output should include code nodes,
code edges, and preferably structural import/call/reference relationships.

Deep output may additionally include:

- `cache/semantic/`, `semantic/`, or `semantics/`
- `.graphify_cached.json` with semantic nodes/edges/hyperedges
- `.graphify_extract.json` containing semantic nodes/edges merged with AST
- inferred semantic edges, communities, or hyperedges
- report lines such as `Extraction: ... INFERRED`

Do not rely only on token-cost wording in `GRAPH_REPORT.md`.

If the output lacks semantic artifacts and hyperedges, treat it as AST/code
graph output. This is acceptable for `ast` mode. Do not proceed only when code
nodes, code edges, or structural code relationships are missing.

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

- `graphify_code_quality.has_code_graph` should be true.
- `graphify_code_quality.has_code_edges` should be true.
- `graphify_code_quality.has_structural_code_edges` should usually be true for
  a useful code graph.
- `graphify_quality.ast_only_likely` may be true in `ast` mode. This is normal
  and not a degradation marker by itself.
- `graphify_quality.has_semantic_artifacts` is optional. It is expected only
  when `deep` mode included non-code files.
- `hyperedges` should be preserved when Graphify produced them, but they are not
  required for code-only audit.
- `graphify_input_warnings` must be empty before continuing.

Use `graph_context.json` to select files for deeper reading. Treat graphify as a
context compressor, not a vulnerability oracle.

## Graphify Quality Gate

Before Phase 2:

- Stop if `graphify_input_warnings` is non-empty.
- Stop if code nodes are missing.
- Stop if code edges are missing.
- Stop if structural code edges are missing, unless manual inspection shows the
  graph still gives enough file/symbol orientation for the current scope. If the
  user explicitly accepts degraded graph context, record it:

```bash
python -m orchestrator.audit_flow skip --repo /path/to/repo \
  --name graph_context_degraded \
  --tool graphify \
  --reason "code graph structure is incomplete; user approved degraded graph context" \
  --uncovered "complete Graphify code structure"
```

- If continuing with incomplete code graph structure, write this limitation into
  `semantic_model.json`, `hypothesis_backlog.json`, and `audit_report.md`.
- Never describe `graph_context.json` itself as the extracted security semantic
  model. Security semantics are produced later by this audit skill from graphify
  context plus source review.
