# Phase 1: SCA Context

Use this phase for dependency, framework, and configuration scanner context.
SCA is auxiliary context for source-code review, not proof of a source-code
vulnerability by itself.

## Collect Dependency Context

Run early, in parallel with source-code context work:

```bash
python scripts/collect_dependency_context.py \
  --repo-root /path/to/repo \
  --output /path/to/repo/.audit/dependency_context.json
```

This inventories manifests, lockfiles, framework hints, deployment config, and
suggested scanners. It does not query vulnerability databases and does not
decide exploitability.

## OSV-Scanner

When OSV-Scanner is available:

```bash
osv-scanner scan --recursive --format json \
  --output /path/to/repo/.audit/osv-results.json \
  /path/to/repo
```

OSV-Scanner may return a non-zero exit code when vulnerabilities are found.
Treat the JSON output as authoritative for SCA reporting.

Convert and render:

```bash
python scripts/convert_osv_results.py \
  --osv-results /path/to/repo/.audit/osv-results.json \
  --repo-root /path/to/repo \
  --output /path/to/repo/.audit/dependency_findings.json

python scripts/render_sca_report.py \
  --dependency-findings /path/to/repo/.audit/dependency_findings.json \
  --output /path/to/repo/.audit/sca_report.md
```

## Optional SCA Subagent

For large audits, run SCA in a separate subagent so dependency/advisory context
does not crowd the main source-code audit context. The subagent consumes:

- `dependency_context.json`
- scanner outputs
- manifests and lockfiles
- relevant configuration files

It writes:

- `dependency_findings.json`
- `sca_report.md`

## SCA Contract

- Record advisory id, affected range, fixed version, trigger conditions, and
  usage/config evidence.
- Highlight findings that may affect A-H hypotheses, exploitability, or audit
  priority.
- Do not require source-level adjudication for every dependency advisory.
- Do not turn a version match alone into a source-code vulnerability.
- Attach dependency findings as auxiliary context during source validation unless
  the user explicitly asks to deep-dive an advisory as a source-validation item.
