---
name: graph-reasoning-code-audit
description: Use this skill to run a modular graph-reasoning code audit workflow focused on exploitable source-code vulnerabilities, not code-quality or generic hardening review. It consumes graphify deep repository context, extracts a security semantic model, builds a broad hypothesis backlog, runs Betterleaks or compatible secret scanning for hardcoded credentials, selects verification batches, uses SCA as auxiliary context, verifies with Semgrep, Joern CLI, and CodeQL when available, validates evidence against source, and writes a user-facing audit report. Use for repository security review, hypothesis-driven code audit, graphify-assisted audit, secret exposure review, and source-grounded vulnerability triage.
---

# Graph Reasoning Code Audit

Use this skill as an orchestrator. Keep this file small; load phase references
only when the phase is about to run.

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
- Do not use AST-only graphify output as the normal input for this audit. Prefer
  graphify deep/semantic output; if only AST output is available, record degraded
  context and ask whether to rerun graphify deep mode before hypotheses.
- Exclude previous audit reports, generated findings, `.audit/`, scanner
  outputs, and old `graphify-out/` directories from the graphify corpus.
- If `graph_context.json` reports input contamination, stop hypothesis
  generation and rerun graphify on a clean source tree.
- Do not use Joern MCP. Use Joern CLI directly. Use CodeQL as an optional
  semantic verifier when available, especially where Joern language support is
  weak or build-aware data flow is useful.
- Do not call a hypothesis confirmed before source validation.
- Do not call a derived observation confirmed until it is promoted to a
  hypothesis candidate and validated with the same source contract.
- Keep SCA findings separate from source-code findings unless the user asks to
  deep-dive a specific advisory.
- Keep secret scanner matches separate from generic source-code findings until
  source/context validation proves the secret is effective or harmful.
- Treat `hypotheses.json` as the current verification batch, not complete audit
  coverage.
- The final user-facing report is `.audit/audit_report.md`, written by the LLM
  after source validation.

## Load References

Always read:

- `references/schemas.md` before creating or modifying JSON artifacts.
- `references/hypothesis_types.md` before generating backlog or shortlist.

Load phase references only when needed:

- `references/phase-0-setup-and-graphify.md` for tool checks, graphify deep mode,
  input hygiene, and `graph_context.json`.
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
- `references/semgrep_templates.md` only when generating Semgrep rules.
- `references/joern_queries.md` only when planning or interpreting Joern CLI
  verification.
- `references/codeql_queries.md` only when planning or interpreting CodeQL
  verification.
- `references/source_validation_playbooks.md` before source validation.

## Workflow

1. Setup and Graphify
   - Confirm local tools and paths.
   - Ensure graphify deep/semantic extraction exists; AST-only graphify output is
     degraded context.
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

5. Verification
   - Generate and run Semgrep evidence rules.
   - Plan and run Joern CLI checks when possible.
   - Run CodeQL when available and appropriate for the repo language/build
     situation.
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
- `.audit/semgrep-rules.yml`
- `.audit/semgrep-results.json`
- `.audit/joern-results.json`
- `.audit/codeql/dbs/<language>/`
- `.audit/codeql/results/<language>.sarif`
- `.audit/codeql-results.json`
- `.audit/evidence.json`
- `.audit/guard_coverage.json`
- `.audit/evidence-final.json`
- `.audit/final_report.md`
- `.audit/source_validation_packet.json`
- `.audit/source_validation_prompt.md`
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
