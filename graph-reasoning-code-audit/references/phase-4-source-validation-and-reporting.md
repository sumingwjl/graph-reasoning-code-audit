# Phase 4: Source Validation and Reporting

Use this phase to validate evidence against source, decide whether to continue
with another backlog batch, and write the final report.

## Prepare Source-Validation Packet

Read `source_validation_playbooks.md`, then run:

```bash
python scripts/source_validate.py \
  --repo-root /path/to/repo \
  --hypotheses /path/to/repo/.audit/hypotheses.json \
  --evidence /path/to/repo/.audit/evidence.json \
  --dependency-findings /path/to/repo/.audit/dependency_findings.json \
  --secret-findings /path/to/repo/.audit/secret_findings.json \
  --min-dependency-severity medium \
  --max-dependency-findings 20 \
  --output /path/to/repo/.audit/source_validation_packet.json \
  --prompt-output /path/to/repo/.audit/source_validation_prompt.md
```

This script gathers evidence and source windows. It does not decide whether a
hypothesis is real.

Dependency findings are auxiliary context by default. Use
`--include-dependency-findings-as-items` only when the user explicitly asks for
source-level validation of specific dependency advisories.

Secret findings are auxiliary context by default, but high-confidence hardcoded
secret findings are often worth validating even when Phase 2 missed them. Use
`--include-secret-findings-as-items` when the user wants the current pass to
adjudicate secret exposure directly.

## Validate Against Source

Use the packet, prompt, playbooks, raw tool results, and source tree to write
`.audit/source_validation.md`.

For each hypothesis, record:

- final status: `confirmed`, `needs_review`, or `false_positive`
- source locations checked
- whether it passes the vulnerability scope gate: realistic actor trigger,
  security boundary or invariant, sensitive action/asset, missing effective
  control, and concrete harm
- guard/invariant chain observed in code
- concise evidence path from entrypoint/source to sink/action
- taint or slice path when Semgrep, Joern, CodeQL, or source tracing provides
  one; explicitly say `not available` or `not applicable` rather than inventing
  tool evidence
- minimal safe reproduction or payload when useful and non-destructive
- whether evidence confirms a missing guard, proves coverage, or remains
  inconclusive
- residual questions that depend on deployment config, extensions, or product
  policy

This is the first phase where vulnerability verdicts are allowed.

If source validation only proves an unsafe practice or missing
defense-in-depth, do not mark it `confirmed`. Use `false_positive` when an
effective guard exists, or `needs_review` when exploitability depends on
deployment/runtime evidence. Optional hardening notes must be separated from
vulnerability findings.

## Derived Findings

If source validation, Joern follow-up, Semgrep review, or manual source reading
discovers a new issue that was not in the packet, treat it as a derived
candidate:

1. Give it a temporary id such as `D-001`.
2. Record why it was noticed and which source lines triggered it.
3. Validate it with the same source-validation contract before calling it
   confirmed.
4. If the full contract cannot be checked in the current pass, leave it as
   `needs_review` and add it to the next hypothesis batch.

Do not move derived candidates directly into the confirmed section of
`audit_report.md`. Dangerous API exposure, scanner severity, or a tool result
named `confirmed` is not enough.

## Continue or Stop

After validating the current shortlist, inspect `hypothesis_backlog.json`.
Treat `hypotheses.json` as one batch.

Continue with another shortlist batch when:

- the user requested broad coverage or a full audit;
- high-priority backlog items remain unvalidated;
- the first batch found no issues but large entrypoint families or A-H classes
  remain uncovered;
- source validation discovered new entrypoints, guards, sinks, or dependency
  context that change prioritization.

Stop and report when:

- the user requested a quick pass or PoC run;
- remaining backlog items are low priority, duplicate, deferred, or blocked;
- current findings are enough for the requested decision;
- time or tool limits make further validation impractical.

If stopping with unvalidated backlog items, say so explicitly in
`audit_report.md`.

## User-Facing Report

Write `.audit/audit_report.md` directly. Do not use a brittle Markdown parser to
transform `source_validation.md`.

Use:

- `source_validation.md`
- `source_validation_packet.json`
- `evidence.json` or `evidence-final.json`
- `semgrep-results.json`
- `joern-results.json`
- `codeql-results.json`
- `dependency_findings.json`
- `sca_report.md`
- `secret_findings.json`
- `secret_report.md`
- `hypothesis_backlog.json`
- checked source files

The final report must include:

- scope and tool coverage
- blocked or skipped tools
- for each skipped verification tool, exact uncovered language/directories and
  how that limits confirmed/needs-review conclusions
- backlog coverage: validated, unvalidated, deferred, and rejected counts by
  class or coverage area
- confirmed source-code vulnerabilities
- confirmed vulnerability totals that exclude hardening/code-practice
  observations
- whether each confirmed item is confirmed by machine evidence, source
  validation, or both
- needs-review items and exact follow-up checks
- false positives and the guard/invariant chain that disproves them
- derived candidates, separated from confirmed findings, with follow-up checks
- SCA summary, clearly separated from source-code findings
- secret exposure summary, clearly separated from generic source-code logic bugs
- optional hardening observations, clearly separated and not counted as
  vulnerabilities
- limitations, especially missing CPG, Semgrep timeout, unsupported languages,
  or contaminated graph inputs

Use this Markdown shape for `.audit/audit_report.md`:

~~~md
# Code Audit Report

## Executive Summary

- Confirmed vulnerabilities: N
- Needs review: N
- False positives: N
- Secret exposure findings: N confirmed / N needs review
- SCA findings: N high-priority advisories, reported separately

## Scope and Tool Coverage

| Area | Status | Notes |
| --- | --- | --- |
| Graphify | used/degraded/skipped | ... |
| Semgrep | used/partial/skipped | ... |
| Joern CLI | used/partial/skipped | ... |
| CodeQL | used/partial/skipped | ... |
| Betterleaks | used/partial/skipped | ... |
| OSV/SCA | used/partial/skipped | ... |

## Confirmed Vulnerabilities

### H-001 [HIGH] Short Vulnerability Title

**Impact**

Concrete attacker impact in one short paragraph.

**Affected Code**

- `path/to/file.ext:10` - why this line matters
- `path/to/other.ext:42` - why this line matters

**Evidence Path**

```text
entrypoint or trigger
  -> controller/handler
  -> service/helper
  -> missing or ineffective guard
  -> sensitive sink/action
```

**Taint / Slice Path**

```text
status: available|not_available|not_applicable
source: attacker-controlled field/trigger
propagation:
  -> step 1
  -> step 2
sink: sensitive action/interpreter/state write
missing guard: expected guard or invariant
tool evidence: Semgrep|Joern|CodeQL|source-validation only
```

If no machine taint/slice path exists, write `status: not_available` and do not
claim tool confirmation.

**Minimal Reproduction / Payload**

```http
Safe minimal request, command, state transition, or pseudocode.
Use placeholders and redaction for real secrets, destructive values, tenant ids,
hostnames, and credentials.
```

If a payload would be unsafe, destructive, or deployment-specific, write:
`Not provided: <reason>. Verification steps: <safe steps>.`

**Why Confirmed**

Source-grounded explanation of why the guard is missing/bypassable and why the
scope gate is satisfied.

**Fix**

Concrete remediation steps.

## Needs Review

For each item, include exact missing evidence and next verification action. Do
not include exploit payloads for unconfirmed items.

## False Positives

For each item, include the guard/invariant chain that disproves the hypothesis.

## Secret Exposure

Separate confirmed effective secrets from scanner-only matches. Never print real
secret values; use redacted values from `secret_report.md`.

## SCA Summary

Keep dependency advisories separate from source-code vulnerability conclusions.

## Deferred Backlog and Limitations

List unvalidated classes, skipped tools, partial language coverage, and why that
limits conclusions.
~~~

This is the primary artifact to present to the user.
