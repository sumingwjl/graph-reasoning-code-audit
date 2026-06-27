# Joern Query Notes

Keep Joern use hypothesis-driven. Avoid full-repo exploratory queries unless the
repo is small or the user asks for broad discovery. Joern querydb/prebuilt rules
and broad CPG inventory are breadth coverage. They do not satisfy Phase 3 depth
validation unless each triaged hypothesis receives a targeted result.

## Verification Tasks

- Reachability: can an entrypoint reach a sensitive action?
- Guard dominance: does an authz/ownership/state guard dominate the sensitive action?
- Data flow: can request-controlled identifiers or payload fields reach resource lookup/write sinks?
- Slicing: produce a compact JSON slice around the path so evidence fusion can map it back to source.

## Evidence Shape

Normalize Joern output to:

```json
{
  "hypothesis_id": "H-001",
  "task": "reachability|guard_dominance|dataflow|slice",
  "status": "hit|miss|error",
  "locations": [
    {
      "path": "src/file.ext",
      "line": 10,
      "symbol": "handler"
    }
  ],
  "paths": [
    ["entrypoint", "service", "sink"]
  ],
  "details": {}
}
```

Use `status: hit` for a concrete tool match and describe the evidence kind in
`details.evidence_kind`. Avoid `status: confirmed` for Joern-only results unless
the Joern output itself contains a full validated path. Raw API exposure such as
`ExecuteCommand`, `Process.Start`, `File.OpenRead`, or permissive annotations
should normally be `evidence_kind: suspicious_pattern`, not `vuln_path`.

## Depth Validation Shape

For each id in `semgrep_triage.json.semantic_review_ids`, write one depth result
to `.audit/semantic_verifier_depth_results.json`:

```json
{
  "hypothesis_id": "H-001",
  "coverage_mode": "depth",
  "query_intent": "Check controller-to-service reachability and owner guard dominance",
  "query_kind": "joern_structural|joern_dataflow|joern_slice",
  "query_file": ".audit/tool-work/joern/queries/H-001.sc",
  "result_path": ".audit/tool-work/joern/results/H-001.json",
  "status": "hit|miss|error|skipped",
  "locations": [],
  "paths": [],
  "source_symbols": ["OrderController.Update"],
  "sink_symbols": ["OrderService.Update"],
  "guard_symbols": ["RequireOwner"],
  "limitations": []
}
```

Before running these checks, write
`.audit/semantic_verifier_depth_plan.json` with one task per
`semantic_review_id`. Planned tasks are not evidence. They must be replaced by
`hit`, `miss`, `error`, or `skipped` depth results, or the main agent must mark
semantic-verifier depth as degraded.

## Query Strategy

1. Identify symbols from `hypotheses.json`.
2. Reuse a full CPG when available, but query only one hypothesis at a time.
3. Restrict queries by concrete filenames, method names, annotations, sink names,
   guard names, resource identifiers, or service classes.
4. Use CPG call graph queries for entrypoint-to-sink reachability.
5. Use data-flow queries only for hypotheses that have concrete source and sink names.
6. Use slicing to emit compact JSON for final evidence.
7. If only querydb/prebuilt rules or inventory queries ran, record that as
   breadth coverage and mark depth validation degraded.

## Full CPG First, Focused CPG Fallback

Full-project CPGs are useful as a shared structural index. The risky pattern is
not "full CPG"; it is "full CPG plus broad all-hypothesis data-flow queries".

Recommended order:

1. Build or reuse the full CPG.
2. Run lightweight inventory queries on the full CPG.
3. Run querydb/prebuilt or equivalent broad checks when available.
4. Run one narrow query per hypothesis on the full CPG.
5. If a specific query is slow, noisy, or errors, create a focused CPG for the
   relevant language/directory/module/hypothesis and retry there.

Focused CPGs are fallback, not the default. They are appropriate for very large
projects, memory pressure, unsupported mixed-language directories, or a single
hypothesis whose full-CPG query is too slow/noisy. They should not be used to
avoid full-CPG breadth coverage on small or medium repositories.

For small/medium Java/Spring repositories, prefer a full source CPG first, then
run narrow queries against symbols from the hypothesis.

Full-project CPG plus default overlays can trigger expensive reaching-definition
passes, especially in C#/.NET or large monorepos. Treat that as a reason to
narrow scope for the affected hypothesis, not as proof that Joern is unusable.

Focused fallback order:

1. Build a CPG for the smallest directory that contains the relevant entrypoints.
2. Run structural queries first.
3. Build a second CPG for the service/module directory if the entrypoint calls
   into a concrete service worth tracing.
4. Only then attempt data-flow or slicing on named methods.

Useful parse options:

```bash
joern-parse <dir> --language csharpsrc --nooverlays --output .audit/tool-work/joern/controllers-cpg.bin
joern-parse <dir> --language csharpsrc --max-num-def 20 --output .audit/tool-work/joern/focused-cpg.bin
```

Java/Spring structural query examples should prefer stable CPG primitives:

```scala
cpg.method
  .filter(m => m.filename.endsWith(".java"))
  .filter(m => m.annotation.name(".*(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping).*").nonEmpty)
  .map(m => s"${m.fullName} @ ${m.filename}:${m.lineNumber.getOrElse(-1)}")
  .take(200)
  .foreach(println)

cpg.call
  .name(".*(get|resolve|readAllBytes|copy|newInputStream|newOutputStream).*")
  .filter(c => c.code.matches(".*(Paths|Files|File).*"))
  .map(c => s"${c.name} :: ${c.code} @ ${c.filename}:${c.lineNumber.getOrElse(-1)}")
  .take(100)
  .foreach(println)

cpg.call
  .filter(c => c.code.matches(".*(MessageDigest|getInstance|MD5|MD5Util).*"))
  .map(c => s"${c.name} :: ${c.code} @ ${c.filename}:${c.lineNumber.getOrElse(-1)}")
  .take(100)
  .foreach(println)
```

If a method such as `filename` is unavailable in the local Joern version, inspect
one node interactively and adjust to the local stable location field. Record the
API mismatch in `limitations`; do not claim depth coverage if the query did not
execute.

For Windows paths with spaces, prefer short paths or forward slashes inside
scripts:

```scala
@main def main() = {
  importCpg("D:/Code/AICODE~1/project/.audit/tool-work/joern/controllers-cpg.bin")
  println(cpg.method.size)
}
```

## Lightweight Structural Queries

Endpoint and controller inventory:

```scala
cpg.method
  .filter(m => m.filename.contains("Controller.cs"))
  .map(m => s"${m.fullName} @ ${m.filename}:${m.lineNumber.getOrElse(-1)}")
  .take(100)
  .foreach(println)

cpg.annotation
  .map(a => s"${a.name}:${a.code}")
  .take(200)
  .foreach(println)
```

Auth annotations and alternate entrypoints:

```scala
cpg.annotation
  .name(".*(Authorize|AllowAnonymous|HttpGet|HttpPost|Route).*")
  .map(a => s"${a.name}:${a.code}")
  .take(200)
  .foreach(println)
```

Dangerous file/path/download operations:

```scala
cpg.call
  .name(".*(File|Path|OpenRead|ReadAll|WriteAll|Download).*")
  .map(c => s"${c.name} :: ${c.code}")
  .take(100)
  .foreach(println)
```

Raw SQL and command execution:

```scala
cpg.call
  .name(".*(ExecuteSql|FromSql|SqlQuery|Process\\.Start|Start).*")
  .map(c => s"${c.name} :: ${c.code}")
  .take(100)
  .foreach(println)
```

When only breadth coverage completed, write:

```bash
python -m orchestrator.audit_flow skip \
  --repo <repo> \
  --name semantic_verifier_depth \
  --tool joern \
  --status degraded \
  --reason "Joern querydb or broad inventory ran, but targeted hypothesis-depth validation did not complete" \
  --uncovered H-001
```
