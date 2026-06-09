# Joern Query Notes

Keep Joern use hypothesis-driven. Avoid full-repo exploratory queries unless the
repo is small or the user asks for broad discovery.

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

## Query Strategy

1. Identify symbols from `hypotheses.json`.
2. Reuse a full CPG when available, but query only one hypothesis at a time.
3. Restrict queries by concrete filenames, method names, annotations, sink names,
   guard names, resource identifiers, or service classes.
4. Use CPG call graph queries for entrypoint-to-sink reachability.
5. Use data-flow queries only for hypotheses that have concrete source and sink names.
6. Use slicing to emit compact JSON for final evidence.

## Full CPG First, Focused CPG Fallback

Full-project CPGs are useful as a shared structural index. The risky pattern is
not "full CPG"; it is "full CPG plus broad all-hypothesis data-flow queries".

Recommended order:

1. Build or reuse the full CPG.
2. Run lightweight inventory queries on the full CPG.
3. Run one narrow query per hypothesis on the full CPG.
4. If a specific query is slow, noisy, or errors, create a focused CPG for the
   relevant language/directory/module/hypothesis and retry there.

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
joern-parse <dir> --language csharpsrc --nooverlays --output .audit/joern/controllers-cpg.bin
joern-parse <dir> --language csharpsrc --max-num-def 20 --output .audit/joern/focused-cpg.bin
```

For Windows paths with spaces, prefer short paths or forward slashes inside
scripts:

```scala
@main def main() = {
  importCpg("D:/Code/AICODE~1/project/.audit/joern/controllers-cpg.bin")
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
