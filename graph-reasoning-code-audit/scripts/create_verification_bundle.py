#!/usr/bin/env python3
"""Create a portable bundle for Semgrep/Joern/CodeQL verification on another machine."""

from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from pathlib import Path


ARTIFACTS = [
    "graph_context.json",
    "semantic_model.json",
    "hypothesis_backlog.json",
    "hypotheses.json",
    "semgrep-rules.yml",
    "joern-results.json",
    "codeql-results.json",
]


def write_runbook(bundle_dir: Path, repo_hint: str) -> None:
    runbook = f"""# Graph Reasoning Code Audit Verification Bundle

This bundle contains the current audit context and verification plans.

Expected external repo under test:

```text
{repo_hint}
```

## Semgrep

Run from the environment that has Semgrep and the target repo:

```bash
python scripts/run_semgrep.py \\
  --repo-root /path/to/target/repo \\
  --config semgrep-rules.yml \\
  --output semgrep-results.json
```

If you do not copy `scripts/run_semgrep.py`, run Semgrep directly:

```bash
semgrep --json --config semgrep-rules.yml /path/to/target/repo > semgrep-raw.json
```

Then normalize or wrap results before fusion.

## Joern CLI

Use Joern CLI, not Joern MCP. First generate a CPG for the target repo. Keep CPG
artifacts outside the source tree if possible:

```bash
mkdir -p .audit/joern
joern-parse /path/to/target/repo --output .audit/joern/cpg.bin.zip
joern .audit/joern/cpg.bin.zip
```

Use `joern-results.json` as the task plan. For each high-priority planned task,
run focused reachability, guard-dominance, data-flow, or slice queries. Produce
results in this shape:

```json
{{
  "hypothesis_id": "H-001",
  "task": "reachability|guard_dominance|dataflow|slice",
  "status": "hit|miss|error",
  "locations": [{{"path": "src/file.ts", "line": 10, "symbol": "handler"}}],
  "paths": [["entrypoint", "service", "sink"]],
  "details": {{}}
}}
```

Save all Joern results as:

```text
joern-verified-results.json
```

## CodeQL

Use CodeQL when available and appropriate for the target language. Prefer
focused project/module databases when full builds fail:

```bash
mkdir -p .audit/codeql/dbs .audit/codeql/results
mkdir -p .audit/codeql/cache
codeql resolve languages
codeql resolve packs
codeql database create .audit/codeql/dbs/<language> \
  --language=<language> \
  --source-root /path/to/target/repo
codeql database analyze .audit/codeql/dbs/<language> \
  --format=sarifv2.1.0 \
  --output=.audit/codeql/results/<language>.sarif \
  --common-caches=.audit/codeql/cache \
  codeql/<language>-queries
```

For compiled languages, add a focused `--command` build if required. If CodeQL
cannot build, or if the database is created but query packs/libraries are
missing, record attempted language, source root, build command/mode, query pack,
error, and uncovered directories.

Normalize SARIF before returning:

```bash
python scripts/normalize_codeql_sarif.py \
  --sarif .audit/codeql/results/<language>.sarif \
  --output codeql-results.json
```

## Return Files

Copy these files back to the orchestrator machine:

```text
semgrep-results.json
joern-verified-results.json
codeql-results.json
```
"""
    (bundle_dir / "RUNBOOK.md").write_text(runbook, encoding="utf-8")


def copy_if_exists(source_dir: Path, bundle_dir: Path, name: str) -> None:
    source = source_dir / name
    if source.exists():
        shutil.copy2(source, bundle_dir / name)


def copy_scripts(skill_dir: Path, bundle_dir: Path) -> None:
    scripts_dir = bundle_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    for name in ("run_semgrep.py", "run_joern_queries.py", "normalize_codeql_sarif.py"):
        source = skill_dir / "scripts" / name
        if source.exists():
            shutil.copy2(source, scripts_dir / name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", required=True, type=Path)
    parser.add_argument("--skill-dir", default=Path("graph-reasoning-code-audit"), type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repo-hint", default="/path/to/target/repo")
    parser.add_argument("--zip", dest="zip_path", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for artifact in ARTIFACTS:
        copy_if_exists(args.audit_dir, args.output_dir, artifact)
    copy_scripts(args.skill_dir, args.output_dir)
    write_runbook(args.output_dir, args.repo_hint)

    manifest = {
        "audit_dir": str(args.audit_dir),
        "artifacts": sorted(path.name for path in args.output_dir.iterdir()),
        "repo_hint": args.repo_hint,
    }
    (args.output_dir / "bundle-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.zip_path:
        args.zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in args.output_dir.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
