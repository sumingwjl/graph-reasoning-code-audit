#!/usr/bin/env python3
"""Run Semgrep and normalize JSON output."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def normalize(raw: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for item in raw.get("results", []):
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        results.append(
            {
                "hypothesis_id": metadata.get("hypothesis_id"),
                "rule_id": item.get("check_id"),
                "status": "hit",
                "path": item.get("path"),
                "line": start.get("line"),
                "message": extra.get("message"),
                "metadata": metadata,
            }
        )
    return results


def load_json(path: Path | None) -> Any:
    if not path or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def ref_to_path(value: Any) -> str | None:
    if isinstance(value, dict):
        raw = value.get("path") or value.get("file") or value.get("location")
    else:
        raw = value
    if not isinstance(raw, str):
        return None
    text = raw.strip().replace("\\", "/")
    if not text:
        return None
    if ":" in text:
        maybe_path, maybe_line = text.rsplit(":", 1)
        if maybe_line.isdigit():
            text = maybe_path
    return text.lstrip("./")


def hypothesis_scan_paths(hypotheses_path: Path | None, repo_root: Path, max_targets: int) -> list[Path]:
    payload = load_json(hypotheses_path)
    hypotheses = payload.get("hypotheses", []) if isinstance(payload, dict) else payload
    if not isinstance(hypotheses, list):
        return []

    paths: list[Path] = []
    seen: set[str] = set()
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        for key in ("evidence_seed", "entrypoints", "sensitive_actions"):
            values = hypothesis.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                ref = ref_to_path(value)
                if not ref:
                    continue
                candidate = (repo_root / ref).resolve()
                try:
                    rel_key = str(candidate.relative_to(repo_root.resolve())).replace("\\", "/")
                except ValueError:
                    continue
                if rel_key in seen or not candidate.is_file():
                    continue
                seen.add(rel_key)
                paths.append(candidate)
                if len(paths) >= max_targets:
                    return paths
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--semgrep-bin", default="semgrep")
    parser.add_argument("--hypotheses", type=Path, help="Derive focused scan paths from hypothesis evidence seeds.")
    parser.add_argument("--scan-path", action="append", default=[], help="Explicit file or directory path to scan.")
    parser.add_argument("--max-targets", type=int, default=80)
    parser.add_argument("--run-timeout", type=int, default=120, help="Overall Semgrep subprocess timeout in seconds.")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not shutil.which(args.semgrep_bin):
        payload = {
            "tool": "semgrep",
            "status": "skipped",
            "reason": f"{args.semgrep_bin} not found on PATH",
            "results": [],
        }
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return 0

    explicit_targets = [Path(value) for value in args.scan_path]
    targets = [path if path.is_absolute() else args.repo_root / path for path in explicit_targets]
    if not targets and args.hypotheses:
        targets = hypothesis_scan_paths(args.hypotheses, args.repo_root, args.max_targets)
    if not targets:
        targets = [args.repo_root]

    command = [
        args.semgrep_bin,
        "--json",
        "--config",
        str(args.config),
        *[str(target) for target in targets],
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=args.run_timeout,
        )
    except subprocess.TimeoutExpired as error:
        payload = {
            "tool": "semgrep",
            "status": "timeout",
            "timeout_seconds": args.run_timeout,
            "targets": [str(target) for target in targets],
            "stderr": (error.stderr or "")[-4000:] if isinstance(error.stderr, str) else "",
            "results": [],
        }
        args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0
    if completed.stdout.strip():
        try:
            raw = json.loads(completed.stdout)
        except json.JSONDecodeError:
            raw = {"results": [], "parse_error": completed.stdout}
    else:
        raw = {"results": []}
    payload = {
        "tool": "semgrep",
        "status": "ok" if completed.returncode in {0, 1} else "error",
        "returncode": completed.returncode,
        "targets": [str(target) for target in targets],
        "stderr": (completed.stderr or "")[-4000:],
        "results": normalize(raw),
        "raw": raw,
    }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if completed.returncode in {0, 1} else completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
