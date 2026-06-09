#!/usr/bin/env python3
"""Append guard coverage markdown to a rendered audit report."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--guard-coverage", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    report = args.report.read_text(encoding="utf-8-sig", errors="replace").rstrip()
    guard = args.guard_coverage.read_text(encoding="utf-8-sig", errors="replace").rstrip()
    guard_body = guard.replace("# Guard Coverage", "## Guard Coverage", 1).replace("\n## ", "\n### ")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{report}\n\n{guard_body}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
