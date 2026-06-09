#!/usr/bin/env python3
"""Collect dependency, framework, and configuration context for SCA review.

This script inventories files and lightweight metadata only. It does not query
vulnerability databases and does not decide whether a CVE is exploitable.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


MANIFEST_PATTERNS = {
    "npm_manifest": ["package.json"],
    "npm_lock": ["package-lock.json", "npm-shrinkwrap.json"],
    "pnpm_lock": ["pnpm-lock.yaml"],
    "yarn_lock": ["yarn.lock"],
    "bun_lock": ["bun.lock", "bun.lockb"],
    "python_requirements": ["requirements.txt", "requirements-*.txt"],
    "python_pyproject": ["pyproject.toml"],
    "python_poetry_lock": ["poetry.lock"],
    "python_pipfile": ["Pipfile", "Pipfile.lock"],
    "go_mod": ["go.mod"],
    "go_sum": ["go.sum"],
    "maven_pom": ["pom.xml"],
    "gradle_build": ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"],
    "gradle_lock": ["gradle.lockfile"],
    "cargo_manifest": ["Cargo.toml"],
    "cargo_lock": ["Cargo.lock"],
    "ruby_gemfile": ["Gemfile", "Gemfile.lock"],
    "php_composer": ["composer.json", "composer.lock"],
    "dotnet_project": ["*.csproj", "packages.lock.json", "Directory.Packages.props"],
}

CONFIG_PATTERNS = {
    "container": ["Dockerfile", "Dockerfile.*", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
    "kubernetes": ["*.yaml", "*.yml"],
    "terraform": ["*.tf", "*.tfvars"],
    "env": [".env", ".env.*"],
    "web_config": [
        "next.config.*",
        "vite.config.*",
        "nuxt.config.*",
        "angular.json",
        "astro.config.*",
        "svelte.config.*",
    ],
    "server_config": [
        "nginx.conf",
        "nginx/*.conf",
        "apache2.conf",
        "httpd.conf",
        "application.yml",
        "application.yaml",
        "application.properties",
    ],
}

FRAMEWORK_HINTS = {
    "next": "Next.js",
    "react": "React",
    "vue": "Vue",
    "nuxt": "Nuxt",
    "express": "Express",
    "fastify": "Fastify",
    "koa": "Koa",
    "@nestjs/core": "NestJS",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "spring-boot": "Spring Boot",
    "org.springframework.boot": "Spring Boot",
    "rails": "Ruby on Rails",
    "laravel/framework": "Laravel",
    "actix-web": "Actix Web",
    "axum": "Axum",
    "gin-gonic/gin": "Gin",
}

SENSITIVE_ENV_KEY_RE = re.compile(r"(secret|token|password|passwd|apikey|api_key|private|credential)", re.I)


def normalize_path(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def read_toml(path: Path) -> dict[str, Any] | None:
    if tomllib is None:
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def dependency_names_from_package_json(path: Path) -> dict[str, str]:
    data = read_json(path)
    if not data:
        return {}
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section)
        if isinstance(values, dict):
            for name, version in values.items():
                deps[str(name)] = str(version)
    return deps


def dependency_names_from_pyproject(path: Path) -> dict[str, str]:
    data = read_toml(path)
    if not data:
        return {}
    deps: dict[str, str] = {}
    project_deps = ((data.get("project") or {}).get("dependencies") or [])
    if isinstance(project_deps, list):
        for value in project_deps:
            if isinstance(value, str):
                name = re.split(r"[<>=~!;\[]", value, maxsplit=1)[0].strip()
                if name:
                    deps[name] = value
    poetry_deps = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    if isinstance(poetry_deps, dict):
        for name, version in poetry_deps.items():
            deps[str(name)] = str(version)
    return deps


def dependency_names_from_go_mod(path: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    in_block = False
    for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        if in_block or raw.strip().startswith("require "):
            parts = line.split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
    return deps


def classify_manifest(path: Path) -> str | None:
    name = path.name
    for kind, patterns in MANIFEST_PATTERNS.items():
        for pattern in patterns:
            if path.match(pattern):
                return kind
            if pattern.startswith("*.") and name.endswith(pattern[1:]):
                return kind
    return None


def classify_config(path: Path) -> str | None:
    rel = path.as_posix()
    name = path.name
    for kind, patterns in CONFIG_PATTERNS.items():
        for pattern in patterns:
            if path.match(pattern) or name == pattern or name.endswith(pattern.removeprefix("*")):
                return kind
            if "/" in pattern and re.search(pattern.replace("*", ".*"), rel):
                return kind
    return None


def env_key_summary(path: Path) -> dict[str, Any]:
    keys: list[str] = []
    sensitive_keys: list[str] = []
    for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines()[:200]:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if not key:
            continue
        keys.append(key)
        if SENSITIVE_ENV_KEY_RE.search(key):
            sensitive_keys.append(key)
    return {"keys": keys[:80], "sensitive_key_names": sensitive_keys[:40], "values_redacted": True}


def find_files(root: Path, max_files: int) -> tuple[list[Path], list[Path]]:
    ignored = {".git", "node_modules", "vendor", "dist", "build", ".next", ".venv", "venv", "__pycache__"}
    manifests: list[Path] = []
    configs: list[Path] = []
    for path in root.rglob("*"):
        if len(manifests) + len(configs) >= max_files:
            break
        if any(part in ignored for part in path.parts):
            continue
        if not path.is_file():
            continue
        if classify_manifest(path):
            manifests.append(path)
            continue
        if classify_config(path):
            configs.append(path)
    return manifests, configs


def extract_manifest_metadata(path: Path, root: Path) -> dict[str, Any]:
    kind = classify_manifest(path) or "unknown"
    metadata: dict[str, Any] = {"path": normalize_path(path, root), "kind": kind}
    deps: dict[str, str] = {}
    if path.name == "package.json":
        deps = dependency_names_from_package_json(path)
    elif path.name == "pyproject.toml":
        deps = dependency_names_from_pyproject(path)
    elif path.name == "go.mod":
        deps = dependency_names_from_go_mod(path)
    metadata["dependency_count"] = len(deps)
    metadata["sample_dependencies"] = dict(list(sorted(deps.items()))[:40])
    return metadata


def infer_frameworks(manifests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    frameworks: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        for dep, version in (manifest.get("sample_dependencies") or {}).items():
            for hint, framework in FRAMEWORK_HINTS.items():
                if dep == hint or hint in dep:
                    entry = frameworks.setdefault(framework, {"name": framework, "evidence": []})
                    entry["evidence"].append({"path": manifest["path"], "dependency": dep, "version": version})
    return list(frameworks.values())


def suggested_commands(manifests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kinds = {item["kind"] for item in manifests}
    commands: list[dict[str, Any]] = [
        {
            "tool": "osv-scanner",
            "command": "osv-scanner scan --recursive --format json --output .audit/osv-results.json <repo-root>",
        }
    ]
    if {"npm_manifest", "npm_lock", "pnpm_lock", "yarn_lock", "bun_lock"} & kinds:
        commands.extend(
            [
                {"tool": "npm", "command": "npm audit --json"},
                {"tool": "pnpm", "command": "pnpm audit --json"},
            ]
        )
    if {"python_requirements", "python_pyproject", "python_poetry_lock", "python_pipfile"} & kinds:
        commands.append({"tool": "pip-audit", "command": "pip-audit -f json"})
    if {"go_mod", "go_sum"} & kinds:
        commands.append({"tool": "govulncheck", "command": "govulncheck ./..."})
    if {"cargo_manifest", "cargo_lock"} & kinds:
        commands.append({"tool": "cargo-audit", "command": "cargo audit --json"})
    if {"maven_pom", "gradle_build", "gradle_lock"} & kinds:
        commands.append({"tool": "trivy", "command": "trivy fs --format json <repo-root>"})
    return commands


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=500)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    manifest_paths, config_paths = find_files(root, args.max_files)
    manifests = [extract_manifest_metadata(path, root) for path in sorted(manifest_paths)]
    configs = []
    for path in sorted(config_paths):
        item: dict[str, Any] = {"path": normalize_path(path, root), "kind": classify_config(path) or "unknown"}
        if item["kind"] == "env":
            item["env_summary"] = env_key_summary(path)
        configs.append(item)

    payload = {
        "schema": "graph-reasoning-code-audit/dependency-context-v1",
        "repo_root": str(root),
        "manifests": manifests,
        "frameworks": infer_frameworks(manifests),
        "config_files": configs,
        "suggested_scanners": suggested_commands(manifests),
        "subagent_task": {
            "goal": "Identify dependency, framework-version, CVE/GHSA/OSV, and dangerous configuration risks.",
            "inputs": ["dependency_context.json", "repository manifests and lockfiles", "scanner JSON outputs if available"],
            "outputs": ["dependency_findings.json"],
            "rules": [
                "Do not treat version match alone as final exploitability.",
                "Capture affected ranges, fixed versions, trigger conditions, and usage/config evidence.",
                "Default to needs_review when exploit preconditions are unclear.",
            ],
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
