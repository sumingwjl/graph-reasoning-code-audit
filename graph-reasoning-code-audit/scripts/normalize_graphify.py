#!/usr/bin/env python3
"""Normalize graphify output into graph_context.json."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ENTRYPOINT_RE = re.compile(
    r"(route|router|controller|handler|endpoint|api|rpc|graphql|webhook|consumer|job|task)",
    re.I,
)
SENSITIVE_RE = re.compile(
    r"(admin|authn|authz|authorize|authorization|authentication|permission|owner|tenant|"
    r"approve|pay|payment|refund|order|inventory|stock|quota|points|credit|balance|"
    r"status|state|delete|patch|create|write)",
    re.I,
)
AUDIT_PATH_RE = re.compile(
    r"(^|/)(api|auth|controllers?|endpoints?|middlewares?|permissions?|policies|routes?|"
    r"services?|schema|workflows?|operations?|items|users?|roles?|access|accountability)(/|$|[-_.])",
    re.I,
)
NOISE_PATH_RE = re.compile(
    r"(^|/)(node_modules|dist|build|coverage|lang|locales?|translations?|i18n)(/|$)|"
    r"(^|/)(\.audit|graphify-out)(/|$)|"
    r"(package-lock|pnpm-lock|yarn.lock|\.svg$|\.png$|\.jpg$|\.jpeg$)|"
    r"(security_audit_report|audit_report|source_validation|hypoth(es|esis)|evidence|"
    r"semgrep-results|joern-results|osv-results|sca_report)\.(md|json|ya?ml)$",
    re.I,
)
TEST_PATH_RE = re.compile(r"(^|/)(test|tests|e2e|spec|specs)(/|$)", re.I)
AUDIT_ARTIFACT_RE = re.compile(
    r"(^|/)(\.audit|graphify-out)(/|$)|"
    r"(^|/|\\)(security_audit_report|audit_report|source_validation|final_report|"
    r"hypoth(es|esis)|evidence|semgrep-results|joern-results|osv-results|sca_report)"
    r"\.(md|json|ya?ml)$",
    re.I,
)
CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".ts",
    ".tsx",
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_report(path: Path | None) -> str:
    if not path or not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:80])


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def detect_type(item: dict[str, Any]) -> str:
    raw = str(item.get("type") or item.get("kind") or item.get("file_type") or item.get("label") or "").lower()
    path = str(item.get("path") or item.get("file") or item.get("source_file") or item.get("file_path") or item.get("name") or "")
    suffix = Path(path).suffix.lower()
    label = str(item.get("label") or item.get("name") or "")
    if "doc" in raw or suffix in {".md", ".rst", ".txt", ".pdf"}:
        return "doc"
    if "config" in raw or suffix in {".json", ".yaml", ".yml", ".toml", ".xml", ".ini"}:
        return "config"
    if suffix in CODE_EXTENSIONS and label == Path(path).name:
        return "file"
    if suffix in CODE_EXTENSIONS or "code" in raw:
        return "symbol"
    if "file" in raw:
        return "file"
    if "function" in raw or "class" in raw or "method" in raw or "symbol" in raw:
        return "symbol"
    return "unknown"


def node_id(item: dict[str, Any], index: int) -> str:
    for key in ("id", "node_id", "key", "name", "path", "file"):
        value = item.get(key)
        if value:
            return str(value)
    return f"node-{index:05d}"


def normalize_nodes(raw_graph: Any) -> list[dict[str, Any]]:
    raw_nodes = []
    if isinstance(raw_graph, dict):
        for key in ("nodes", "vertices", "entities", "items"):
            if key in raw_graph:
                raw_nodes = as_list(raw_graph[key])
                break
    nodes: list[dict[str, Any]] = []
    for index, item in enumerate(raw_nodes, 1):
        if not isinstance(item, dict):
            continue
        nid = node_id(item, index)
        label = str(item.get("label") or item.get("name") or item.get("title") or nid)
        path = item.get("path") or item.get("file") or item.get("source_file") or item.get("file_path") or item.get("filepath")
        score = item.get("score") or item.get("rank") or item.get("centrality") or item.get("confidence_score") or 0
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            score_value = 0.0
        nodes.append(
            {
                "id": nid,
                "label": label,
                "type": detect_type(item),
                "path": str(path) if path else None,
                "score": score_value,
                "metadata": {
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "id",
                        "node_id",
                        "key",
                        "label",
                        "name",
                        "title",
                        "path",
                        "file",
                        "source_file",
                        "file_path",
                        "filepath",
                    }
                },
            }
        )
    return nodes


def normalize_edges(raw_graph: Any) -> list[dict[str, Any]]:
    raw_edges = []
    if isinstance(raw_graph, dict):
        for key in ("edges", "links", "relationships"):
            if key in raw_graph:
                raw_edges = as_list(raw_graph[key])
                break
    edges: list[dict[str, Any]] = []
    for item in raw_edges:
        if not isinstance(item, dict):
            continue
        source = item.get("source") or item.get("from") or item.get("src")
        target = item.get("target") or item.get("to") or item.get("dst")
        if source is None or target is None:
            continue
        edge_type = str(item.get("type") or item.get("label") or item.get("relation") or "related")
        edges.append(
            {
                "source": str(source),
                "target": str(target),
                "type": edge_type,
                "metadata": {
                    key: value
                    for key, value in item.items()
                    if key not in {"source", "from", "src", "target", "to", "dst", "type", "label", "relation"}
                },
            }
        )
    return edges


def edge_text(edge: dict[str, Any]) -> str:
    metadata = edge.get("metadata") or {}
    values = [edge.get("type")]
    if isinstance(metadata, dict):
        values.extend(metadata.get(key) for key in ("confidence", "source", "provenance", "evidence", "relation_kind"))
    return " ".join(str(value) for value in values if value is not None)


def normalize_hyperedges(raw_graph: Any) -> list[dict[str, Any]]:
    raw_hyperedges = []
    if isinstance(raw_graph, dict):
        raw_hyperedges = as_list(raw_graph.get("hyperedges"))
        if not raw_hyperedges and isinstance(raw_graph.get("graph"), dict):
            raw_hyperedges = as_list(raw_graph["graph"].get("hyperedges"))
    hyperedges: list[dict[str, Any]] = []
    for index, item in enumerate(raw_hyperedges, 1):
        if not isinstance(item, dict):
            continue
        nodes = item.get("nodes") or item.get("target_nodes") or item.get("members") or []
        if not isinstance(nodes, list):
            nodes = [nodes]
        relation = item.get("relation") or item.get("relation_type") or item.get("type") or "related"
        hyperedges.append(
            {
                "id": str(item.get("id") or f"hyperedge-{index:05d}"),
                "label": str(item.get("label") or item.get("name") or item.get("id") or f"hyperedge-{index:05d}"),
                "relation": str(relation),
                "nodes": [str(node) for node in nodes if node is not None],
                "source_file": item.get("source_file"),
                "confidence": item.get("confidence"),
                "confidence_score": item.get("confidence_score"),
                "description": item.get("description"),
                "metadata": {
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "id",
                        "label",
                        "name",
                        "relation",
                        "relation_type",
                        "type",
                        "nodes",
                        "target_nodes",
                        "members",
                        "source_file",
                        "confidence",
                        "confidence_score",
                        "description",
                    }
                },
            }
        )
    return hyperedges


def semantic_artifact_summary(graph_json: Path) -> dict[str, Any]:
    graphify_dir = graph_json.parent
    semantic_dirs = [
        path
        for path in (graphify_dir / "semantic", graphify_dir / "semantics", graphify_dir / "cache" / "semantic")
        if path.exists()
    ]
    files: list[Path] = []
    for directory in semantic_dirs:
        if directory.is_dir():
            files.extend(path for path in directory.rglob("*") if path.is_file())
    return {
        "semantic_dirs": [str(path) for path in semantic_dirs],
        "semantic_file_count": len(files),
        "semantic_total_bytes": sum(path.stat().st_size for path in files),
    }


def graphify_quality_summary(
    semantic_artifacts: dict[str, Any],
    edges: list[dict[str, Any]],
    hyperedges: list[dict[str, Any]],
) -> dict[str, Any]:
    semantic_file_count = int(semantic_artifacts.get("semantic_file_count") or 0)
    inferred_edges = [
        edge
        for edge in edges
        if re.search(r"\b(INFERRED|AMBIGUOUS|semantically_similar_to|semantic)\b", edge_text(edge), re.I)
    ]
    warnings: list[str] = []
    if semantic_file_count == 0:
        warnings.append(
            "No graphify semantic cache/artifact files were detected. This graph may be AST-only or non-deep output."
        )
    if not hyperedges:
        warnings.append(
            "No graphify hyperedges were detected. Deep semantic extraction may be absent or sparse."
        )
    if semantic_file_count == 0 and not inferred_edges and not hyperedges:
        warnings.append(
            "Graphify output looks AST-only. Do not use it as the main security semantic input; rerun graphify with --mode deep or continue only with an explicit degraded-context note."
        )
    return {
        "has_semantic_artifacts": semantic_file_count > 0,
        "semantic_file_count": semantic_file_count,
        "hyperedge_count": len(hyperedges),
        "inferred_or_ambiguous_edge_count": len(inferred_edges),
        "ast_only_likely": semantic_file_count == 0 and not inferred_edges and not hyperedges,
        "warnings": warnings,
    }


def contamination_warnings(nodes: list[dict[str, Any]], hyperedges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any, note: str) -> None:
        text = str(value or "")
        if not text or not AUDIT_ARTIFACT_RE.search(text.replace("\\", "/")):
            return
        key = (kind, text)
        if key in seen:
            return
        seen.add(key)
        warnings.append({"kind": kind, "path": text, "note": note})

    for node in nodes:
        add("node", node.get("path") or node.get("metadata", {}).get("source_file"), "Graph includes a generated audit artifact as a node.")
    for edge in hyperedges:
        add("hyperedge", edge.get("source_file"), "Graph includes a generated audit artifact as a hyperedge source.")
    return warnings[:50]


def add_degree_scores(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    degree: dict[str, int] = {}
    for edge in edges:
        degree[str(edge["source"])] = degree.get(str(edge["source"]), 0) + 1
        degree[str(edge["target"])] = degree.get(str(edge["target"]), 0) + 1
    max_degree = max(degree.values(), default=0)
    for node in nodes:
        degree_score = degree.get(str(node["id"]), 0) / max_degree if max_degree else 0
        existing_score = float(node.get("score") or 0)
        node["metadata"]["graph_degree_score"] = round(degree_score, 4)
        node["metadata"]["raw_score"] = existing_score
        node["score"] = round(max(existing_score, degree_score), 4)


def add_audit_scores(nodes: list[dict[str, Any]]) -> None:
    for node in nodes:
        label = str(node.get("label") or "")
        path = str(node.get("path") or "")
        haystack = f"{label} {path}"
        score = float(node.get("score") or 0) * 0.4
        if ENTRYPOINT_RE.search(haystack):
            score += 2.0
        if SENSITIVE_RE.search(haystack):
            score += 2.0
        if AUDIT_PATH_RE.search(path):
            score += 1.5
        if TEST_PATH_RE.search(path):
            score -= 1.2
        if NOISE_PATH_RE.search(path):
            score -= 1.2
        if path.endswith((".yaml", ".yml")) and "/paths/" in path.replace("\\", "/"):
            score += 1.0
        if path.endswith(("package.json", "tsconfig.json")):
            score -= 0.8
        node["metadata"]["base_score"] = node.get("score", 0)
        node["score"] = round(max(score, 0.0), 4)


def pick_candidates(nodes: list[dict[str, Any]], pattern: re.Pattern[str], limit: int) -> list[dict[str, Any]]:
    scored = []
    for node in nodes:
        haystack = " ".join(str(node.get(key) or "") for key in ("label", "path", "type"))
        if pattern.search(haystack):
            scored.append(node)
    scored.sort(key=lambda item: float(item.get("score") or 0), reverse=True)
    return [
        {
            "id": item["id"],
            "label": item["label"],
            "path": item.get("path"),
            "score": item.get("score", 0),
        }
        for item in scored[:limit]
    ]


def core_paths(nodes: list[dict[str, Any]], limit: int) -> list[str]:
    path_scores: dict[str, float] = {}
    for node in nodes:
        if not node.get("path"):
            continue
        path = str(node["path"])
        score = float(node.get("score") or 0)
        if NOISE_PATH_RE.search(path) and score < 2.5:
            continue
        path_scores[path] = max(path_scores.get(path, 0.0), score)
    ranked = sorted(path_scores.items(), key=lambda item: item[1], reverse=True)
    return [path for path, _score in ranked[:limit]]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-json", required=True, type=Path)
    parser.add_argument("--graph-report", type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    raw_graph = load_json(args.graph_json)
    nodes = normalize_nodes(raw_graph)
    edges = normalize_edges(raw_graph)
    hyperedges = normalize_hyperedges(raw_graph)
    add_degree_scores(nodes, edges)
    add_audit_scores(nodes)
    semantic_artifacts = semantic_artifact_summary(args.graph_json)
    graphify_quality = graphify_quality_summary(semantic_artifacts, edges, hyperedges)
    context = {
        "repo": {
            "name": args.repo_root.resolve().name,
            "root": str(args.repo_root),
        },
        "sources": {
            "graph_json": str(args.graph_json),
            "graph_report": str(args.graph_report) if args.graph_report else "",
        },
        "graphify_semantic_artifacts": semantic_artifacts,
        "graphify_quality": graphify_quality,
        "graphify_input_warnings": contamination_warnings(nodes, hyperedges),
        "nodes": nodes,
        "edges": edges,
        "hyperedges": hyperedges,
        "entrypoint_candidates": pick_candidates(nodes, ENTRYPOINT_RE, args.limit),
        "sensitive_candidates": pick_candidates(nodes, SENSITIVE_RE, args.limit),
        "core_paths": core_paths(nodes, args.limit),
        "report_summary": read_report(args.graph_report),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
