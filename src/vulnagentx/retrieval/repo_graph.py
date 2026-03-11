from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vulnagentx.adapters.treesitter_adapter import ASTSummary, CodeGraph, TreeSitterAdapter


@dataclass
class FileGraphRecord:
    file_path: str
    summary: ASTSummary
    graph: CodeGraph


@dataclass
class RepoGraphIndex:
    files: dict[str, FileGraphRecord] = field(default_factory=dict)

    def add(self, record: FileGraphRecord) -> None:
        self.files[record.file_path] = record

    def neighbors_for_file(self, file_path: str, limit: int = 5) -> list[str]:
        if file_path not in self.files:
            return []

        target = self.files[file_path]
        target_terms = set(target.graph.imports + target.graph.calls + target.graph.functions)
        if not target_terms:
            return []

        scored: list[tuple[str, float]] = []
        for other_path, other in self.files.items():
            if other_path == file_path:
                continue
            other_terms = set(other.graph.imports + other.graph.calls + other.graph.functions)
            if not other_terms:
                continue
            inter = len(target_terms.intersection(other_terms))
            if inter == 0:
                continue
            union = len(target_terms.union(other_terms))
            score = inter / union if union else 0.0
            scored.append((other_path, score))

        scored.sort(key=lambda item: item[1], reverse=True)
        return [item[0] for item in scored[:limit]]


class RepoGraphBuilder:
    def __init__(self, adapter: TreeSitterAdapter | None = None) -> None:
        self.adapter = adapter or TreeSitterAdapter()

    def build(self, repo_path: str, file_paths: list[str]) -> RepoGraphIndex:
        repo_root = Path(repo_path)
        index = RepoGraphIndex()

        for relative in file_paths:
            full_path = repo_root / relative
            if not full_path.exists() or not full_path.is_file():
                continue
            try:
                source = full_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            summary, graph = self.adapter.build_code_graph_for_file(file_path=relative, source=source)
            index.add(FileGraphRecord(file_path=relative, summary=summary, graph=graph))

        return index
