from __future__ import annotations

from pathlib import Path

from vulnagentx.adapters.treesitter_adapter import TreeSitterAdapter
from vulnagentx.core.state import WorkflowState
from vulnagentx.retrieval.repo_graph import RepoGraphBuilder


def _context_key(file_path: str, start_line: int, end_line: int) -> str:
    return f"{file_path}:{start_line}-{end_line}"


def _extract_window(text: str, line_no: int, radius: int = 8) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    numbered = [f"{idx + 1}: {lines[idx]}" for idx in range(start, end)]
    return "\n".join(numbered)


def _preview_file(path: Path, max_lines: int = 10) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    preview = lines[:max_lines]
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(preview))


def run_context_expansion(
    state: WorkflowState,
    max_regions: int = 25,
    line_radius: int = 8,
    use_treesitter: bool = True,
    max_neighbor_files: int = 2,
) -> WorkflowState:
    state.retrieved_context = {}
    state.graph_neighbors = {}

    if not state.suspicious_regions:
        state.add_log(stage="context_expansion", message="No suspicious regions to expand")
        return state

    repo_root = Path(state.repo_path) if state.repo_path else None

    graph_index = None
    if repo_root is not None and use_treesitter:
        file_paths = sorted({item.location.file_path for item in state.suspicious_regions[:max_regions]})
        builder = RepoGraphBuilder(adapter=TreeSitterAdapter())
        graph_index = builder.build(repo_path=str(repo_root), file_paths=file_paths)

    for region in state.suspicious_regions[:max_regions]:
        key = _context_key(
            file_path=region.location.file_path,
            start_line=region.location.start_line,
            end_line=region.location.end_line,
        )

        context_text = region.snippet
        if repo_root is not None:
            full_path = repo_root / region.location.file_path
            if full_path.exists() and full_path.is_file():
                try:
                    raw = full_path.read_text(encoding="utf-8", errors="ignore")
                    context_text = _extract_window(raw, region.location.start_line, radius=line_radius)
                except OSError:
                    context_text = region.snippet

        if graph_index is not None and region.location.file_path in graph_index.files:
            record = graph_index.files[region.location.file_path]
            neighbors = graph_index.neighbors_for_file(region.location.file_path, limit=max_neighbor_files)
            state.graph_neighbors[key] = neighbors
            graph_header = (
                f"\n\n[ast_summary] lang={record.summary.language} "
                f"func={record.summary.function_count} "
                f"import={record.summary.import_count} call={record.summary.call_count}"
            )
            context_text += graph_header
            if neighbors and repo_root is not None:
                for neighbor in neighbors:
                    preview = _preview_file(repo_root / neighbor, max_lines=8)
                    if preview:
                        context_text += f"\n\n[neighbor_file] {neighbor}\n{preview}"

        state.retrieved_context[key] = context_text

    state.metrics["expanded_contexts"] = float(len(state.retrieved_context))
    state.metrics["graph_contexts"] = float(len(state.graph_neighbors))
    state.add_log(
        stage="context_expansion",
        message="Context expansion complete",
        context_items=len(state.retrieved_context),
        radius=line_radius,
        treesitter_enabled=use_treesitter,
        graph_items=len(state.graph_neighbors),
    )
    return state
