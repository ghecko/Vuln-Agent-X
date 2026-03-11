from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ASTSummary:
    language: str
    node_count: int
    function_count: int
    import_count: int
    call_count: int


@dataclass
class CodeGraph:
    functions: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    edges: dict[str, list[str]] = field(default_factory=dict)


_LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
}


class TreeSitterAdapter:
    """Tree-sitter based parser with fallback heuristics when runtime deps are absent."""

    def __init__(self) -> None:
        self._get_parser = self._load_parser_factory()

    @staticmethod
    def _load_parser_factory() -> Any:
        try:
            from tree_sitter_languages import get_parser  # type: ignore[import-not-found]

            return get_parser
        except Exception:
            return None

    def available(self) -> bool:
        return self._get_parser is not None

    def detect_language(self, file_path: str) -> str:
        return _LANGUAGE_MAP.get(Path(file_path).suffix.lower(), "unknown")

    def summarize(self, source: str, language: str) -> ASTSummary:
        graph = self.build_code_graph(source=source, language=language)
        return ASTSummary(
            language=language,
            node_count=max(len(source.splitlines()), len(graph.functions) + len(graph.calls) + len(graph.imports)),
            function_count=len(graph.functions),
            import_count=len(graph.imports),
            call_count=len(graph.calls),
        )

    def build_code_graph(self, source: str, language: str) -> CodeGraph:
        if self._get_parser is None or language == "unknown":
            return self._fallback_graph(source=source)

        try:
            parser = self._get_parser(language)
            tree = parser.parse(bytes(source, "utf-8"))
            return self._graph_from_tree(source=source, root=tree.root_node)
        except Exception:
            return self._fallback_graph(source=source)

    def build_code_graph_for_file(self, file_path: str, source: str) -> tuple[ASTSummary, CodeGraph]:
        language = self.detect_language(file_path)
        graph = self.build_code_graph(source=source, language=language)
        summary = self.summarize(source=source, language=language)
        return summary, graph

    def _graph_from_tree(self, source: str, root: Any) -> CodeGraph:
        functions: list[str] = []
        imports: list[str] = []
        calls: list[str] = []
        edges: dict[str, list[str]] = defaultdict(list)

        stack: list[tuple[Any, str | None]] = [(root, None)]
        while stack:
            node, current_function = stack.pop()
            node_type = getattr(node, "type", "")
            snippet = self._slice(source, node)

            next_function = current_function
            if self._is_function_node(node_type):
                func_name = self._extract_function_name(snippet)
                if func_name:
                    functions.append(func_name)
                    next_function = func_name

            if self._is_import_node(node_type):
                import_text = self._compact(snippet)
                if import_text:
                    imports.append(import_text)

            if self._is_call_node(node_type):
                callee = self._extract_callee_name(snippet)
                if callee:
                    calls.append(callee)
                    if current_function:
                        edges[current_function].append(callee)

            children = getattr(node, "children", [])
            for child in reversed(children):
                stack.append((child, next_function))

        return CodeGraph(
            functions=self._dedupe(functions),
            imports=self._dedupe(imports),
            calls=self._dedupe(calls),
            edges={key: self._dedupe(value) for key, value in edges.items()},
        )

    def _fallback_graph(self, source: str) -> CodeGraph:
        functions = re.findall(r"\bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", source)
        imports = re.findall(r"^(?:from\s+\S+\s+import\s+\S+|import\s+\S+)", source, flags=re.MULTILINE)
        calls = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", source)

        edges: dict[str, list[str]] = {}
        for func in functions:
            edges[func] = []

        return CodeGraph(
            functions=self._dedupe(functions),
            imports=self._dedupe(imports),
            calls=self._dedupe(calls),
            edges=edges,
        )

    @staticmethod
    def _slice(source: str, node: Any) -> str:
        start = getattr(node, "start_byte", 0)
        end = getattr(node, "end_byte", 0)
        if not isinstance(start, int) or not isinstance(end, int):
            return ""
        return source[start:end]

    @staticmethod
    def _is_function_node(node_type: str) -> bool:
        return node_type in {
            "function_definition",
            "function_declaration",
            "method_definition",
            "function_item",
            "method_declaration",
        }

    @staticmethod
    def _is_import_node(node_type: str) -> bool:
        return "import" in node_type or "include" in node_type

    @staticmethod
    def _is_call_node(node_type: str) -> bool:
        return node_type in {"call", "call_expression", "method_invocation"}

    @staticmethod
    def _extract_function_name(snippet: str) -> str:
        patterns = [
            r"\bdef\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            r"\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{",
        ]
        for pattern in patterns:
            match = re.search(pattern, snippet)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _extract_callee_name(snippet: str) -> str:
        match = re.search(r"([a-zA-Z_][a-zA-Z0-9_\.]*)\s*\(", snippet)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _compact(text: str) -> str:
        return " ".join(text.strip().split())[:180]

    @staticmethod
    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out
