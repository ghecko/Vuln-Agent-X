from __future__ import annotations

import re
from pathlib import Path

from vulnagentx.adapters.semgrep_adapter import SemgrepAdapter
from vulnagentx.core.state import CodeLocation, SuspiciousRegion, WorkflowState

RISK_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("dangerous_eval", re.compile(r"\beval\s*\("), 0.85),
    ("command_exec", re.compile(r"\b(system|popen|Runtime\.getRuntime\(\)\.exec)\s*\("), 0.88),
    ("shell_true", re.compile(r"shell\s*=\s*true", re.IGNORECASE), 0.82),
    ("sql_concat", re.compile(r"(select|insert|update|delete).*(\+|%s|\{)", re.IGNORECASE), 0.76),
    ("unsafe_c_copy", re.compile(r"\b(strcpy|strcat|sprintf|gets)\s*\("), 0.90),
    ("deserialization", re.compile(r"\b(pickle\.loads|yaml\.load\s*\()"), 0.78),
    ("todo_security", re.compile(r"TODO|FIXME|HACK", re.IGNORECASE), 0.45),
    ("assert_auth", re.compile(r"assert\s+.*auth", re.IGNORECASE), 0.55),
]

CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".php",
    ".rb",
}


def _iter_repo_files(repo_path: str, max_files: int = 400) -> list[Path]:
    base = Path(repo_path)
    if not base.exists():
        return []

    files: list[Path] = []
    for path in base.rglob("*"):
        if len(files) >= max_files:
            break
        if not path.is_file():
            continue
        if (
            ".git" in path.parts
            or "node_modules" in path.parts
            or ".venv" in path.parts
            or "venv" in path.parts
            or "__pycache__" in path.parts
        ):
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        files.append(path)
    return files


def _scan_text_for_patterns(text: str, file_path: str, base_line: int | None = None) -> list[SuspiciousRegion]:
    regions: list[SuspiciousRegion] = []
    for idx, raw_line in enumerate(text.splitlines(), start=1):
        line_no = base_line if base_line is not None else idx
        line = raw_line.strip()
        if not line:
            continue
        for reason, pattern, score in RISK_PATTERNS:
            if pattern.search(line):
                regions.append(
                    SuspiciousRegion(
                        location=CodeLocation(file_path=file_path, start_line=line_no, end_line=line_no),
                        reason=reason,
                        score=score,
                        snippet=line[:300],
                    )
                )
    return regions


def _screen_repo(repo_path: str) -> list[SuspiciousRegion]:
    regions: list[SuspiciousRegion] = []
    base = Path(repo_path)
    for file_path in _iter_repo_files(repo_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative = str(file_path.relative_to(base))
        regions.extend(_scan_text_for_patterns(text=text, file_path=relative))
    return regions


def _screen_diff(diff_text: str) -> list[SuspiciousRegion]:
    regions: list[SuspiciousRegion] = []
    current_file = "diff_fragment"
    current_line = 1

    hunk_re = re.compile(r"@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")

    for raw_line in diff_text.splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("+++ "):
            candidate = line[4:].strip()
            if candidate.startswith("b/"):
                candidate = candidate[2:]
            current_file = candidate or current_file
            continue

        if line.startswith("@@"):
            match = hunk_re.search(line)
            if match:
                current_line = int(match.group(1))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            regions.extend(_scan_text_for_patterns(line[1:], current_file, base_line=current_line))
            current_line += 1
            continue

        if line.startswith("-"):
            continue

        current_line += 1

    return regions


def _semgrep_score(check_id: str, message: str) -> float:
    digest = f"{check_id} {message}".lower()
    if "command" in digest and "inject" in digest:
        return 0.92
    if "sql" in digest and "inject" in digest:
        return 0.90
    if "deserial" in digest:
        return 0.84
    if "travers" in digest or "path" in digest:
        return 0.82
    if "overflow" in digest or "out-of-bounds" in digest:
        return 0.90
    return 0.72


def _to_relative(repo_path: str, file_path: str) -> str:
    base = Path(repo_path).resolve()
    candidate = Path(file_path)
    if not candidate.is_absolute():
        return file_path
    try:
        return str(candidate.resolve().relative_to(base))
    except ValueError:
        return file_path


def _screen_semgrep(
    repo_path: str,
    config: str,
    rules_path: str | None,
) -> list[SuspiciousRegion]:
    adapter = SemgrepAdapter()
    if not adapter.available():
        return []

    results = adapter.scan(repo_path=repo_path, config=config, rules_path=rules_path)
    regions: list[SuspiciousRegion] = []
    for result in results:
        normalized = adapter.normalize_finding(result)
        file_path = _to_relative(repo_path=repo_path, file_path=str(normalized["path"]))
        start_line = int(normalized["start_line"])
        end_line = int(normalized["end_line"])
        check_id = str(normalized["check_id"])
        message = str(normalized["message"])

        regions.append(
            SuspiciousRegion(
                location=CodeLocation(file_path=file_path, start_line=start_line, end_line=end_line),
                reason=f"semgrep:{check_id}",
                score=_semgrep_score(check_id=check_id, message=message),
                snippet=message[:300],
            )
        )
    return regions


def _dedupe_regions(regions: list[SuspiciousRegion]) -> list[SuspiciousRegion]:
    best_by_key: dict[tuple[str, int, int, str], SuspiciousRegion] = {}
    for region in regions:
        key = (
            region.location.file_path,
            region.location.start_line,
            region.location.end_line,
            region.reason,
        )
        existing = best_by_key.get(key)
        if existing is None or region.score > existing.score:
            best_by_key[key] = region
    return list(best_by_key.values())


def run_screening(
    state: WorkflowState,
    top_k: int = 30,
    use_semgrep: bool = True,
    semgrep_config: str = "auto",
    semgrep_rules_path: str | None = None,
) -> WorkflowState:
    heuristic_candidates: list[SuspiciousRegion]
    semgrep_candidates: list[SuspiciousRegion] = []

    if state.diff_text:
        heuristic_candidates = _screen_diff(state.diff_text)
    elif state.repo_path:
        heuristic_candidates = _screen_repo(state.repo_path)
        if use_semgrep:
            semgrep_candidates = _screen_semgrep(
                repo_path=state.repo_path,
                config=semgrep_config,
                rules_path=semgrep_rules_path,
            )
    else:
        heuristic_candidates = []

    combined = _dedupe_regions(heuristic_candidates + semgrep_candidates)
    combined.sort(key=lambda region: region.score, reverse=True)
    state.suspicious_regions = combined[:top_k]

    state.metrics["screening_candidates"] = float(len(state.suspicious_regions))
    state.metrics["semgrep_candidates"] = float(len(semgrep_candidates))
    state.add_log(
        stage="screening",
        message="Completed risk screening",
        top_k=top_k,
        candidate_count=len(state.suspicious_regions),
        semgrep_enabled=use_semgrep,
        semgrep_candidates=len(semgrep_candidates),
    )
    return state
