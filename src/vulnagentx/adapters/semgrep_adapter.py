from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class SemgrepAdapter:
    """Thin wrapper around semgrep CLI.

    Prototype behavior: if semgrep is unavailable, return an empty list.
    """

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(
        self,
        repo_path: str,
        config: str = "auto",
        rules_path: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self.available():
            return []

        scan_target = str(Path(repo_path) / target) if target else str(Path(repo_path))
        effective_config = rules_path or config
        command = [
            "semgrep",
            "scan",
            "--config",
            effective_config,
            "--json",
            "--quiet",
            scan_target,
        ]
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        if proc.returncode not in {0, 1}:
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        raw_results = payload.get("results", [])
        if not isinstance(raw_results, list):
            return []
        return [item for item in raw_results if isinstance(item, dict)]

    @staticmethod
    def normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
        path = ""
        start_line = 1
        end_line = 1
        extra = item.get("extra")

        if isinstance(item.get("path"), str):
            path = item["path"]

        if isinstance(item.get("start"), dict):
            maybe = item["start"].get("line")
            if isinstance(maybe, int):
                start_line = maybe
        if isinstance(item.get("end"), dict):
            maybe = item["end"].get("line")
            if isinstance(maybe, int):
                end_line = maybe

        check_id = item.get("check_id")
        message = ""
        if isinstance(extra, dict):
            raw_message = extra.get("message")
            if isinstance(raw_message, str):
                message = raw_message

        return {
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "check_id": check_id if isinstance(check_id, str) else "semgrep.generic",
            "message": message,
        }
