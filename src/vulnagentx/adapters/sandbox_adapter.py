from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass


@dataclass
class SandboxTask:
    name: str
    command: list[str]
    cwd: str
    timeout_seconds: int = 20


@dataclass
class SandboxExecution:
    name: str
    command: list[str]
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    duration_seconds: float


class SandboxAdapter:
    """Process sandbox runner with bounded timeout and no shell expansion."""

    def __init__(self) -> None:
        pass

    def execute(self, task: SandboxTask) -> SandboxExecution:
        started = time.perf_counter()
        env = {
            "PATH": os.getenv("PATH", ""),
            "PYTHONUNBUFFERED": "1",
        }

        try:
            proc = subprocess.run(
                task.command,
                cwd=task.cwd,
                env=env,
                text=True,
                capture_output=True,
                timeout=task.timeout_seconds,
                check=False,
                shell=False,
            )
            elapsed = time.perf_counter() - started
            return SandboxExecution(
                name=task.name,
                command=task.command,
                returncode=proc.returncode,
                timed_out=False,
                stdout=proc.stdout[-4000:],
                stderr=proc.stderr[-4000:],
                duration_seconds=elapsed,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.perf_counter() - started
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return SandboxExecution(
                name=task.name,
                command=task.command,
                returncode=None,
                timed_out=True,
                stdout=stdout[-4000:],
                stderr=stderr[-4000:],
                duration_seconds=elapsed,
            )
