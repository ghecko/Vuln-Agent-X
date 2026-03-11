from __future__ import annotations

import json
import shutil
from pathlib import Path

from vulnagentx.adapters.sandbox_adapter import SandboxAdapter, SandboxTask
from vulnagentx.core.state import VerificationResult, WorkflowState


def _build_tasks_for_location(
    repo_path: str,
    file_path: str,
    timeout_seconds: int,
    semgrep_config: str,
    semgrep_rules_path: str | None,
) -> list[SandboxTask]:
    full_path = Path(repo_path) / file_path
    if not full_path.exists() or not full_path.is_file():
        return []

    tasks: list[SandboxTask] = []

    if full_path.suffix.lower() == ".py":
        tasks.append(
            SandboxTask(
                name="py_compile",
                command=["python", "-m", "py_compile", str(full_path)],
                cwd=repo_path,
                timeout_seconds=timeout_seconds,
            )
        )

    if shutil.which("semgrep"):
        config_arg = semgrep_rules_path or semgrep_config
        tasks.append(
            SandboxTask(
                name="semgrep_verify",
                command=["semgrep", "scan", "--config", config_arg, "--json", "--quiet", str(full_path)],
                cwd=repo_path,
                timeout_seconds=timeout_seconds,
            )
        )

    return tasks


def _result_dict(task: SandboxTask, stdout: str, stderr: str, returncode: int | None, timed_out: bool, duration_seconds: float) -> dict[str, object]:
    return {
        "task": task.name,
        "command": task.command,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(duration_seconds, 4),
        "stdout": stdout,
        "stderr": stderr,
    }


def run_optional_verification(
    state: WorkflowState,
    enable_verification: bool = True,
    timeout_seconds: int = 20,
    run_tests: bool = False,
    semgrep_config: str = "auto",
    semgrep_rules_path: str | None = None,
) -> WorkflowState:
    needs_verification = any(step.action == "verification" for step in state.escalation_plan)

    if not enable_verification:
        state.verification_results.append(
            VerificationResult(
                executed=False,
                passed=None,
                summary="Verification disabled by configuration",
                signal_score=0.0,
            )
        )
        state.add_log(stage="verification", message="Verification disabled")
        return state

    if not needs_verification:
        state.verification_results.append(
            VerificationResult(
                executed=False,
                passed=None,
                summary="Verification skipped by escalation policy",
                signal_score=0.0,
            )
        )
        state.add_log(stage="verification", message="Verification skipped")
        return state

    if not state.repo_path:
        state.verification_results.append(
            VerificationResult(
                executed=False,
                passed=None,
                summary="Verification requires repository path",
                signal_score=0.0,
            )
        )
        state.add_log(stage="verification", message="Verification skipped (no repo path)")
        return state

    sandbox = SandboxAdapter()
    total_executions = 0

    for step in state.escalation_plan:
        if step.action != "verification":
            continue

        tasks = _build_tasks_for_location(
            repo_path=state.repo_path,
            file_path=step.location.file_path,
            timeout_seconds=timeout_seconds,
            semgrep_config=semgrep_config,
            semgrep_rules_path=semgrep_rules_path,
        )

        if not tasks:
            state.verification_results.append(
                VerificationResult(
                    location=step.location,
                    executed=False,
                    passed=None,
                    summary="No runnable verification task for this location",
                    signal_score=0.0,
                    task_results=[],
                )
            )
            continue

        signal_score = 0.0
        task_results: list[dict[str, object]] = []

        for task in tasks:
            execution = sandbox.execute(task)
            total_executions += 1

            task_results.append(
                _result_dict(
                    task=task,
                    stdout=execution.stdout,
                    stderr=execution.stderr,
                    returncode=execution.returncode,
                    timed_out=execution.timed_out,
                    duration_seconds=execution.duration_seconds,
                )
            )

            if execution.timed_out:
                continue

            if task.name == "py_compile" and execution.returncode not in {0, None}:
                signal_score += 0.25

            if task.name == "semgrep_verify" and execution.returncode in {0, 1}:
                try:
                    payload = json.loads(execution.stdout)
                    raw_results = payload.get("results", [])
                    count = len(raw_results) if isinstance(raw_results, list) else 0
                    if count > 0:
                        signal_score += min(0.60, 0.20 + 0.10 * count)
                except json.JSONDecodeError:
                    pass

        signal_score = min(1.0, signal_score)
        passed = signal_score < 0.2
        summary = "Verification produced confirming signals" if signal_score >= 0.2 else "No strong verification signal"

        state.verification_results.append(
            VerificationResult(
                location=step.location,
                executed=True,
                passed=passed,
                summary=summary,
                signal_score=signal_score,
                task_results=task_results,
            )
        )

    if run_tests and shutil.which("pytest"):
        test_task = SandboxTask(
            name="repo_pytest",
            command=["pytest", "-q", "--maxfail=1"],
            cwd=state.repo_path,
            timeout_seconds=max(15, timeout_seconds),
        )
        execution = sandbox.execute(test_task)
        total_executions += 1
        signal_score = 0.15 if execution.returncode not in {0, None} and not execution.timed_out else 0.0
        state.verification_results.append(
            VerificationResult(
                location=None,
                executed=True,
                passed=execution.returncode == 0 and not execution.timed_out,
                summary="Repository pytest execution",
                signal_score=signal_score,
                task_results=[
                    _result_dict(
                        task=test_task,
                        stdout=execution.stdout,
                        stderr=execution.stderr,
                        returncode=execution.returncode,
                        timed_out=execution.timed_out,
                        duration_seconds=execution.duration_seconds,
                    )
                ],
            )
        )

    state.metrics["verification_tasks"] = float(total_executions)
    state.add_log(
        stage="verification",
        message="Verification completed",
        verification_results=len(state.verification_results),
        executed_tasks=total_executions,
    )
    return state
