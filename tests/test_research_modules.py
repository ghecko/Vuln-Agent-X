from pathlib import Path

from vulnagentx.adapters.treesitter_adapter import TreeSitterAdapter
from vulnagentx.core.state import CodeLocation, EscalationStep, TargetType, WorkflowState
from vulnagentx.core.verification import run_optional_verification
from vulnagentx.eval.detection_metrics import compute_detection_metrics
from vulnagentx.eval.localization_metrics import compute_localization_metrics


def test_treesitter_adapter_builds_graph() -> None:
    source = """
import os

def a(x):
    return b(x)

def b(y):
    return y
""".strip()
    adapter = TreeSitterAdapter()
    summary, graph = adapter.build_code_graph_for_file("demo.py", source)

    assert summary.function_count >= 1
    assert "a" in graph.functions
    assert graph.calls


def test_verification_pipeline_executes_tasks(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n    pass\n", encoding="utf-8")

    state = WorkflowState(
        run_id="verify-test",
        repo_path=str(tmp_path),
        target_type=TargetType.repository,
        escalation_plan=[
            EscalationStep(
                location=CodeLocation(file_path="bad.py", start_line=1, end_line=1),
                action="verification",
                rationale="test",
            )
        ],
    )

    run_optional_verification(
        state,
        enable_verification=True,
        timeout_seconds=10,
        run_tests=False,
        semgrep_config="auto",
        semgrep_rules_path=None,
    )

    assert state.verification_results
    assert state.verification_results[0].executed


def test_eval_metrics_compute_expected_shapes() -> None:
    detection = compute_detection_metrics(labels=[1, 0, 1, 0], predictions=[1, 0, 0, 0])
    assert 0.0 <= detection.f1 <= 1.0

    localization = compute_localization_metrics(
        gold_locations=[["a.py:1-1"], ["b.py:3-3"]],
        ranked_predictions=[["a.py:1-1", "x.py:2-2"], ["x.py:9-9", "b.py:3-3"]],
    )
    assert 0.0 <= localization.top1 <= 1.0
    assert 0.0 <= localization.top3 <= 1.0
