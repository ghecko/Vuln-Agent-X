from __future__ import annotations

from dataclasses import dataclass

from vulnagentx.core.workflow import VulnAgentWorkflow
from vulnagentx.datasets.base import DatasetSample
from vulnagentx.eval.detection_metrics import DetectionMetrics, compute_detection_metrics
from vulnagentx.utils.config import WorkflowConfig


@dataclass
class AblationVariant:
    name: str
    updates: dict[str, object]


def run_ablation(samples: list[DatasetSample], base_config: WorkflowConfig, variants: list[AblationVariant]) -> dict[str, DetectionMetrics]:
    results: dict[str, DetectionMetrics] = {}

    for variant in variants:
        config = base_config.model_copy(update=variant.updates)
        workflow = VulnAgentWorkflow(config=config)

        labels: list[int] = []
        preds: list[int] = []

        for sample in samples:
            state = workflow.run(repo_path=sample.repo_path, diff_text=sample.diff_text)
            labels.append(1 if sample.label else 0)
            preds.append(1 if state.final_findings else 0)

        results[variant.name] = compute_detection_metrics(labels=labels, predictions=preds)

    return results
