#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnagentx.core.workflow import VulnAgentWorkflow
from vulnagentx.datasets import load_bigvul, load_devign, load_jit, load_primevul
from vulnagentx.utils.config import WorkflowConfig


def _load_samples(dataset_name: str, dataset_file: str):
    loaders = {
        "devign": load_devign,
        "bigvul": load_bigvul,
        "primevul": load_primevul,
        "jit": load_jit,
    }
    if dataset_name not in loaders:
        raise ValueError(f"Unsupported dataset: {dataset_name}")
    return loaders[dataset_name](dataset_file)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnAgent-X experiment on a dataset")
    parser.add_argument("--dataset", required=True, choices=["devign", "bigvul", "primevul", "jit"])
    parser.add_argument("--dataset-file", required=True)
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--llm-provider", choices=["mock", "openai", "ollama"], default=None)
    parser.add_argument("--llm-model", default=None)
    parser.add_argument("--no-semgrep", action="store_true")
    parser.add_argument("--no-treesitter", action="store_true")
    parser.add_argument("--no-verification", action="store_true")
    args = parser.parse_args()

    samples = _load_samples(args.dataset, args.dataset_file)
    base_config = WorkflowConfig.from_env()
    config = base_config.model_copy(
        update={
            "llm_provider": args.llm_provider or base_config.llm_provider,
            "llm_model": args.llm_model or base_config.llm_model,
            "use_semgrep": False if args.no_semgrep else base_config.use_semgrep,
            "use_treesitter": False if args.no_treesitter else base_config.use_treesitter,
            "enable_verification": False if args.no_verification else base_config.enable_verification,
        }
    )

    workflow = VulnAgentWorkflow(config=config)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            state = workflow.run(repo_path=sample.repo_path, diff_text=sample.diff_text)
            record = {
                "sample_id": sample.sample_id,
                "label": sample.label,
                "gold_locations": sample.gold_locations,
                "prediction": 1 if state.final_findings else 0,
                "predicted_locations": [
                    f"{item.location.file_path}:{item.location.start_line}-{item.location.end_line}"
                    for item in state.final_findings
                ],
                "metrics": state.metrics,
                "findings": [item.model_dump(mode="json") for item in state.final_findings],
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
