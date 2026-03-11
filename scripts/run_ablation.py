#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from vulnagentx.datasets import load_bigvul, load_devign, load_jit, load_primevul
from vulnagentx.eval.ablations import AblationVariant, run_ablation
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
    parser = argparse.ArgumentParser(description="Run component ablation experiments")
    parser.add_argument("--dataset", required=True, choices=["devign", "bigvul", "primevul", "jit"])
    parser.add_argument("--dataset-file", required=True)
    args = parser.parse_args()

    samples = _load_samples(args.dataset, args.dataset_file)
    base = WorkflowConfig.from_env()
    variants = [
        AblationVariant(name="full", updates={}),
        AblationVariant(name="no_semgrep", updates={"use_semgrep": False}),
        AblationVariant(name="no_treesitter", updates={"use_treesitter": False}),
        AblationVariant(name="no_sceptic", updates={"enable_sceptic": False}),
        AblationVariant(name="no_verification", updates={"enable_verification": False}),
    ]

    metrics = run_ablation(samples=samples, base_config=base, variants=variants)
    report = {name: metric.__dict__ for name, metric in metrics.items()}
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
