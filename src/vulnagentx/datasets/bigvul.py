from __future__ import annotations

from vulnagentx.datasets.base import DatasetSample, load_dataset_file


def load_bigvul(path: str) -> list[DatasetSample]:
    return load_dataset_file(path)
