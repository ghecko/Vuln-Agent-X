from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DatasetSample:
    sample_id: str
    repo_path: str | None = None
    diff_text: str | None = None
    label: int = 0
    gold_locations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _coerce_locations(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw if isinstance(item, (str, int))]
    if isinstance(raw, str) and raw.strip():
        return [segment.strip() for segment in raw.split(";") if segment.strip()]
    return []


def load_jsonl(path: str) -> list[DatasetSample]:
    samples: list[DatasetSample] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            payload = json.loads(raw)
            sample_id = str(payload.get("id", f"sample-{idx}"))
            samples.append(
                DatasetSample(
                    sample_id=sample_id,
                    repo_path=payload.get("repo_path"),
                    diff_text=payload.get("diff_text"),
                    label=int(payload.get("label", 0)),
                    gold_locations=_coerce_locations(payload.get("gold_locations")),
                    metadata={k: v for k, v in payload.items() if k not in {"id", "repo_path", "diff_text", "label", "gold_locations"}},
                )
            )
    return samples


def load_csv_file(path: str) -> list[DatasetSample]:
    samples: list[DatasetSample] = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            sample_id = row.get("id") or f"sample-{idx}"
            samples.append(
                DatasetSample(
                    sample_id=sample_id,
                    repo_path=row.get("repo_path") or None,
                    diff_text=row.get("diff_text") or None,
                    label=int(row.get("label") or 0),
                    gold_locations=_coerce_locations(row.get("gold_locations")),
                    metadata={k: v for k, v in row.items() if k not in {"id", "repo_path", "diff_text", "label", "gold_locations"}},
                )
            )
    return samples


def load_dataset_file(path: str) -> list[DatasetSample]:
    suffix = Path(path).suffix.lower()
    if suffix == ".jsonl":
        return load_jsonl(path)
    if suffix in {".csv", ".tsv"}:
        return load_csv_file(path)
    raise ValueError(f"Unsupported dataset format: {suffix}")
