from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LocalizationMetrics:
    top1: float
    top3: float
    mrr: float


def compute_localization_metrics(gold_locations: list[list[str]], ranked_predictions: list[list[str]]) -> LocalizationMetrics:
    if len(gold_locations) != len(ranked_predictions):
        raise ValueError("gold_locations and ranked_predictions must have the same length")

    if not gold_locations:
        return LocalizationMetrics(top1=0.0, top3=0.0, mrr=0.0)

    top1_hits = 0
    top3_hits = 0
    mrr_sum = 0.0

    for gold, preds in zip(gold_locations, ranked_predictions):
        gold_set = set(gold)
        if not gold_set:
            continue

        if preds[:1] and preds[0] in gold_set:
            top1_hits += 1

        if any(pred in gold_set for pred in preds[:3]):
            top3_hits += 1

        reciprocal_rank = 0.0
        for rank, pred in enumerate(preds, start=1):
            if pred in gold_set:
                reciprocal_rank = 1.0 / rank
                break
        mrr_sum += reciprocal_rank

    n = len(gold_locations)
    return LocalizationMetrics(
        top1=top1_hits / n,
        top3=top3_hits / n,
        mrr=mrr_sum / n,
    )
