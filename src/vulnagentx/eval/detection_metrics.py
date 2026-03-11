from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectionMetrics:
    precision: float
    recall: float
    f1: float
    accuracy: float
    tp: int
    fp: int
    tn: int
    fn: int


def compute_detection_metrics(labels: list[int], predictions: list[int]) -> DetectionMetrics:
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")

    tp = fp = tn = fn = 0
    for label, pred in zip(labels, predictions):
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 0 and pred == 0:
            tn += 1
        elif label == 1 and pred == 0:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0

    return DetectionMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
    )
