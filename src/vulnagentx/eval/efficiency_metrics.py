from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EfficiencyMetrics:
    avg_runtime_seconds: float
    p95_runtime_seconds: float
    avg_findings: float


def compute_efficiency_metrics(runtimes: list[float], findings_count: list[int]) -> EfficiencyMetrics:
    if not runtimes:
        return EfficiencyMetrics(avg_runtime_seconds=0.0, p95_runtime_seconds=0.0, avg_findings=0.0)

    ordered = sorted(runtimes)
    p95_index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))

    avg_runtime = sum(runtimes) / len(runtimes)
    avg_findings = sum(findings_count) / len(findings_count) if findings_count else 0.0

    return EfficiencyMetrics(
        avg_runtime_seconds=avg_runtime,
        p95_runtime_seconds=ordered[p95_index],
        avg_findings=avg_findings,
    )
