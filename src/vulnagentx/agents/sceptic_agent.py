from __future__ import annotations

from collections import Counter, defaultdict

from vulnagentx.agents.base import BaseAgent
from vulnagentx.core.state import AgentResult, CodeLocation, EvidenceItem, Severity, WorkflowState


class ScepticAgent(BaseAgent):
    name = "sceptic_agent"

    def run(self, state: WorkflowState) -> list[AgentResult]:
        grouped: dict[str, list[AgentResult]] = defaultdict(list)
        for agent_name, results in state.agent_outputs.items():
            if agent_name in {self.name, "router_agent"}:
                continue
            for result in results:
                if not result.locations:
                    continue
                for loc in result.locations:
                    key = f"{loc.file_path}:{loc.start_line}-{loc.end_line}"
                    grouped[key].append(result)

        sceptic_outputs: list[AgentResult] = []
        counter_evidence: list[EvidenceItem] = []

        for key, claims in grouped.items():
            first_loc = claims[0].locations[0] if claims[0].locations else CodeLocation(file_path="unknown")
            mean_conf = sum(item.confidence for item in claims) / len(claims)

            issue_counter = Counter(item.issue_type for item in claims)
            top_issue_count = issue_counter.most_common(1)[0][1]
            disagreement = 1.0 - (top_issue_count / len(claims))

            skepticism = 0.0
            reasons: list[str] = []
            if len(claims) == 1 and mean_conf < 0.75:
                skepticism += 0.25
                reasons.append("single-agent support")
            if disagreement > 0.4 and len(claims) > 1:
                skepticism += 0.20
                reasons.append("cross-agent disagreement")
            if mean_conf < 0.55:
                skepticism += 0.25
                reasons.append("low-average-confidence")

            if skepticism <= 0:
                continue

            skepticism = min(0.95, skepticism)
            evidence = EvidenceItem(
                source=self.name,
                summary=f"Counter-evidence for {key}: {', '.join(reasons)}",
                location=first_loc,
                raw={"mean_confidence": round(mean_conf, 4), "disagreement": round(disagreement, 4)},
            )
            counter_evidence.append(evidence)

            sceptic_outputs.append(
                AgentResult(
                    agent_name=self.name,
                    issue_type="counter_evidence",
                    claim="Insufficient or conflicting evidence; reduce final confidence.",
                    confidence=skepticism,
                    severity=Severity.low,
                    supports_issue=False,
                    locations=[first_loc],
                    notes=f"Reasons: {', '.join(reasons)}",
                    evidence=[evidence],
                )
            )

        state.counter_evidence.extend(counter_evidence)
        state.add_log(
            stage=self.name,
            message="Sceptic review complete",
            counter_evidence=len(counter_evidence),
        )
        return sceptic_outputs
