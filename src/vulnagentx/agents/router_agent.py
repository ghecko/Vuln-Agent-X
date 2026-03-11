from __future__ import annotations

from vulnagentx.agents.base import BaseAgent
from vulnagentx.core.state import AgentResult, EvidenceItem, RoutePlan, WorkflowState


class RouterAgent(BaseAgent):
    name = "router_agent"

    _security_hints = (
        "eval(",
        "system(",
        "popen(",
        "shell=true",
        "strcpy(",
        "gets(",
        "select ",
        "insert ",
        "pickle.loads",
        "yaml.load",
    )

    _logic_hints = (
        "for ",
        "while ",
        "if ",
        "<=",
        "< len(",
        " / ",
        "break",
        "continue",
        "return",
    )

    def run(self, state: WorkflowState) -> list[AgentResult]:
        plans: list[RoutePlan] = []
        outputs: list[AgentResult] = []

        for region in state.suspicious_regions:
            text = self.context_for_region(state, region).lower()
            selected = ["semantic_agent"]

            if any(hint in text for hint in self._security_hints):
                selected.append("security_agent")
            if any(hint in text for hint in self._logic_hints):
                selected.append("logic_bug_agent")
            if len(selected) == 1:
                selected.append("security_agent")

            plans.append(
                RoutePlan(
                    location=region.location,
                    selected_agents=selected,
                    rationale=f"region_reason={region.reason}; score={region.score:.2f}",
                )
            )

            outputs.append(
                AgentResult(
                    agent_name=self.name,
                    issue_type="routing_decision",
                    claim=f"Dispatch to {', '.join(selected)}",
                    confidence=min(1.0, region.score + 0.05),
                    notes="Routing signal only; not a vulnerability finding.",
                    supports_issue=False,
                    locations=[region.location],
                    evidence=[
                        EvidenceItem(
                            source=self.name,
                            summary=f"Selected {', '.join(selected)} for region",
                            location=region.location,
                            raw={"region_reason": region.reason, "region_score": region.score},
                        )
                    ],
                )
            )

        state.route_plan = plans
        state.add_log(
            stage=self.name,
            message="Routing complete",
            routed_regions=len(plans),
        )
        return outputs
