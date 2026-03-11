from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from vulnagentx.core.state import CodeLocation, EscalationStep, WorkflowState


class EscalationAction(str, Enum):
    early_exit = "early_exit"
    expert_review = "expert_review"
    verification = "verification"


class EscalationDecision(BaseModel):
    location: CodeLocation
    action: EscalationAction
    rationale: str


HIGH_RISK_REASONS = {"unsafe_c_copy", "command_exec", "dangerous_eval", "sql_concat"}


def compute_escalation(state: WorkflowState) -> list[EscalationDecision]:
    decisions: list[EscalationDecision] = []
    for region in state.suspicious_regions:
        if region.score >= 0.85:
            decisions.append(
                EscalationDecision(
                    location=region.location,
                    action=EscalationAction.early_exit,
                    rationale="High confidence screening signal",
                )
            )
            continue

        if region.score >= 0.60:
            decisions.append(
                EscalationDecision(
                    location=region.location,
                    action=EscalationAction.expert_review,
                    rationale="Moderate confidence requires multi-agent review",
                )
            )
            continue

        if region.reason in HIGH_RISK_REASONS:
            decisions.append(
                EscalationDecision(
                    location=region.location,
                    action=EscalationAction.verification,
                    rationale="Low confidence but high-risk issue family",
                )
            )
        else:
            decisions.append(
                EscalationDecision(
                    location=region.location,
                    action=EscalationAction.expert_review,
                    rationale="Default review path",
                )
            )

    state.add_log(
        stage="scheduler",
        message="Escalation policy computed",
        decisions=len(decisions),
    )
    state.escalation_plan = [
        EscalationStep(location=item.location, action=item.action.value, rationale=item.rationale)
        for item in decisions
    ]
    return decisions
