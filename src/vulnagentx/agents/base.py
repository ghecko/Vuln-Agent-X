from __future__ import annotations

from abc import ABC, abstractmethod

from vulnagentx.core.state import AgentResult, SuspiciousRegion, WorkflowState


class BaseAgent(ABC):
    name: str

    @abstractmethod
    def run(self, state: WorkflowState) -> list[AgentResult]:
        raise NotImplementedError

    @staticmethod
    def context_for_region(state: WorkflowState, region: SuspiciousRegion) -> str:
        key = f"{region.location.file_path}:{region.location.start_line}-{region.location.end_line}"
        return state.retrieved_context.get(key, region.snippet)
