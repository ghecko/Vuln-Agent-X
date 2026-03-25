from __future__ import annotations

import time
import uuid

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.adapters.llm.factory import build_agent_llm_adapters, build_llm_adapter
from vulnagentx.agents.logic_bug_agent import LogicBugAgent
from vulnagentx.agents.router_agent import RouterAgent
from vulnagentx.agents.sceptic_agent import ScepticAgent
from vulnagentx.agents.security_agent import SecurityAgent
from vulnagentx.agents.semantic_agent import SemanticAgent
from vulnagentx.core.context_expansion import run_context_expansion
from vulnagentx.core.evidence_fusion import fuse_evidence
from vulnagentx.core.scheduler import compute_escalation
from vulnagentx.core.screening import run_screening
from vulnagentx.core.state import AgentResult, TargetType, WorkflowState
from vulnagentx.core.verification import run_optional_verification
from vulnagentx.utils.config import WorkflowConfig


class VulnAgentWorkflow:
    def __init__(self, llm_adapter: LLMAdapter | None = None, config: WorkflowConfig | None = None) -> None:
        self.config = config or WorkflowConfig.from_env()
        # Build per-agent adapters (respects agent_models overrides).
        self._agent_adapters = build_agent_llm_adapters(self.config)
        # Keep a single default for backward compatibility.
        self.llm_adapter = llm_adapter or self._agent_adapters.get("_default") or build_llm_adapter(self.config)

    def _adapter_for(self, agent_name: str) -> LLMAdapter:
        """Return the LLM adapter configured for a specific agent."""
        return self._agent_adapters.get(agent_name, self.llm_adapter)

    @staticmethod
    def _loc_key(file_path: str, start_line: int, end_line: int) -> str:
        return f"{file_path}:{start_line}-{end_line}"

    def _filter_results_for_agent(self, state: WorkflowState, agent_name: str, results: list[AgentResult]) -> list[AgentResult]:
        allowed = {
            self._loc_key(item.location.file_path, item.location.start_line, item.location.end_line)
            for item in state.route_plan
            if agent_name in item.selected_agents
        }
        if not allowed:
            return []

        filtered: list[AgentResult] = []
        for result in results:
            if not result.locations:
                continue
            loc_keys = {
                self._loc_key(loc.file_path, loc.start_line, loc.end_line)
                for loc in result.locations
            }
            if allowed.intersection(loc_keys):
                filtered.append(result)
        return filtered

    def run(
        self,
        repo_path: str | None = None,
        diff_text: str | None = None,
        target_type: TargetType | None = None,
    ) -> WorkflowState:
        start = time.perf_counter()

        inferred_target = target_type
        if inferred_target is None:
            inferred_target = TargetType.diff if diff_text else TargetType.repository

        state = WorkflowState(
            run_id=uuid.uuid4().hex,
            repo_path=repo_path,
            diff_text=diff_text,
            target_type=inferred_target,
        )

        # Build a readable model assignment map for the log.
        model_map = {
            name: self.config.model_for_agent(name)
            for name in ("semantic_agent", "security_agent", "logic_bug_agent")
        }

        state.add_log(
            stage="workflow",
            message="Workflow started",
            llm_provider=self.config.llm_provider,
            default_model=self.config.llm_model,
            agent_models=model_map,
            semgrep_enabled=self.config.use_semgrep,
            treesitter_enabled=self.config.use_treesitter,
            verification_enabled=self.config.enable_verification,
        )

        run_screening(
            state,
            use_semgrep=self.config.use_semgrep,
            semgrep_config=self.config.semgrep_config,
            semgrep_rules_path=self.config.semgrep_rules_path,
        )
        run_context_expansion(
            state,
            max_regions=self.config.max_context_regions,
            line_radius=self.config.context_line_radius,
            use_treesitter=self.config.use_treesitter,
        )
        compute_escalation(state)

        router = RouterAgent()
        state.agent_outputs[router.name] = router.run(state)

        specialists = [
            SemanticAgent(llm_adapter=self._adapter_for("semantic_agent")),
            SecurityAgent(llm_adapter=self._adapter_for("security_agent")),
            LogicBugAgent(llm_adapter=self._adapter_for("logic_bug_agent")),
        ]

        for agent in specialists:
            raw_results = agent.run(state)
            state.agent_outputs[agent.name] = self._filter_results_for_agent(
                state=state,
                agent_name=agent.name,
                results=raw_results,
            )

        if self.config.enable_sceptic:
            sceptic = ScepticAgent()
            state.agent_outputs[sceptic.name] = sceptic.run(state)
        else:
            state.agent_outputs["sceptic_agent"] = []
            state.add_log(stage="sceptic_agent", message="Sceptic agent disabled")

        run_optional_verification(
            state,
            enable_verification=self.config.enable_verification,
            timeout_seconds=self.config.verification_timeout_seconds,
            run_tests=self.config.verification_run_tests,
            semgrep_config=self.config.semgrep_config,
            semgrep_rules_path=self.config.semgrep_rules_path,
        )
        fuse_evidence(state)

        elapsed = time.perf_counter() - start
        state.metrics["runtime_seconds"] = round(elapsed, 4)
        state.add_log(stage="workflow", message="Workflow finished", runtime_seconds=elapsed)
        return state
