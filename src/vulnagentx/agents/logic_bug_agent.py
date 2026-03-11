from __future__ import annotations

import re

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.agents.base import BaseAgent
from vulnagentx.core.state import AgentResult, EvidenceItem, Severity, WorkflowState


class LogicBugAgent(BaseAgent):
    name = "logic_bug_agent"

    def __init__(self, llm_adapter: LLMAdapter | None = None) -> None:
        self.llm_adapter = llm_adapter

    _rules: tuple[tuple[str, re.Pattern[str], str, str | None, Severity], ...] = (
        (
            "off_by_one",
            re.compile(r"<=\s*len\s*\(|\bi\s*<=\s*n\b"),
            "Loop boundary looks off-by-one and may exceed valid range.",
            "CWE-193",
            Severity.medium,
        ),
        (
            "division_by_zero",
            re.compile(r"/\s*[a-zA-Z_][a-zA-Z0-9_]*"),
            "Division detected; missing denominator guard may cause runtime failure.",
            "CWE-369",
            Severity.medium,
        ),
        (
            "error_swallowing",
            re.compile(r"if\s+err(or)?\s*:\s*pass|catch\s*\(.*\)\s*\{\s*\}"),
            "Error path appears swallowed and may hide faulty state transitions.",
            "CWE-754",
            Severity.medium,
        ),
        (
            "missing_authz_check",
            re.compile(r"delete|transfer|withdraw|admin", re.IGNORECASE),
            "Sensitive operation found; explicit authorization check not observed nearby.",
            "CWE-285",
            Severity.high,
        ),
    )

    def run(self, state: WorkflowState) -> list[AgentResult]:
        outputs: list[AgentResult] = []

        for region in state.suspicious_regions:
            context = self.context_for_region(state, region)
            lowered = context.lower()

            for issue_type, pattern, claim, cwe, severity in self._rules:
                if not pattern.search(context):
                    continue

                llm_note = ""
                llm_boost = 0.0
                if self.llm_adapter is not None:
                    llm_note = self.llm_adapter.complete(
                        system_prompt="You review logic-level software flaws.",
                        user_prompt=context,
                    )
                    if "no strong signal" not in llm_note.lower():
                        llm_boost = 0.03

                confidence = min(1.0, 0.40 + region.score * 0.40 + llm_boost)

                outputs.append(
                    AgentResult(
                        agent_name=self.name,
                        issue_type=issue_type,
                        claim=claim,
                        confidence=confidence,
                        severity=severity,
                        optional_cwe=cwe,
                        locations=[region.location],
                        notes=llm_note,
                        evidence=[
                            EvidenceItem(
                                source=self.name,
                                summary=f"Logic rule `{pattern.pattern}` matched control-flow signal.",
                                location=region.location,
                                raw={"screen_reason": region.reason, "context_preview": lowered[:220]},
                            )
                        ],
                    )
                )

        state.add_log(
            stage=self.name,
            message="Logic analysis complete",
            outputs=len(outputs),
        )
        return outputs
