from __future__ import annotations

import re

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.agents.base import BaseAgent
from vulnagentx.core.state import AgentResult, EvidenceItem, Severity, WorkflowState


class SemanticAgent(BaseAgent):
    name = "semantic_agent"

    def __init__(self, llm_adapter: LLMAdapter | None = None) -> None:
        self.llm_adapter = llm_adapter

    _rules: tuple[tuple[str, re.Pattern[str], str, str | None, Severity], ...] = (
        (
            "unchecked_return",
            re.compile(r"\b(malloc|calloc|realloc|fopen)\s*\("),
            "Potential unchecked return value for resource allocation/open.",
            "CWE-252",
            Severity.medium,
        ),
        (
            "null_dereference",
            re.compile(r"->|\*\w+"),
            "Potential null dereference path without explicit guard.",
            "CWE-476",
            Severity.high,
        ),
        (
            "unsafe_deserialization",
            re.compile(r"\b(pickle\.loads|yaml\.load\s*\()"),
            "Untrusted deserialization API usage detected.",
            "CWE-502",
            Severity.high,
        ),
        (
            "exception_swallowing",
            re.compile(r"except\s+.*:\s*pass"),
            "Exception is swallowed which may hide broken security checks.",
            "CWE-703",
            Severity.medium,
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
                        system_prompt="You are a semantic vulnerability analysis assistant.",
                        user_prompt=context,
                    )
                    if issue_type.split("_")[0] in llm_note.lower():
                        llm_boost = 0.05

                confidence = min(1.0, 0.45 + region.score * 0.45 + llm_boost)

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
                                summary=f"Pattern `{pattern.pattern}` matched semantic context.",
                                location=region.location,
                                raw={"reason": region.reason, "text_preview": lowered[:220]},
                            )
                        ],
                    )
                )

        state.add_log(
            stage=self.name,
            message="Semantic analysis complete",
            outputs=len(outputs),
        )
        return outputs
