from __future__ import annotations

import re

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.agents.base import BaseAgent
from vulnagentx.core.state import AgentResult, EvidenceItem, Severity, WorkflowState


class SecurityAgent(BaseAgent):
    name = "security_agent"

    def __init__(self, llm_adapter: LLMAdapter | None = None) -> None:
        self.llm_adapter = llm_adapter

    _rules: tuple[tuple[str, re.Pattern[str], str, str | None, Severity], ...] = (
        (
            "command_injection",
            re.compile(r"\b(system|popen|exec|subprocess\.(Popen|run|call))\s*\("),
            "Command execution surface detected; validate all untrusted inputs.",
            "CWE-78",
            Severity.critical,
        ),
        (
            "sql_injection",
            re.compile(r"(select|insert|update|delete)\s+.*(\+|%s|\{)" , re.IGNORECASE),
            "Potential SQL query string composition with untrusted data.",
            "CWE-89",
            Severity.high,
        ),
        (
            "buffer_overflow",
            re.compile(r"\b(strcpy|strcat|sprintf|gets)\s*\("),
            "Unsafe C string API usage may cause out-of-bounds write/read.",
            "CWE-120",
            Severity.critical,
        ),
        (
            "path_traversal",
            re.compile(r"open\s*\(\s*.*(user|request|input|path)"),
            "File path derived from user input without canonicalization.",
            "CWE-22",
            Severity.high,
        ),
    )

    def run(self, state: WorkflowState) -> list[AgentResult]:
        outputs: list[AgentResult] = []

        for region in state.suspicious_regions:
            context = self.context_for_region(state, region)
            lower = context.lower()

            for issue_type, pattern, claim, cwe, severity in self._rules:
                if not pattern.search(context):
                    continue

                llm_note = ""
                llm_boost = 0.0
                if self.llm_adapter is not None:
                    llm_note = self.llm_adapter.complete(
                        system_prompt="You are a security vulnerability triage assistant.",
                        user_prompt=context,
                    )
                    if "injection" in llm_note.lower() and "injection" in issue_type:
                        llm_boost = 0.07

                confidence = min(1.0, 0.55 + region.score * 0.35 + llm_boost)

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
                                summary=f"Security rule `{pattern.pattern}` matched risky API usage.",
                                location=region.location,
                                raw={"screen_reason": region.reason, "context_preview": lower[:220]},
                            )
                        ],
                    )
                )

        state.add_log(
            stage=self.name,
            message="Security analysis complete",
            outputs=len(outputs),
        )
        return outputs
