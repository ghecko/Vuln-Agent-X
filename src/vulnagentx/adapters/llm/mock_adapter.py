from __future__ import annotations

from vulnagentx.adapters.llm.base import LLMAdapter


class MockLLMAdapter(LLMAdapter):
    """Deterministic adapter for offline testing."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        digest = (system_prompt + user_prompt).lower()
        if "sql" in digest:
            return "Potential SQL injection due to string-concatenated query."
        if "system(" in digest or "shell=true" in digest:
            return "Potential command injection risk from shell execution."
        return "No strong signal from mock model; rely on heuristic evidence."
