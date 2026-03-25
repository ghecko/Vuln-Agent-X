from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, Field


LLMProvider = Literal["mock", "openai", "ollama"]

# Well-known agent names for per-agent model configuration.
AGENT_NAMES = ("semantic_agent", "security_agent", "logic_bug_agent")


class WorkflowConfig(BaseModel):
    llm_provider: LLMProvider = "mock"
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str | None = None
    llm_base_url: str | None = None

    # Per-agent model overrides.
    # Keys are agent names (e.g. "semantic_agent"), values are model
    # identifiers (e.g. "qwen2.5:8b", "qwen2.5:32b").
    # When an agent is not listed here it falls back to ``llm_model``.
    agent_models: dict[str, str] = Field(default_factory=dict)

    use_semgrep: bool = True
    semgrep_config: str = "auto"
    semgrep_rules_path: str | None = None

    use_treesitter: bool = True
    context_line_radius: int = Field(default=8, ge=2, le=60)
    max_context_regions: int = Field(default=25, ge=1, le=200)

    enable_sceptic: bool = True
    enable_verification: bool = True
    verification_timeout_seconds: int = Field(default=20, ge=3, le=120)
    verification_run_tests: bool = False

    def model_for_agent(self, agent_name: str) -> str:
        """Return the model identifier for a given agent, falling back to the default."""
        return self.agent_models.get(agent_name, self.llm_model)

    @classmethod
    def from_env(cls) -> "WorkflowConfig":
        def _env_bool(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None:
                return default
            return raw.strip().lower() in {"1", "true", "yes", "on"}

        provider = os.getenv("VULNAGENTX_LLM_PROVIDER", "mock").strip().lower()
        if provider not in {"mock", "openai", "ollama"}:
            provider = "mock"
        llm_provider = cast(LLMProvider, provider)

        default_rules = None
        candidate = Path(__file__).resolve().parents[3] / "rules" / "semgrep" / "vulnagentx-rules.yml"
        if candidate.exists():
            default_rules = str(candidate)

        # Build per-agent model overrides from environment variables.
        # Format: VULNAGENTX_MODEL_<AGENT_SUFFIX>=<model_name>
        # Examples:
        #   VULNAGENTX_MODEL_SEMANTIC_AGENT=qwen2.5:8b
        #   VULNAGENTX_MODEL_SECURITY_AGENT=qwen2.5:32b
        #   VULNAGENTX_MODEL_LOGIC_BUG_AGENT=qwen2.5:32b
        agent_models: dict[str, str] = {}
        for agent_name in AGENT_NAMES:
            env_key = f"VULNAGENTX_MODEL_{agent_name.upper()}"
            value = os.getenv(env_key)
            if value:
                agent_models[agent_name] = value.strip()

        return cls(
            llm_provider=llm_provider,
            llm_model=os.getenv("VULNAGENTX_LLM_MODEL", "gpt-4o-mini"),
            llm_api_key=os.getenv("OPENAI_API_KEY"),
            llm_base_url=os.getenv("VULNAGENTX_LLM_BASE_URL"),
            agent_models=agent_models,
            use_semgrep=_env_bool("VULNAGENTX_USE_SEMGREP", True),
            semgrep_config=os.getenv("VULNAGENTX_SEMGREP_CONFIG", "auto"),
            semgrep_rules_path=os.getenv("VULNAGENTX_SEMGREP_RULES_PATH", default_rules),
            use_treesitter=_env_bool("VULNAGENTX_USE_TREESITTER", True),
            context_line_radius=int(os.getenv("VULNAGENTX_CONTEXT_RADIUS", "8")),
            max_context_regions=int(os.getenv("VULNAGENTX_MAX_CONTEXT_REGIONS", "25")),
            enable_sceptic=_env_bool("VULNAGENTX_ENABLE_SCEPTIC", True),
            enable_verification=_env_bool("VULNAGENTX_ENABLE_VERIFICATION", True),
            verification_timeout_seconds=int(os.getenv("VULNAGENTX_VERIFICATION_TIMEOUT", "20")),
            verification_run_tests=_env_bool("VULNAGENTX_VERIFICATION_RUN_TESTS", False),
        )
