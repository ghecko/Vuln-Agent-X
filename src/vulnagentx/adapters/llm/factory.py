from __future__ import annotations

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.adapters.llm.local_adapter import OllamaAdapter
from vulnagentx.adapters.llm.mock_adapter import MockLLMAdapter
from vulnagentx.adapters.llm.openai_adapter import OpenAIAdapter
from vulnagentx.utils.config import AGENT_NAMES, WorkflowConfig


def _build_single_adapter(
    provider: str,
    model: str,
    api_key: str | None,
    base_url: str | None,
) -> LLMAdapter:
    """Build one LLM adapter for a specific provider/model combination."""
    if provider == "openai":
        try:
            return OpenAIAdapter(model=model, api_key=api_key, base_url=base_url)
        except Exception:
            return MockLLMAdapter()

    if provider == "ollama":
        effective_url = base_url or "http://127.0.0.1:11434"
        try:
            return OllamaAdapter(model=model, base_url=effective_url)
        except Exception:
            return MockLLMAdapter()

    return MockLLMAdapter()


def build_llm_adapter(config: WorkflowConfig) -> LLMAdapter:
    """Build the default (fallback) LLM adapter from config."""
    return _build_single_adapter(
        provider=config.llm_provider,
        model=config.llm_model,
        api_key=config.llm_api_key,
        base_url=config.llm_base_url,
    )


def build_agent_llm_adapters(config: WorkflowConfig) -> dict[str, LLMAdapter]:
    """Build a mapping of agent_name -> LLMAdapter.

    Agents that have a per-agent model override in ``config.agent_models``
    get their own adapter instance.  Agents without an override share the
    default adapter built from ``config.llm_model``.

    Returns a dict keyed by agent name.  The special key ``"_default"``
    always holds the fallback adapter.
    """
    default_adapter = build_llm_adapter(config)
    adapters: dict[str, LLMAdapter] = {"_default": default_adapter}

    for agent_name in AGENT_NAMES:
        agent_model = config.agent_models.get(agent_name)
        if agent_model and agent_model != config.llm_model:
            # This agent gets its own adapter with the overridden model.
            adapters[agent_name] = _build_single_adapter(
                provider=config.llm_provider,
                model=agent_model,
                api_key=config.llm_api_key,
                base_url=config.llm_base_url,
            )
        else:
            adapters[agent_name] = default_adapter

    return adapters
