from __future__ import annotations

from vulnagentx.adapters.llm.base import LLMAdapter
from vulnagentx.adapters.llm.local_adapter import OllamaAdapter
from vulnagentx.adapters.llm.mock_adapter import MockLLMAdapter
from vulnagentx.adapters.llm.openai_adapter import OpenAIAdapter
from vulnagentx.utils.config import WorkflowConfig


def build_llm_adapter(config: WorkflowConfig) -> LLMAdapter:
    if config.llm_provider == "openai":
        try:
            return OpenAIAdapter(
                model=config.llm_model,
                api_key=config.llm_api_key,
                base_url=config.llm_base_url,
            )
        except Exception:
            return MockLLMAdapter()

    if config.llm_provider == "ollama":
        base_url = config.llm_base_url or "http://127.0.0.1:11434"
        try:
            return OllamaAdapter(model=config.llm_model, base_url=base_url)
        except Exception:
            return MockLLMAdapter()

    return MockLLMAdapter()
