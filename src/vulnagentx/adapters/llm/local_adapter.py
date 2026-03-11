from __future__ import annotations

import httpx

from vulnagentx.adapters.llm.base import LLMAdapter


class OllamaAdapter(LLMAdapter):
    """Local LLM adapter using Ollama HTTP API."""

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434") -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        prompt = f"[SYSTEM]\n{system_prompt}\n\n[USER]\n{user_prompt}"
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{self._base_url}/api/generate",
                json={"model": self._model, "prompt": prompt, "stream": False},
            )
            response.raise_for_status()
            payload = response.json()
        text = payload.get("response", "")
        return text if isinstance(text, str) else ""
