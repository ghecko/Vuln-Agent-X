from __future__ import annotations

from typing import Any

from vulnagentx.adapters.llm.base import LLMAdapter


class OpenAIAdapter(LLMAdapter):
    """OpenAI adapter backed by the official openai python package."""

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None) -> None:
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - runtime dependency
            raise RuntimeError(
                "openai package is not installed. Install with `pip install openai`."
            ) from exc

        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url

        self._client = OpenAI(**kwargs)
        self._model = model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            temperature=0,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.choices[0].message.content
        return content or ""
