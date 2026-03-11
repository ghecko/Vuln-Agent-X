from __future__ import annotations

from pydantic import BaseModel, Field

from vulnagentx.core.state import Finding, LogEvent, TargetType
from vulnagentx.utils.config import LLMProvider


class AnalyzeRequest(BaseModel):
    repo_path: str | None = None
    diff_text: str | None = None
    target_type: TargetType | None = None
    llm_provider: LLMProvider | None = None
    llm_model: str | None = None
    use_semgrep: bool | None = None
    use_treesitter: bool | None = None
    enable_verification: bool | None = None
    semgrep_rules_path: str | None = None


class AnalyzeResponse(BaseModel):
    run_id: str
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    logs: list[LogEvent] = Field(default_factory=list)
