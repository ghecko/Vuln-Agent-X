from __future__ import annotations

from fastapi import FastAPI, HTTPException

from vulnagentx.app.schemas import AnalyzeRequest, AnalyzeResponse
from vulnagentx.core.workflow import VulnAgentWorkflow
from vulnagentx.utils.config import WorkflowConfig

app = FastAPI(title="VulnAgent-X API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    if payload.repo_path is None and payload.diff_text is None:
        raise HTTPException(status_code=400, detail="repo_path or diff_text is required")

    base = WorkflowConfig.from_env()
    config = base.model_copy(
        update={
            "llm_provider": payload.llm_provider or base.llm_provider,
            "llm_model": payload.llm_model or base.llm_model,
            "use_semgrep": payload.use_semgrep if payload.use_semgrep is not None else base.use_semgrep,
            "use_treesitter": payload.use_treesitter if payload.use_treesitter is not None else base.use_treesitter,
            "enable_verification": payload.enable_verification if payload.enable_verification is not None else base.enable_verification,
            "semgrep_rules_path": payload.semgrep_rules_path or base.semgrep_rules_path,
        }
    )
    workflow = VulnAgentWorkflow(config=config)

    state = workflow.run(
        repo_path=payload.repo_path,
        diff_text=payload.diff_text,
        target_type=payload.target_type,
    )

    return AnalyzeResponse(
        run_id=state.run_id,
        findings=state.final_findings,
        metrics=state.metrics,
        logs=state.logs,
    )
