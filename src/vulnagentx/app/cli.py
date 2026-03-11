from __future__ import annotations

import json
from pathlib import Path

import typer

from vulnagentx.core.workflow import VulnAgentWorkflow
from vulnagentx.utils.config import LLMProvider, WorkflowConfig

app = typer.Typer(help="VulnAgent-X research prototype CLI", no_args_is_help=True)


@app.callback()
def _root() -> None:
    """CLI root."""


@app.command("analyze")
def analyze(
    repo: str | None = typer.Option(None, "--repo", help="Local repository path"),
    diff_file: str | None = typer.Option(None, "--diff-file", help="Path to unified diff/patch file"),
    output: str = typer.Option("json", "--output", help="Output format: json or summary"),
    llm_provider: LLMProvider | None = typer.Option(None, "--llm-provider", help="mock/openai/ollama"),
    llm_model: str | None = typer.Option(None, "--llm-model", help="Model name for selected provider"),
    use_semgrep: bool | None = typer.Option(None, "--use-semgrep/--no-semgrep", help="Enable Semgrep screening"),
    use_treesitter: bool | None = typer.Option(None, "--use-treesitter/--no-treesitter", help="Enable Tree-sitter context"),
    enable_verification: bool | None = typer.Option(None, "--enable-verification/--no-verification", help="Enable sandbox verification"),
    semgrep_rules_path: str | None = typer.Option(None, "--semgrep-rules-path", help="Path to custom Semgrep rules"),
) -> None:
    if repo is None and diff_file is None:
        raise typer.BadParameter("Either --repo or --diff-file must be provided.")

    diff_text: str | None = None
    if diff_file is not None:
        diff_text = Path(diff_file).read_text(encoding="utf-8", errors="ignore")

    base = WorkflowConfig.from_env()
    config = base.model_copy(
        update={
            "llm_provider": llm_provider or base.llm_provider,
            "llm_model": llm_model or base.llm_model,
            "use_semgrep": use_semgrep if use_semgrep is not None else base.use_semgrep,
            "use_treesitter": use_treesitter if use_treesitter is not None else base.use_treesitter,
            "enable_verification": enable_verification if enable_verification is not None else base.enable_verification,
            "semgrep_rules_path": semgrep_rules_path or base.semgrep_rules_path,
        }
    )

    workflow = VulnAgentWorkflow(config=config)
    state = workflow.run(repo_path=repo, diff_text=diff_text)

    if output == "summary":
        typer.echo(f"run_id={state.run_id}")
        typer.echo(f"findings={len(state.final_findings)} runtime={state.metrics.get('runtime_seconds', 0.0)}s")
        for item in state.final_findings[:10]:
            loc = f"{item.location.file_path}:{item.location.start_line}-{item.location.end_line}"
            typer.echo(f"- {item.issue_type} {loc} conf={item.confidence:.2f} sev={item.severity.value}")
        return

    payload = {
        "run_id": state.run_id,
        "findings": [item.model_dump(mode="json") for item in state.final_findings],
        "metrics": state.metrics,
        "logs": [item.model_dump(mode="json") for item in state.logs],
    }
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    app()
