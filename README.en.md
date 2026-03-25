<p align="right">
  <a href="./README.zh.md"><img src="https://img.shields.io/badge/Language-Chinese-lightgrey" alt="Chinese"></a>
  <a href="./README.en.md"><img src="https://img.shields.io/badge/Language-English-blue" alt="English"></a>
</p>

# VulnAgent-X Research Prototype

VulnAgent-X is a research-focused multi-agent prototype for bug and vulnerability detection.
It takes a local repository or diff as input, and outputs structured findings, evidence chains, localization, confidence, and experiment logs.

## Core Capabilities

- Inputs: `repo path` or `unified diff`
- Workflow: `screening -> context expansion -> scheduler -> router -> experts -> sceptic -> verification(stub) -> evidence fusion`
- Output fields:
  - `issue_type`
  - `location(file + line range)`
  - `evidence_summary`
  - `confidence`
  - `severity`
  - `optional_cwe`
  - `fix_hint`
  - `evidence_chain`
  - `counter_evidence`
- Interfaces: CLI + FastAPI
- Reproducibility: pytest / mypy / ruff + Docker support

## Workflow Overview

1. `screening`: fast suspicious-region extraction (rules + metadata signals)
2. `context_expansion`: fetch minimal sufficient local context around suspicious locations
3. `scheduler`: confidence-aware escalation policy (early_exit / expert_review / verification)
4. `router_agent`: choose specialist agents per suspicious region
5. `semantic/security/logic`: produce structured claims and evidence from different perspectives
6. `sceptic_agent`: generate counter-evidence and confidence penalties
7. `verification`: optional dynamic verification (currently a safe placeholder)
8. `evidence_fusion`: merge all evidence and produce final findings

## Setup and Usage Tutorial

### 1) Environment Setup

Requirement: Python `3.11+` (higher versions also work in this prototype).

```bash
cd /path/to/vulnAgentX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

### 2) CLI Usage

Analyze a repository:

```bash
.venv/bin/vulnagentx analyze --repo /path/to/repo --output json
```

Analyze a diff file:

```bash
.venv/bin/vulnagentx analyze --diff-file /path/to/patch.diff --output json
```

Short summary output:

```bash
.venv/bin/vulnagentx analyze --repo /path/to/repo --output summary
```

### 3) API Usage

Start server:

```bash
.venv/bin/uvicorn vulnagentx.app.api:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Run analysis request:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_path":"/path/to/repo"}'
```

### 4) Run with Docker

```bash
docker compose -f docker/docker-compose.yml up --build
```

### 5) Quality Checks and Tests

```bash
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/pytest
```

## Output Example

```json
{
  "run_id": "...",
  "findings": [
    {
      "issue_type": "command_injection",
      "location": {"file_path": "app.py", "start_line": 42, "end_line": 42},
      "evidence_summary": "Command execution surface detected...",
      "confidence": 0.87,
      "severity": "critical",
      "optional_cwe": "CWE-78",
      "fix_hint": "Avoid shell command composition...",
      "source_agents": ["security_agent", "semantic_agent"],
      "evidence_chain": [],
      "counter_evidence": []
    }
  ],
  "metrics": {
    "runtime_seconds": 0.07
  },
  "logs": []
}
```

## File-by-File Purpose

### Root and Infrastructure Files

| File | Purpose |
|---|---|
| `.env.example` | Environment template for optional runtime settings (for example log level). |
| `pyproject.toml` | Build system, dependencies, script entrypoints, pytest/ruff/mypy configuration. |
| `README.md` | Main README with language switch buttons (default English). |
| `README.zh.md` | Full Chinese documentation. |
| `README.en.md` | Full English documentation. |
| `docker/Dockerfile` | Container image build file for API service. |
| `docker/docker-compose.yml` | One-command local container startup. |
| `rules/semgrep/vulnagentx-rules.yml` | Built-in Semgrep rules for injection/deserialization/unsafe C APIs. |
| `scripts/run_experiment.py` | Batch dataset runner that writes JSONL predictions. |
| `scripts/evaluate.py` | Metrics evaluator for experiment outputs. |
| `scripts/run_ablation.py` | Component ablation runner (`no_semgrep/no_treesitter/no_sceptic/no_verification`). |

### Core Source Files (`src/vulnagentx`)

| File | Purpose |
|---|---|
| `src/vulnagentx/__init__.py` | Package version and exports. |
| `src/vulnagentx/app/__init__.py` | `app` package initializer. |
| `src/vulnagentx/app/cli.py` | CLI entrypoint (`vulnagentx analyze`). |
| `src/vulnagentx/app/api.py` | FastAPI entrypoint (`/health`, `/analyze`). |
| `src/vulnagentx/app/schemas.py` | Pydantic request/response schemas for API. |
| `src/vulnagentx/core/__init__.py` | `core` package initializer. |
| `src/vulnagentx/core/state.py` | Global state models: regions, evidence, agent outputs, findings, logs, metrics. |
| `src/vulnagentx/core/screening.py` | Stage-1 fast risk screening and suspicious region extraction. |
| `src/vulnagentx/core/context_expansion.py` | Context expansion with bounded local code windows. |
| `src/vulnagentx/core/scheduler.py` | Confidence-aware escalation policy (early_exit/expert_review/verification). |
| `src/vulnagentx/core/verification.py` | Optional dynamic verification module (safe placeholder for now). |
| `src/vulnagentx/core/evidence_fusion.py` | Final evidence fusion and finding ranking. |
| `src/vulnagentx/core/workflow.py` | End-to-end orchestration entry (`VulnAgentWorkflow`). |
| `src/vulnagentx/agents/__init__.py` | Agent export aggregator. |
| `src/vulnagentx/agents/base.py` | Agent abstract base and shared context helper. |
| `src/vulnagentx/agents/router_agent.py` | Router agent: dispatches specialists by region. |
| `src/vulnagentx/agents/semantic_agent.py` | Semantic agent: semantic code-risk signals (null deref, deserialization, etc.). |
| `src/vulnagentx/agents/security_agent.py` | Security agent: vulnerability patterns (command injection, SQLi, overflow, etc.). |
| `src/vulnagentx/agents/logic_bug_agent.py` | Logic agent: control-flow/business logic defects (bounds, division, authz, etc.). |
| `src/vulnagentx/agents/sceptic_agent.py` | Sceptic agent: counter-evidence generation and confidence penalty. |
| `src/vulnagentx/adapters/__init__.py` | Adapter package initializer. |
| `src/vulnagentx/adapters/sandbox_adapter.py` | Sandboxed subprocess executor with timeout/no-shell constraints for verification. |
| `src/vulnagentx/adapters/semgrep_adapter.py` | Semgrep CLI adapter (optional). |
| `src/vulnagentx/adapters/treesitter_adapter.py` | Tree-sitter adapter with AST extraction + fallback heuristics. |
| `src/vulnagentx/adapters/llm/__init__.py` | LLM adapter exports. |
| `src/vulnagentx/adapters/llm/base.py` | LLM adapter protocol interface. |
| `src/vulnagentx/adapters/llm/mock_adapter.py` | Deterministic mock LLM for offline tests. |
| `src/vulnagentx/adapters/llm/openai_adapter.py` | OpenAI SDK adapter implementation. |
| `src/vulnagentx/adapters/llm/local_adapter.py` | Local model adapter (Ollama HTTP API). |
| `src/vulnagentx/adapters/llm/factory.py` | Provider-based adapter factory with mock fallback. |
| `src/vulnagentx/retrieval/repo_graph.py` | Repository code-graph indexing and neighbor retrieval. |
| `src/vulnagentx/datasets/base.py` | Shared dataset sample model and JSONL/CSV loaders. |
| `src/vulnagentx/datasets/devign.py` | Devign loader entrypoint. |
| `src/vulnagentx/datasets/bigvul.py` | Big-Vul loader entrypoint. |
| `src/vulnagentx/datasets/primevul.py` | PrimeVul loader entrypoint. |
| `src/vulnagentx/datasets/jit.py` | JIT loader entrypoint. |
| `src/vulnagentx/eval/detection_metrics.py` | Detection metrics (Precision/Recall/F1/Accuracy). |
| `src/vulnagentx/eval/localization_metrics.py` | Localization metrics (Top-1/Top-3/MRR). |
| `src/vulnagentx/eval/efficiency_metrics.py` | Efficiency metrics (avg runtime/P95/findings). |
| `src/vulnagentx/eval/ablations.py` | Ablation execution logic across workflow variants. |
| `src/vulnagentx/utils/config.py` | Central workflow configuration (env/CLI/API toggles). |

### Test Files (`tests`)

| File | Purpose |
|---|---|
| `tests/test_agents.py` | Unit tests for agent structured outputs and sceptic behavior. |
| `tests/test_end_to_end.py` | End-to-end workflow test from input repo to final findings. |
| `tests/test_research_modules.py` | Tests for Tree-sitter graphing, verification pipeline, and metrics modules. |

## Implemented Research Modules

- Real LLM adapters: OpenAI + local Ollama + provider-based factory fallback
- Real Tree-sitter AST and code graph integration (with graceful fallback mode)
- Real Semgrep ruleset integration in screening
- Verification sandbox execution chain with bounded subprocess tasks
- Dataset loaders, evaluation metrics, and ablation scripts for experiments
