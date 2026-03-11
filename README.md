<p align="right">
  <a href="./README.zh.md"><img src="https://img.shields.io/badge/语言-中文-blue" alt="中文"></a>
  <a href="./README.en.md"><img src="https://img.shields.io/badge/Language-English-lightgrey" alt="English"></a>
</p>

# VulnAgent-X 研究原型

VulnAgent-X 是一个面向论文复现的多 Agent 漏洞/缺陷检测原型。
输入本地仓库或 diff，输出结构化 findings、证据链、定位结果、置信度和实验日志。

## 核心能力

- 输入形式：`repo path` 或 `unified diff`
- 工作流：`screening -> context expansion -> scheduler -> router -> experts -> sceptic -> verification(stub) -> evidence fusion`
- 输出字段：
  - `issue_type`
  - `location(file + line range)`
  - `evidence_summary`
  - `confidence`
  - `severity`
  - `optional_cwe`
  - `fix_hint`
  - `evidence_chain`
  - `counter_evidence`
- 接口：CLI + FastAPI
- 可复现实验：pytest / mypy / ruff + Docker 运行支持

## 工作流概览

1. `screening`：快速筛查可疑区域（规则 + 元数据信号）
2. `context_expansion`：拉取“最小充分上下文”（按可疑位置提取窗口）
3. `scheduler`：根据置信度和风险做升级策略（early_exit / expert_review / verification）
4. `router_agent`：为每个可疑区域选择专家 Agent
5. `semantic/security/logic`：从不同视角给出结构化主张和证据
6. `sceptic_agent`：生成反证与惩罚信号
7. `verification`：可选动态验证（当前为安全占位实现）
8. `evidence_fusion`：统一融合并输出最终 findings

## 安装与运行教程

### 1) 环境准备

要求：Python `3.11+`（当前也可在更高版本运行）

```bash
cd /Users/xiaolu/Documents/Python_code/vulnAgentX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

### 2) CLI 使用

分析整个仓库：

```bash
.venv/bin/vulnagentx analyze --repo /path/to/repo --output json
```

分析 diff 文件：

```bash
.venv/bin/vulnagentx analyze --diff-file /path/to/patch.diff --output json
```

简要输出：

```bash
.venv/bin/vulnagentx analyze --repo /path/to/repo --output summary
```

### 3) API 使用

启动服务：

```bash
.venv/bin/uvicorn vulnagentx.app.api:app --reload
```

健康检查：

```bash
curl http://127.0.0.1:8000/health
```

发起分析：

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_path":"/path/to/repo"}'
```

### 4) Docker 运行

```bash
docker compose -f docker/docker-compose.yml up --build
```

### 5) 质量检查与测试

```bash
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/pytest
```

## 输出示例

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

## 文件用途说明（逐文件）

### 根目录与工程文件

| 文件 | 用途 |
|---|---|
| `.env.example` | 环境变量模板（日志级别等可选设置）。 |
| `pyproject.toml` | 项目构建、依赖、脚本入口、pytest/ruff/mypy 配置。 |
| `README.md` | 主 README（带语言切换按钮，默认中文）。 |
| `README.zh.md` | 中文完整版文档。 |
| `README.en.md` | 英文完整版文档。 |
| `docker/Dockerfile` | API 服务容器镜像构建文件。 |
| `docker/docker-compose.yml` | 本地一键拉起容器服务。 |
| `rules/semgrep/vulnagentx-rules.yml` | 内置 Semgrep 规则集（命令注入/SQL 注入/反序列化/不安全 C API）。 |
| `scripts/run_experiment.py` | 数据集批量实验执行脚本，输出预测 JSONL。 |
| `scripts/evaluate.py` | 读取实验输出并计算检测/定位/效率指标。 |
| `scripts/run_ablation.py` | 消融实验脚本（no_semgrep/no_treesitter/no_sceptic/no_verification）。 |

### 核心源码（`src/vulnagentx`）

| 文件 | 用途 |
|---|---|
| `src/vulnagentx/__init__.py` | 包版本与包导出定义。 |
| `src/vulnagentx/app/__init__.py` | `app` 子包初始化。 |
| `src/vulnagentx/app/cli.py` | CLI 入口（`vulnagentx analyze`）。 |
| `src/vulnagentx/app/api.py` | FastAPI 服务入口（`/health`、`/analyze`）。 |
| `src/vulnagentx/app/schemas.py` | API 请求/响应的 Pydantic Schema。 |
| `src/vulnagentx/core/__init__.py` | `core` 子包初始化。 |
| `src/vulnagentx/core/state.py` | 全局状态模型：区域、证据、Agent 输出、Finding、日志、指标。 |
| `src/vulnagentx/core/screening.py` | 第一阶段快速筛查，提取可疑区域。 |
| `src/vulnagentx/core/context_expansion.py` | 上下文扩展：按定位提取最小代码窗口。 |
| `src/vulnagentx/core/scheduler.py` | 置信度感知升级策略（early_exit/expert_review/verification）。 |
| `src/vulnagentx/core/verification.py` | 可选动态验证模块（当前为安全占位版）。 |
| `src/vulnagentx/core/evidence_fusion.py` | 多 Agent 证据融合，输出最终 findings。 |
| `src/vulnagentx/core/workflow.py` | 端到端编排入口 `VulnAgentWorkflow`。 |
| `src/vulnagentx/agents/__init__.py` | Agent 导出聚合。 |
| `src/vulnagentx/agents/base.py` | Agent 抽象基类与上下文获取工具。 |
| `src/vulnagentx/agents/router_agent.py` | 路由 Agent：为每个可疑区域分配专家 Agent。 |
| `src/vulnagentx/agents/semantic_agent.py` | 语义 Agent：语义层风险（如空指针、反序列化、异常吞掉）。 |
| `src/vulnagentx/agents/security_agent.py` | 安全 Agent：安全漏洞规则（命令注入、SQL 注入、越界等）。 |
| `src/vulnagentx/agents/logic_bug_agent.py` | 逻辑 Agent：业务/控制流缺陷（边界、除零、授权缺失等）。 |
| `src/vulnagentx/agents/sceptic_agent.py` | 怀疑者 Agent：生成反证、冲突惩罚、降置信。 |
| `src/vulnagentx/adapters/__init__.py` | 适配器子包初始化。 |
| `src/vulnagentx/adapters/sandbox_adapter.py` | 受限子进程沙箱执行器（超时、无 shell）用于 verification。 |
| `src/vulnagentx/adapters/semgrep_adapter.py` | Semgrep CLI 适配器（可选启用）。 |
| `src/vulnagentx/adapters/treesitter_adapter.py` | 真实 Tree-sitter 适配器（可用时解析 AST 与调用/导入关系，不可用时降级）。 |
| `src/vulnagentx/adapters/llm/__init__.py` | LLM 适配器导出聚合。 |
| `src/vulnagentx/adapters/llm/base.py` | LLM 适配器协议接口。 |
| `src/vulnagentx/adapters/llm/mock_adapter.py` | 离线可测的 Mock LLM。 |
| `src/vulnagentx/adapters/llm/openai_adapter.py` | OpenAI 官方 SDK 适配器。 |
| `src/vulnagentx/adapters/llm/local_adapter.py` | 本地模型适配器（Ollama HTTP API）。 |
| `src/vulnagentx/adapters/llm/factory.py` | 按配置自动选择 LLM 适配器并兜底到 Mock。 |
| `src/vulnagentx/retrieval/repo_graph.py` | 代码图索引与邻居文件检索（基于 AST 符号重叠）。 |
| `src/vulnagentx/datasets/base.py` | 通用数据集样本结构与 JSONL/CSV 读取。 |
| `src/vulnagentx/datasets/devign.py` | Devign 数据加载入口。 |
| `src/vulnagentx/datasets/bigvul.py` | Big-Vul 数据加载入口。 |
| `src/vulnagentx/datasets/primevul.py` | PrimeVul 数据加载入口。 |
| `src/vulnagentx/datasets/jit.py` | JIT 数据加载入口。 |
| `src/vulnagentx/eval/detection_metrics.py` | 检测指标（Precision/Recall/F1/Accuracy）。 |
| `src/vulnagentx/eval/localization_metrics.py` | 定位指标（Top-1/Top-3/MRR）。 |
| `src/vulnagentx/eval/efficiency_metrics.py` | 效率指标（平均耗时、P95、平均 findings）。 |
| `src/vulnagentx/eval/ablations.py` | 消融实验执行逻辑。 |
| `src/vulnagentx/utils/config.py` | 工作流配置中心（env/CLI/API 开关）。 |

### 测试文件（`tests`）

| 文件 | 用途 |
|---|---|
| `tests/test_agents.py` | 单测：各 Agent 结构化输出与反证逻辑。 |
| `tests/test_end_to_end.py` | 端到端测试：从输入仓库到最终 findings 的主流程。 |
| `tests/test_research_modules.py` | 新增模块测试：Tree-sitter 图构建、verification 执行链路、评测指标。 |

## 本次已实现增强模块

- 真实 LLM Adapter：`OpenAI` + 本地 `Ollama` + 自动工厂切换
- 真实 Tree-sitter AST 与代码图：解析函数/导入/调用关系，支持邻居文件上下文扩展
- 真实 Semgrep 规则集：内置规则文件并接入 screening 阶段
- verification sandbox 执行链路：任务规划、受限执行、超时控制、结构化结果回写
- 数据集评测与消融：数据加载器、指标模块、实验与消融脚本
