# 🧠 SentriX Backend

> 面向安全分析、规则研判与执行审计的后端核心引擎

本目录文档聚焦后端工程，包括 CLI、API、架构分层、配置项、批量评估、RAG 运维与排障。

## 📌 目录
- [🎯 后端职责](#-后端职责)
- [🏗️ 架构分层](#️-架构分层)
- [🔄 主流程](#-主流程)
- [📁 目录结构](#-目录结构)
- [✅ 运行前准备](#-运行前准备)
- [🚀 运行命令手册](#-运行命令手册)
- [🔌 API 手册](#-api-手册)
- [🧾 Eval Harness 说明](#-eval-harness-说明)
- [🧠 RAG 数据维护](#-rag-数据维护)
- [⚙️ 配置项说明](#️-配置项说明)
- [🧪 运行模式建议](#-运行模式建议)
- [🩺 常见问题与排障](#-常见问题与排障)
- [🗂️ 迁移与兼容](#️-迁移与兼容)

## 🎯 后端职责
- 统一接入日志输入（JSON/CSV/Dataset）并做结构化解析。
- 执行 `triage -> rag -> planning -> audit` 的阶段化分析。
- 输出前端统一契约数据（用于仪表盘、狩猎页、执行编排页）。
- 提供运行时日志和状态接口供前端轮询。
- 支持离线评估与批量报告落盘。

## 🏗️ 架构分层

```text
app/
  domain/    # 领域模型与配置
  services/  # 能力实现（ingestion, rag, llm, planning, auditing 等）
  engine/    # 流程编排与运行时（workflow, skill_engine, agents）
  api_server.py
  main.py
```

分层职责：
- `app/main.py`：CLI 参数解析、任务分发、输出控制。
- `app/api_server.py`：Flask API 路由、参数校验、JSON 序列化。
- `app/engine/workflow.py`：主流程编排与阶段输出聚合。
- `app/services/*`：各模块能力实现。

## 🔄 主流程

```text
ingestion -> triage -> rag -> planning/rule_judgement -> audit -> frontend payload
```

关键特性：
- 支持技能闭环门控（skill-gated execution）。
- 审计失败时阻断执行下发（`execution_allowed=false`）。
- 可输出阶段轨迹与运行时日志，便于诊断。

## 📁 目录结构

```text
backend/
  app/
    domain/
      config.py
      models.py
    services/
      ingestion.py
      state_estimator.py
      llm_client.py
      web_search_client.py
      rag.py
      action_policy.py
      action_generator.py
      planning.py
      response_generator.py
      auditor.py
      eval_harness.py
    engine/
      skill_engine.py
      workflow.py
      agents.py
    api_server.py
    main.py
    auditory.py
    prompts/
  data/
  dataset/
  logs/
  requirements.txt
```

## ✅ 运行前准备

```bash
cd /home/kali/SentriX
conda create -n sentrix python=3.11 -y
conda run -n sentrix pip install -r backend/requirements.txt
```

> 建议优先用 `conda run -n sentrix ...`，避免 shell 初始化差异导致的激活问题。

## 🚀 运行命令手册

### 1) 单样本 JSON

```bash
conda run -n sentrix python -m backend.app.main \
  --input /home/kali/SentriX/backend/data/sample_incident.json
```

### 2) Dataset JSON 单样本

```bash
conda run -n sentrix python -m backend.app.main \
  --dataset-file /home/kali/SentriX/backend/dataset/incident_examples.json \
  --dataset-index 0
```

### 3) CSV 单行

```bash
conda run -n sentrix python -m backend.app.main \
  --csv-dataset-file /home/kali/SentriX/backend/dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
  --csv-row-index 0
```

### 4) 启动 API 服务（供前端联调）

```bash
conda run -n sentrix python -m backend.app.main \
  --serve-api --api-host 127.0.0.1 --api-port 8000
```

### 5) Eval Harness（推荐批量评估）

```bash
conda run --no-capture-output -n sentrix python -m backend.app.main \
  --eval-harness \
  --eval-dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json \
  --eval-start-index 0 \
  --eval-max-samples 20 \
  --heartbeat-seconds 2
```

### 6) RAG 数据维护

```bash
# 重建索引
conda run -n sentrix python -m backend.app.main --rag-reindex

# 冒烟测试
conda run -n sentrix python -m backend.app.main \
  --rag-smoke-test \
  --dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json \
  --dataset-index 0

# 导入 CVE / Rule / IOC
conda run -n sentrix python -m backend.app.main --rag-import-cve-dir /home/kali/SentriX/backend/data/cve
conda run -n sentrix python -m backend.app.main --rag-import-rule-dir /home/kali/SentriX/backend/data/rules
conda run -n sentrix python -m backend.app.main --rag-import-ioc-dir /home/kali/SentriX/backend/data/ioc
```

## 🔌 API 手册

### 健康与基础
- `GET /api/health`：健康检查。
- `GET /api/datasets/files`：返回 dataset 可选文件列表（供前端下拉）。

### 分析与运行态
- `GET /api/frontend-payload`：主分析入口。
  - 支持参数：`dataset_file`、`dataset_index`、`input_file`、`csv_file`、`csv_row_index`。
- `GET /api/runtime/analysis-logs`：增量日志。
  - 常用参数：`since_id`、`limit`、`include_heartbeat`。
- `GET /api/runtime/async-cross-validate`：异步校验状态。

### 业务能力
- `POST /api/hunt/rag-suggest`：猎捕建议生成。
- `POST /api/copilot/chat`：AI 对话。
- `POST /api/execution/countermeasure`：反制预演/下发。
- `GET /api/rules/search`：规则检索。
- `GET/PATCH /api/system/settings`：系统设置读取与更新。

## 🧾 Eval Harness 说明

终端输出：
- `[EVAL xx]`：阶段进度。
- `[EVAL-SAMPLE]`：样本级简报。
- `[EVAL-SUMMARY]`：汇总统计。
- `[EVAL-REPORT]`：报告路径。

报告落盘：
- `backend/logs/eval_harness_*.json`
- `backend/logs/eval_harness_*.md`

报告特点：
- 包含 `mapping_diagnostics`，用于定位映射偏差问题。

## 🧠 RAG 数据维护

数据来源：
- CVE（漏洞结构化数据）
- IOC（威胁指示器）
- Rule（检测规则）

默认配置：
- `RAG_USE_DB=true`
- `RAG_DB_PATH=backend/data/rag_intel.db`
- `RAG_TOP_K=12`
- `RAG_AUTO_REINDEX=true`

建议：
- 批量导入后先 `--rag-smoke-test`，再进行大规模评估。
- 导入格式应保持字段一致性，避免检索命中质量波动。

## ⚙️ 配置项说明

配置加载优先级：
- 仓库根 `.env`（优先）
- `backend/.env`（回退）

模型与 Provider：
- `LLM_PROVIDER`（默认 qwen）
- `LLM_MODEL`
- `LLM_ENDPOINT`
- `LLM_ENFORCE_DOMESTIC=true`（可按策略调整）

多 Agent 参数：
- `MULTI_AGENT_ENABLED`
- `MULTI_AGENT_USE_LLM_AGENTS`
- `MULTI_AGENT_MAX_ROUNDS`
- `MULTI_AGENT_CONVERGENCE_STREAK`
- `MULTI_AGENT_PER_AGENT_TIMEOUT_MS`
- `MULTI_AGENT_MAX_ELAPSED_MS`
- `MULTI_AGENT_MIN_MARGIN`

Key 来源：
- `backend/apikey.txt`（支持 `DASHSCOPE_API_KEY / GLM_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY`）
- 或 `API_KEY_FILE=/path/to/file`

## 🧪 运行模式建议

开发联调：
- 启动 API + 前端，观察 `/api/runtime/analysis-logs`。

批量评估：
- 优先 `--eval-harness`，并开启 heartbeat。

生产化演示：
- 使用固定 dataset + 固定索引集合，保证可重复结果与可解释性。

## 🩺 常见问题与排障

### 1) `CondaError: Run 'conda init' before 'conda activate'`
- 使用 `conda run -n sentrix ...` 规避 shell 激活依赖。

### 2) 批量任务报 `No valid candidate actions after policy filtering`
- 多为样本在策略过滤后无候选动作。
- 建议分段运行定位问题样本：
  - `--eval-max-samples 10`
  - 配合 `--eval-start-index` 逐段排查。

### 3) `--stress-test` 报 `unexpected keyword argument 'progress_callback'`
- 当前版本建议临时使用 `--eval-harness` 完成批量任务。

### 4) API 返回慢或前端等待过久
- 查看 heartbeat 与 runtime logs 是否持续更新。
- 检查模型接口耗时与检索源可用性。

## 🗂️ 迁移与兼容
- 架构迁移文档：`backend/MIGRATION.md`
- `app/services/auditor.py` 为审计主实现。
- `app/auditory.py` 保留兼容导入能力。
