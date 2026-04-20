# Automated Threat Analysis & Incident Response (Backend)

## Run

```bash
python -m backend.app.main --input /home/kali/SentriX/backend/data/sample_incident.json
# or run from repository root
python /home/kali/SentriX/main.py --input /home/kali/SentriX/backend/data/sample_incident.json
```

### Dataset / Stress Test

```bash
# Dataset JSON single sample
python -m backend.app.main --dataset-file /home/kali/SentriX/backend/dataset/incident_examples.json --dataset-index 0
# shorthand aliases from root entry
python /home/kali/SentriX/main.py --dataset /home/kali/SentriX/backend/dataset/incident_examples.json --index 0

# CSV single row
python -m backend.app.main --csv-dataset-file /home/kali/SentriX/backend/dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv --csv-row-index 0
# shorthand aliases from root entry
python /home/kali/SentriX/main.py --csv /home/kali/SentriX/backend/dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv --row 0

# Stress test over real CSV traffic dataset
python -m backend.app.main --stress-test --stress-mode csv --csv-dataset-file /home/kali/SentriX/backend/dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv --stress-max-samples 20

# Rebuild RAG database + run smoke test
python -m backend.app.main --rag-reindex
python -m backend.app.main --rag-smoke-test --dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json --dataset-index 0

# Import real CVE JSONs (MITRE/NVD style single-file records) into RAG
python -m backend.app.main --rag-import-cve-dir /home/kali/SentriX/backend/data/cve

# Import attack rules (custom json / sigma-like json) into RAG
python -m backend.app.main --rag-import-rule-dir /home/kali/SentriX/backend/data/rules

# Import IOC jsons into RAG
python -m backend.app.main --rag-import-ioc-dir /home/kali/SentriX/backend/data/ioc

# Rule+evidence judgement on minimal csv dataset
python -m backend.app.main --rag-eval-csv --csv-dataset-file /home/kali/SentriX/backend/dataset/test_10_no_label.csv --rag-eval-max-rows 10

# LLM eval harness (keep heartbeat + colorful realtime output)
conda run --no-capture-output -n sentrix python -m backend.app.main --eval-harness --eval-max-samples 20 --eval-start-index 0 --heartbeat-seconds 2
```

### Eval Harness 输出说明（简洁终端 + 详细落盘）

- 终端输出：
  - 彩色阶段进度（`[EVAL xx]`）
  - 样本简报（`[EVAL-SAMPLE]`）
  - 汇总结果（`[EVAL-SUMMARY]`）
  - 报告路径（`[EVAL-REPORT]`）
- 详细数据文件：自动写入 `backend/logs/eval_harness_*.json` 与 `backend/logs/eval_harness_*.md`。
- 映射诊断：报告内新增 `mapping_diagnostics`，用于定位 Incident 映射偏差来源（如 `audit_pass_but_pred_incident`）。

## Backend Skill Closed Loop

- Runtime enforces required skills from `.trae/skills`.
- Pipeline stages are skill-gated: `triage -> rag -> planning -> audit`.
- Output includes:
  - `skill_runtime.loaded_skills`
  - `skill_runtime.execution_trace`
  - `audit.audit_result`
  - `execution_allowed` (blocks execution when audit fails)

## Project Structure

```
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
    engine/
      skill_engine.py
      workflow.py
      agents.py
    main.py
    auditory.py
    __init__.py
    prompts/
      action_generation.prompt.txt
      state_estimation.prompt.txt
      planning_simulation.prompt.txt
  main.py
  data/
    sample_incident.json
  requirements.txt
```

## Refactored Architecture

- `app/main.py` 只负责 CLI 参数解析与输出控制。
- `app/engine/workflow.py` 统一做依赖装配、阶段执行与结果拼装。
- `app/services/auditor.py` 作为审计主实现；`app/auditory.py` 保留兼容导入。
- `app/domain` 承载领域模型与配置，`app/services` 承载业务能力实现，`app/engine` 承载流程编排与运行引擎。
- `backend/main.py` 提供包级统一启动入口。

## Migration

- 迁移文档见 `backend/MIGRATION.md`。

## Multi-Agent LLM 配置

### .env 模型配置（国产）

- 运行时会自动读取工作区根目录 `.env`（优先）和 `backend/.env`（回退）。
- 默认强制国产 provider：`LLM_ENFORCE_DOMESTIC=true`。
- 支持 provider：`qwen` / `glm` / `deepseek`。
- 推荐在 `.env` 中设置：
  - `LLM_PROVIDER=qwen`
  - `LLM_MODEL=qwen-plus`
  - `LLM_ENDPOINT=https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions`

> 当前代码已改为硬编码默认值：直接 `python main.py` 可运行，无需额外传入以上模型参数。

- 多 agent 讨论开关与收敛参数：
  - `MULTI_AGENT_ENABLED`（默认 `true`）
  - `MULTI_AGENT_USE_LLM_AGENTS`（默认 `true`，关闭后走规则回退）
  - `MULTI_AGENT_MAX_ROUNDS`（默认 `3`）
  - `MULTI_AGENT_CONVERGENCE_STREAK`（默认 `2`）
  - `MULTI_AGENT_PER_AGENT_TIMEOUT_MS`（默认 `1800`）
  - `MULTI_AGENT_MAX_ELAPSED_MS`（默认 `6000`）
  - `MULTI_AGENT_MIN_MARGIN`（默认 `0.05`）
- agent 模型 API 配置（支持全局 + 角色覆盖）：
  - 全局：`AGENT_ENDPOINT`、`AGENT_API_KEY`、`AGENT_MODEL`、`AGENT_TIMEOUT_SECONDS`
  - 角色覆盖：`AGENT_TRIAGE_*`、`AGENT_INTEL_*`、`AGENT_RESPONSE_*`
    - 如：`AGENT_TRIAGE_API_KEY`、`AGENT_INTEL_MODEL`
- 基础模型配置支持从 `backend/apikey.txt` 自动加载（也可通过 `API_KEY_FILE=/path/to/apikey.txt` 指定）：
  - `DASHSCOPE_API_KEY`（qwen）
  - `GLM_API_KEY`（glm）
  - `DEEPSEEK_API_KEY`（deepseek）
  - `OPENAI_API_KEY`（openai）
- RAG 数据库配置：
  - `RAG_USE_DB`（默认 `true`）
  - `RAG_DB_PATH`（默认 `backend/data/rag_intel.db`）
  - `RAG_TOP_K`（默认 `12`）
  - `RAG_AUTO_REINDEX`（默认 `true`）
- 规则导入 JSON（自定义）示例字段：
  - `rule_id`, `rule_type`, `title`, `pattern`, `ttp`, `severity`, `confidence`, `source`, `version`
- IOC 导入 JSON（自定义）示例字段：
  - `ioc`, `threat`, `confidence`, `source_url`
- 提示词文件：
  - `app/prompts/agent_triage.prompt.txt`
  - `app/prompts/agent_intel.prompt.txt`
  - `app/prompts/agent_response.prompt.txt`

## 5x5 规则生成引擎（CVE）

- 功能开关与策略参数（均通过 `.env`）：
  - 默认已硬编码启用（5 并行 x 5 迭代，温度 0.7~0.9）
- 行为：单个 CVE 并行生成 5 条候选规则，每条最多优化 5 轮，按评分保留 Top-K。

## 当前主流程（规则驱动研判）

- 主流程不再使用多 Agent 行动规划做最终研判。
- 新流程：`triage -> rag -> rule_generation -> rule_judgement`。
- 规则来源：
  - RAG 中已有规则（rule_findings）
  - 基于漏洞（CVE）自动生成的最佳规则（best_rule）
- 事件研判直接基于规则匹配结果输出：
  - `clean / suspicious / malicious`
  - `audit_result: pass / warning / fail`
  - `execution_allowed` 由规则风险等级直接决定。
