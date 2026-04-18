# Backend 架构迁移指南

本文档记录已完成的后端目录重组方案，以及后续新增代码的落位规范。

## 1. 迁移结果

后端已从“`app/` 根目录平铺模块”迁移为分层结构：

- `app/domain`：领域模型与基础配置。
- `app/services`：业务能力实现（ingestion/rag/planning/audit 等）。
- `app/engine`：运行时引擎与流程编排。
- `app/main.py`：CLI 入口层。

## 2. 目录映射

- 旧：`app/models.py` -> 新：`app/domain/models.py`
- 旧：`app/config.py` -> 新：`app/domain/config.py`
- 旧：`app/ingestion.py` -> 新：`app/services/ingestion.py`
- 旧：`app/state_estimator.py` -> 新：`app/services/state_estimator.py`
- 旧：`app/llm_client.py` -> 新：`app/services/llm_client.py`
- 旧：`app/web_search_client.py` -> 新：`app/services/web_search_client.py`
- 旧：`app/rag.py` -> 新：`app/services/rag.py`
- 旧：`app/action_policy.py` -> 新：`app/services/action_policy.py`
- 旧：`app/action_generator.py` -> 新：`app/services/action_generator.py`
- 旧：`app/planning.py` -> 新：`app/services/planning.py`
- 旧：`app/response_generator.py` -> 新：`app/services/response_generator.py`
- 旧：`app/auditor.py` -> 新：`app/services/auditor.py`
- 旧：`app/skill_engine.py` -> 新：`app/engine/skill_engine.py`
- 旧：`app/workflow.py` -> 新：`app/engine/workflow.py`
- 旧：`app/agents.py` -> 新：`app/engine/agents.py`

## 3. 导入规范

新代码优先按分层导入：

- 领域对象：`from backend.app.domain...`
- 业务能力：`from backend.app.services...`
- 编排入口：`from backend.app.engine.workflow import run_pipeline, run_pipeline_dataset`

兼容说明：

- `backend.app.auditory` 仍可导入 `DecisionAuditor`，内部转发到 `services.auditor`。

## 4. 运行方式

推荐命令：

```bash
python -m backend.app.main --input /home/kali/SentriX/backend/data/sample_incident.json
```

包级入口：

```bash
python -m backend.main
```

## 5. 新增代码落位规则

- 新数据结构与常量：放 `app/domain`。
- 新能力模块（外部调用、策略、计算逻辑）：放 `app/services`。
- 新流程编排、阶段调度、运行时轨迹：放 `app/engine`。
- `app/main.py` 仅保留 CLI 解析和输出，不承载业务实现。

## 6. 验证清单

- `python -m backend.app.main --help` 可执行。
- json/dataset 两种输入模式可跑通。
- 输出字段兼容：
  - `skill_runtime.loaded_skills`
  - `skill_runtime.execution_trace`
  - `audit.audit_result`
  - `execution_allowed`
