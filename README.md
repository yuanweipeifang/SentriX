# 🛡️ SentriX

> 面向 SOC 场景的智能化威胁分析与响应系统（Automated Threat Analysis & Incident Response）

SentriX 是一个可落地的“分析引擎 + 作战控制台”组合：  
后端负责编排分析流程与决策审计，前端负责多页面可视化、交互式分析与执行编排。

## 📌 目录
- [🌟 项目价值](#-项目价值)
- [✨ 核心能力](#-核心能力)
- [🏗️ 总体架构](#️-总体架构)
- [🧰 技术栈](#-技术栈)
- [📁 仓库结构](#-仓库结构)
- [✅ 环境要求](#-环境要求)
- [🚀 快速启动](#-快速启动)
- [🧪 运行模式](#-运行模式)
- [🖥️ 前端操作指南](#️-前端操作指南)
- [🔌 API 总览](#-api-总览)
- [⚙️ 配置与安全](#️-配置与安全)
- [🩺 排障手册](#-排障手册)
- [📚 文档导航](#-文档导航)
- [🤝 贡献建议](#-贡献建议)
- [📄 License](#-license)

## 🌟 项目价值
- 将“日志分析、情报检索、规则判断、执行审计”打通到同一条流水线。
- 提供“终端批量评估”和“前端联动作战”两种工作方式，覆盖研发与演示双场景。
- 数据契约清晰，便于后端迭代时前端稳定展示。

## ✨ 核心能力
- 🔍 多源分析：`JSON 单样本`、`JSON Dataset`、`CSV 行级样本`。
- 🧠 RAG 增强：融合 `CVE / IOC / Rule` 本地知识检索。
- ⚖️ 规则驱动研判：输出 `clean / suspicious / malicious`。
- 🚦 审计门控：通过 `audit_result` + `execution_allowed` 防误执行。
- 🧾 可观测运行：实时分析日志、异步状态、阶段轨迹、审计结果。
- 🗂️ 案例记忆：支持历史案例存储与人工纠偏。

## 🏗️ 总体架构

```text
┌────────────────────────────────────────────────────────────┐
│                     Frontend (React + TS)                 │
│ Dashboard / Hunt / Threat-Hunt / Orchestration / Rules    │
└───────────────▲────────────────────────────────────────────┘
                │ HTTP (/api/*)
┌───────────────┴────────────────────────────────────────────┐
│                     Backend (Flask + Engine)              │
│ API Layer + Workflow Engine + Services + Auditing         │
└───────────────▲────────────────────────────────────────────┘
                │
┌───────────────┴────────────────────────────────────────────┐
│                  Data / Knowledge Layer                    │
│ dataset/*.json|csv + backend/data/rag_intel.db (SQLite)   │
└────────────────────────────────────────────────────────────┘
```

## 🧰 技术栈

### Backend
- `Python 3.10+`
- `Flask 3.x`（REST API）
- `argparse`（CLI）
- `LangChain / LangChain Community`（LLM 编排）
- `sqlite3`（本地 RAG 存储）
- `duckduckgo-search`（在线检索补强）
- `colorama`（彩色终端输出）

### Frontend
- `React 19`
- `TypeScript 6`
- `Vite 8`
- `ESLint 9 + typescript-eslint + react-hooks`

### 工程形态
- 前后端分离目录：`backend/` + `frontend/`
- 前端开发代理：`/api` → `http://127.0.0.1:8000`
- 推荐 Python 环境：`Conda`

## 📁 仓库结构

```text
SentriX/
  main.py
  backend/
    app/
    requirements.txt
    README.md
  frontend/
    src/
    package.json
  docs/
    frontend_payload_contract.md
  Licence
```

## ✅ 环境要求
- `Python 3.10+`
- `Node.js 20+`
- `npm`
- 建议安装 `conda`（便于 Python 依赖隔离）

## 🚀 快速启动

### 1) 初始化后端环境

```bash
cd /home/kali/SentriX
conda create -n sentrix python=3.11 -y
conda run -n sentrix pip install -r backend/requirements.txt
```

### 2) 启动后端 API（终端 1）

```bash
cd /home/kali/SentriX
conda run -n sentrix python -m backend.app.main --serve-api --api-host 127.0.0.1 --api-port 8000
```

### 3) 启动前端（终端 2）

```bash
cd /home/kali/SentriX/frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

### 4) 健康检查

```bash
curl "http://127.0.0.1:8000/api/health"
```

浏览器访问：`http://localhost:5173/`

## 🧪 运行模式

### A. 单样本离线分析

```bash
conda run -n sentrix python -m backend.app.main \
  --input /home/kali/SentriX/backend/data/sample_incident.json
```

### B. Dataset 指定样本分析

```bash
conda run -n sentrix python -m backend.app.main \
  --dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json \
  --dataset-index 0
```

### C. CSV 指定行分析

```bash
conda run -n sentrix python -m backend.app.main \
  --csv-dataset-file /home/kali/SentriX/backend/dataset/test_10_no_label.csv \
  --csv-row-index 0
```

### D. 批量评估（推荐）

```bash
conda run --no-capture-output -n sentrix python -m backend.app.main \
  --eval-harness \
  --eval-dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json \
  --eval-start-index 0 \
  --eval-max-samples 20 \
  --heartbeat-seconds 2
```

### E. 矩阵格式输出（更适合终端阅读）

```bash
conda run -n sentrix python -m backend.app.main \
  --dataset-file /home/kali/SentriX/backend/dataset/incident_examples_min.json \
  --dataset-index 0 \
  --output-format matrix
```

## 🖥️ 前端操作指南

推荐路径（可直接演示）：
1. 打开 `威胁狩猎` 页面。
2. 选择数据源类型：`数据集 JSON` / `单个日志 JSON` / `CSV 行日志`。
3. 从下拉列表选择具体文件（来自后端 dataset 目录接口）。
4. 设置索引或行号，点击“按所选源分析”。
5. 在 `执行编排` / `攻击规则` / `系统设置` 页面继续联动操作。

## 🔌 API 总览

| 分类 | 方法 | 路径 | 作用 |
|---|---|---|---|
| Health | GET | `/api/health` | 服务健康检查 |
| Dataset Catalog | GET | `/api/datasets/files` | 返回 dataset 目录文件清单 |
| Main Analysis | GET | `/api/frontend-payload` | 核心分析入口（input/dataset/csv） |
| Runtime Logs | GET | `/api/runtime/analysis-logs` | 增量分析日志 |
| Runtime Status | GET | `/api/runtime/async-cross-validate` | 异步校验运行状态 |
| Copilot | POST | `/api/copilot/chat` | 右侧 AI 对话 |
| Hunt RAG | POST | `/api/hunt/rag-suggest` | 猎捕参数建议 |
| Countermeasure | POST | `/api/execution/countermeasure` | 反制预演/下发 |
| Rules | GET | `/api/rules/search` | 规则检索 |
| Settings | GET/PATCH | `/api/system/settings` | 系统设置读取/修改 |

示例：

```bash
curl "http://127.0.0.1:8000/api/frontend-payload?input_file=/home/kali/SentriX/backend/data/sample_incident.json"
curl "http://127.0.0.1:8000/api/runtime/analysis-logs?since_id=0&limit=120"
```

字段契约：`docs/frontend_payload_contract.md`

## ⚙️ 配置与安全
- 配置优先级：仓库根 `.env` > `backend/.env`。
- Key 管理：可使用 `backend/apikey.txt`。
- Provider：默认 `qwen`，支持 `glm`、`deepseek` 与 openai 兼容配置。
- 建议将生产环境密钥放入受控 Secret 管理系统，不在仓库提交明文。
- 建议通过反向代理网关做鉴权、限流、审计日志归集。

## 🩺 排障手册

### 1) `CondaError: Run 'conda init' before 'conda activate'`
- 直接使用 `conda run -n sentrix ...`，避免 shell 初始化依赖。

### 2) 前端转圈不出结果
- 检查后端健康接口：`/api/health`
- 检查前端是否运行在 `5173`
- 检查 Vite 代理是否指向 `127.0.0.1:8000`

### 3) 批量分析失败 `No valid candidate actions after policy filtering`
- 多见于某些样本在策略过滤后无可执行候选动作。
- 建议分段排查：`--eval-max-samples 10` + 调整 `--eval-start-index`。

### 4) `--stress-test` 报 `unexpected keyword argument 'progress_callback'`
- 当前版本建议优先用 `--eval-harness` 完成批量评估。

## 📚 文档导航
- 后端深度文档：`backend/README.md`
- 迁移记录：`backend/MIGRATION.md`
- 前端契约：`docs/frontend_payload_contract.md`

## 🤝 贡献建议
- 新增后端字段时，先更新契约，再同步前端 normalize。
- 变更 API 时保持向后兼容，避免前端页面硬崩。
- 批量任务改动应附带可观测日志（heartbeat/阶段事件/样本索引）。
- PR 建议同时附“命令复现步骤 + 截图/终端结果”。

## 📄 License

MIT License. See `Licence`.
