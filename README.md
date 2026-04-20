# SentriX

SentriX is an automated threat analysis and incident response project.
It combines a Python backend pipeline (triage, intel retrieval, rule generation, judgement, and audit)
with a React frontend for operational workflows.

## Key Capabilities

- Incident analysis from JSON and CSV traffic data.
- RAG-backed threat intelligence retrieval from CVE, IOC, and rule datasets.
- Rule-driven judgement output (`clean`, `suspicious`, `malicious`) with audit gating.
- Flask API mode for frontend integration.
- Historical case memory and correction workflow.

## 技术栈总览

### 后端（Backend）

- 语言与运行时: Python 3.10+
- CLI: argparse（标准库）
- Web API: Flask 3.x
- LLM 编排与调用: LangChain、LangChain Community
- 检索增强与规则情报存储: SQLite（sqlite3 标准库 + 本地 RAG 数据）
- 在线检索: duckduckgo-search（并支持通过环境变量配置外部 Web Search Provider）
- 终端输出增强: colorama
- 配置管理: .env（工作区根目录优先，backend/.env 回退）
- 模型生态支持: qwen（默认）、glm、deepseek（并保留 openai 兼容配置）

### 前端（Frontend）

- UI 框架: React 19
- 语言: TypeScript 6
- 构建与开发服务器: Vite 8（含 /api 反向代理到后端 8000 端口）
- 代码质量: ESLint 9 + typescript-eslint + react-hooks + react-refresh
- 包管理与脚本: npm（dev/build/lint/preview）

### 数据与工程化

- 数据输入: JSON 事件样本、CSV 流量数据集
- 本地知识库: CVE、IOC、Rules（落地到 SQLite RAG 库）
- 项目组织: 前后端分离（backend + frontend）
- 推荐环境管理: Conda（用于 Python 依赖隔离）

### 运行形态

- 单次离线分析（CLI）
- 数据集/CSV 行级分析与压力测试
- API 服务模式（供前端页面联调）

## Repository Layout

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
	data/
		sample_incident.json
	dataset/
		incident_examples.json
	docs/
		frontend_payload_contract.md
	Licence
```

## Prerequisites

- Python 3.10+ (recommended via Conda)
- Node.js 20+ and npm

## Quick Start

### 1. Install backend dependencies (Conda recommended)

```bash
conda create -n sentrix python=3.11 -y
conda run -n sentrix pip install -r backend/requirements.txt
```

### 2. Run backend on sample incident

```bash
conda run -n sentrix python main.py --input data/sample_incident.json
```

### 3. Start backend API service (for frontend)

```bash
conda run -n sentrix python -m backend.app.main --serve-api --api-host 127.0.0.1 --api-port 8000
```

### 4. Start frontend

```bash
cd frontend
npm install
npm run dev
```

## 快速上手（中文）

### 1. 创建并安装后端环境（Conda）

```bash
conda create -n sentrix python=3.11 -y
conda run -n sentrix pip install -r backend/requirements.txt
```

### 2. 运行一次后端分析

```bash
conda run -n sentrix python main.py --input data/sample_incident.json
```

### 3. 启动后端 API（用于前端联调）

```bash
conda run -n sentrix python -m backend.app.main --serve-api --api-host 127.0.0.1 --api-port 8000
```

### 4. 启动前端页面

```bash
cd frontend
npm install
npm run dev
```

## API 示例

启动 API 后，可用如下方式做最小联调。

```bash
# 健康检查
curl "http://127.0.0.1:8000/api/health"

# 获取 frontend payload（使用 input_file）
curl "http://127.0.0.1:8000/api/frontend-payload?input_file=data/sample_incident.json"
```

说明：具体字段契约请以 `docs/frontend_payload_contract.md` 为准。

## Common Backend Commands

```bash
# Dataset JSON: run one sample
conda run -n sentrix python main.py --dataset dataset/incident_examples.json --index 0

# CSV: run one row
conda run -n sentrix python main.py --csv dataset/test_10_no_label.csv --row 0

# Rebuild RAG database
conda run -n sentrix python -m backend.app.main --rag-reindex

# RAG smoke test
conda run -n sentrix python -m backend.app.main --rag-smoke-test --dataset-file dataset/incident_examples_min.json --dataset-index 0
```

For more backend options, see `backend/README.md`.

## Configuration Notes

- Model/provider options are loaded from `.env` at repository root (or `backend/.env` as fallback).
- API keys can be provided via `backend/apikey.txt`.
- Edit configuration files directly based on your environment and security policy.

## Additional Documentation

- Backend details: `backend/README.md`
- Migration notes: `backend/MIGRATION.md`
- Frontend payload contract: `docs/frontend_payload_contract.md`

## License

This project is licensed under the MIT License.
See `Licence` for full text.
