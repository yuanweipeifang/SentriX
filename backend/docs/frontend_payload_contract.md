# Frontend Payload Contract

## Overview

后端完整结果中新增统一字段 `frontend_payload`，用于前端直接消费。

建议前端优先读取：

- `frontend_payload.incident_overview`
- `frontend_payload.cards`
- `frontend_payload.confidence`
- `frontend_payload.evidence`
- `frontend_payload.hunt`
- `frontend_payload.execution`
- `frontend_payload.orchestration`
- `frontend_payload.case_memory`
- `frontend_payload.observability`

## Root Schema

```json
{
  "schema_version": "frontend-payload/v1",
  "page_title": "安全事件研判面板",
  "incident_overview": {},
  "cards": [],
  "confidence": {},
  "evidence": {},
  "downgrade": [],
  "timeline": [],
  "checklist": [],
  "hunt": {},
  "execution": {},
  "orchestration": {},
  "case_memory": {},
  "observability": {}
}
```

## Section Details

### incident_overview

用途：页面顶部事件摘要区域。

字段：

- `event_summary: string`
- `affected_assets: string[]`
- `ioc: { ip: string[], domain: string[], cve: string[], process: string[] }`
- `timestamp: string`
- `source: string`

### cards

用途：首页关键卡片。

每项结构：

```json
{
  "key": "top_threat",
  "label": "首要威胁",
  "value": "Log4Shell RCE",
  "tone": "danger"
}
```

`tone` 建议映射：

- `danger` -> 红色
- `primary` -> 主色
- `info` -> 蓝色
- `success` -> 绿色
- `warning` -> 橙色

### confidence

用途：置信度面板、进度条、解释卡片。

字段：

- `scores.detection_confidence: number`
- `scores.response_confidence: number`
- `scores.execution_confidence: number`
- `levels.*: "高" | "中" | "低"`
- `breakdown[]`

`breakdown[]` 每项结构：

```json
{
  "key": "rule_confidence",
  "label": "规则证据强度",
  "value": 0.9,
  "weight": "high"
}
```

### evidence

用途：证据树、关系图、力导图。

字段：

- `root_id: string`
- `nodes: EvidenceNode[]`
- `edges: EvidenceEdge[]`
- `legend: Record<string,string>`

`nodes[]` 结构：

```json
{
  "id": "support-1",
  "type": "rule",
  "label": "RULE-CVE-CVE_2021_22941",
  "title": "CVE-2021-22941 | improper | access | control | citrix",
  "subtitle": "confidence=0.891",
  "severity": "high",
  "meta": {
    "evidence_id": "EVID-0002",
    "severity": 0.98
  }
}
```

`edges[]` 结构：

```json
{
  "from": "event-root",
  "to": "support-1",
  "relation": "supports"
}
```

### downgrade

用途：误报降级解释区。

每项结构：

```json
{
  "code": "historical_false_positive_pattern",
  "title": "命中历史误报模式",
  "description": "本地案例库中存在相似且已被人工修正为误报/正常的历史事件，因此下调当前风险评分。",
  "severity": "medium",
  "display": "命中历史误报模式"
}
```

### timeline

用途：流程时间线。

每项结构：

```json
{
  "id": "tl-1",
  "stage": "detection",
  "label": "威胁检测",
  "value": "规则=8 / CVE=1"
}
```

### checklist

用途：人工复核 checklist。

每项结构：

```json
{
  "key": "check_top_threat",
  "label": "确认首要威胁是否符合人工研判",
  "status": "todo"
}
```

### hunt

用途：查询标签页区域。

字段：

- `count: number`
- `tabs: HuntTab[]`

`tabs[]` 结构：

```json
{
  "id": "hunt-1",
  "title": "Log4Shell RCE",
  "stage": "discovery",
  "sql": "SELECT ...",
  "elasticsearch_dsl": {},
  "splunk_spl": "search ..."
}
```

### execution

用途：执行适配面板。

字段：

- `mode: "shell" | "api" | "hybrid" | "playbook" | "blocked"`
- `guardrails: string[]`
- `playbook: object`
- `tasks: object[]`
- `summary: object`

### orchestration

用途：SOAR 编排图。

字段：

- `graph_id: string`
- `strategy: string`
- `nodes: object[]`
- `edges: object[]`
- `approval_nodes: object[]`
- `rollback_plan: object`
- `execution_order: string[]`

推荐展示：

- DAG 图
- 审批节点高亮
- 回滚链单独抽屉展示

### case_memory

用途：历史案例面板。

字段：

- `stored: boolean`
- `case_id: string`
- `effective_label: string`
- `storage_file: string`
- `historical_panel`

`historical_panel` 结构：

```json
{
  "has_false_positive_pattern": false,
  "benign_like_count": 0,
  "malicious_like_count": 1,
  "cases": [
    {
      "case_id": "case-71a051a64eac",
      "score": 12,
      "effective_label": "malicious",
      "top_threat": "RULE-CVE-CVE_2021_22941",
      "best_action": "采集 api-backend 内存与磁盘镜像"
    }
  ]
}
```

### observability

用途：调试和开发模式。

字段：

- `cache_hit`
- `planner`
- `stage_elapsed_ms`

## Recommended Frontend Layout

- 顶部：`incident_overview + cards`
- 左栏：`confidence + downgrade + checklist`
- 中区：`evidence`
- 右栏：`case_memory + observability`
- 底部 Tab：
  - `timeline`
  - `hunt`
  - `execution`
  - `orchestration`

## Stability Notes

- 当前契约版本：`frontend-payload/v1`
- 后续若有破坏性变更，应升级 `schema_version`
- 前端建议以 `frontend_payload` 为主，其他字段仅作为调试或回溯数据源
